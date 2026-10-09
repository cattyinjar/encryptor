"""SM2 混合加密插件（国密套件，密钥文件模式）。

完整国密三件套组合，结构同 RSA/ECC 混合插件：

  1. 每次加密随机生成 16 字节内容密钥 CEK（SM4 密钥长度）；
  2. 文件内容用 CEK 做逐块 SM4-GCM（同 sm4-gcm 插件的分块方案）；
  3. CEK 用接收方 SM2 公钥加密（GB/T 32918 标准算法，C1C3C2 格式），
     连同 SM3(CEK) 校验值一起存入元数据。

为什么要 SM3(CEK) 校验值：gmssl 的 SM2 解密在私钥不匹配时不报错而是
返回乱码，且空文件没有内容块可供 GCM 校验——元数据里的 SM3(CEK) 让
"私钥是否正确"在解密一开始就有明确答案，与文件大小无关。

密钥文件格式（Encryptor 自有封装，使用标准 SM2 推荐曲线参数；
openssl 的 SM2 文件是 ASN.1 结构，与本格式不直接互通）::

    公钥   -----BEGIN SM2 PUBLIC KEY-----      base64(64 字节: x || y)
    私钥   -----BEGIN SM2 PRIVATE KEY-----     base64(32 字节)
    加密私钥 -----BEGIN ENCRYPTED SM2 PRIVATE KEY-----
           base64(salt(16) || nonce(12) || SM4-GCM 密文(48))   ← 口令保护

元数据布局（大端）::

    sm2_ct_len(2) || sm2 密文(112) || SM3(CEK)(32) || nonce_prefix(8) || 明文总长(8)

依赖：cryptography（SM3/SM4）与 gmssl（SM2，pip install gmssl）。
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

try:
    from gmssl import sm2 as gm_sm2
    from gmssl import func as gm_func
except ImportError as _exc:  # 由插件管理器捕获并展示原因
    raise ImportError("本插件依赖第三方库 gmssl，请先执行: pip install gmssl") from _exc

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as _exc:
    raise ImportError(
        "本插件依赖第三方库 cryptography，请先执行: pip install cryptography"
    ) from _exc

from encryptor.sdk import (
    CryptoPlugin,
    IntegrityError,
    PluginError,
    ProgressFn,
    WrongPasswordError,
    secure_zero,
)

CEK_LEN = 16                       # SM4 密钥 128 位
SM2_CT_LEN = 112                   # C1(64) || C3(32) || C2(=CEK 16)，C1 不含 04 前缀
CHUNK_SIZE = 1024 * 1024
NONCE_PREFIX_LEN = 8
TAG_LEN = 16
SALT_LEN = 16
WRAP_NONCE_LEN = 12
PRIV_LEN = 32
PUB_LEN = 64
KEYFILE_ROUNDS = 200_000
SM4_KEY_LEN = 16
# 元数据中 sm2 密文之后的固定尾段：SM3(CEK) + nonce 前缀 + 总长
_META_TAIL_LEN = 32 + NONCE_PREFIX_LEN + 8


# ---------------------------------------------------------------- 密钥文件

def _armor(marker: str, blob: bytes) -> bytes:
    b64 = base64.b64encode(blob).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return (
        f"-----BEGIN {marker}-----\n" + "\n".join(lines) + f"\n-----END {marker}-----\n"
    ).encode("ascii")


def _dearmor(data: bytes, marker: str) -> bytes:
    begin, end = f"-----BEGIN {marker}-----".encode(), f"-----END {marker}-----".encode()
    if begin not in data or end not in data:
        raise ValueError(f"缺少 {marker} 标记")
    middle = data.split(begin, 1)[1].split(end, 1)[0].decode("ascii", errors="ignore")
    return base64.b64decode("".join(middle.split()), validate=False)


def _curve_params() -> dict:
    empty = gm_sm2.CryptSM2(public_key="", private_key="")
    return {
        "g": empty.ecc_table["g"],
        "n": int(empty.ecc_table["n"], 16),
        "p": int(empty.ecc_table["p"], 16),
    }


def _generate_keypair_raw() -> Tuple[bytes, bytes]:
    """返回 (私钥 32B, 公钥 64B)。"""
    table = _curve_params()
    while True:
        priv_hex = gm_func.random_hex(PRIV_LEN * 2)
        d = int(priv_hex, 16)
        if 1 <= d < table["n"]:
            break
    maker = gm_sm2.CryptSM2(public_key="", private_key=priv_hex)
    pub_hex = maker._kg(d, table["g"])  # x||y 十六进制（gmssl 内部标量乘法）
    if len(pub_hex) != PUB_LEN * 2:
        raise PluginError("SM2 公钥生成结果异常")
    return d.to_bytes(PRIV_LEN, "big"), bytes.fromhex(pub_hex)


def _load_public_key(credential: str) -> bytes:
    path = Path(credential)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PluginError(f"无法读取公钥文件：{exc}") from exc
    try:
        pub = _dearmor(data, "SM2 PUBLIC KEY")
    except (ValueError, base64.binascii.Error) as exc:
        raise PluginError("公钥文件解析失败：不是有效的 SM2 公钥文件。") from exc
    if len(pub) != PUB_LEN:
        raise PluginError("SM2 公钥长度不正确（需要 64 字节 x||y）。")
    if pub == bytes(PUB_LEN):
        raise PluginError("SM2 公钥无效（全零）。")
    return pub


def _decrypt_priv_blob(blob: bytes, passphrase: Optional[str]):
    """解开加密私钥信封：blob = salt(16)+nonce(12)+SM4-GCM 密文(48)。"""
    if len(blob) != SALT_LEN + WRAP_NONCE_LEN + PRIV_LEN + TAG_LEN:
        raise PluginError("加密私钥文件内容长度不正确。")
    salt, nonce, ct = blob[:SALT_LEN], blob[SALT_LEN : SALT_LEN + WRAP_NONCE_LEN], blob[SALT_LEN + WRAP_NONCE_LEN :]
    if not passphrase:
        raise PluginError("该私钥文件设有口令保护，请在解密页的『口令』栏输入口令后重试。")
    key = PBKDF2HMAC(
        algorithm=hashes.SM3(), length=SM4_KEY_LEN, salt=salt, iterations=KEYFILE_ROUNDS
    ).derive(passphrase.encode("utf-8"))
    try:
        dec = Cipher(algorithms.SM4(key), modes.GCM(nonce, ct[-TAG_LEN:])).decryptor()
        try:
            priv = dec.update(ct[:-TAG_LEN]) + dec.finalize()
        except InvalidTag:
            raise WrongPasswordError("私钥口令错误，或私钥文件已损坏。") from None
        return priv
    finally:
        secure_zero(key)


def _load_private_key(credential: str, passphrase: Optional[str] = None) -> bytes:
    path = Path(credential)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PluginError(f"无法读取私钥文件：{exc}") from exc
    try:
        try:
            if b"BEGIN ENCRYPTED SM2 PRIVATE KEY" in data:
                priv = _decrypt_priv_blob(_dearmor(data, "ENCRYPTED SM2 PRIVATE KEY"), passphrase)
            elif b"BEGIN SM2 PRIVATE KEY" in data:
                priv = _dearmor(data, "SM2 PRIVATE KEY")
            else:
                raise ValueError("缺少 SM2 私钥标记")
        except WrongPasswordError:
            raise
        except (ValueError, base64.binascii.Error) as exc:
            raise PluginError("私钥文件解析失败：不是有效的 SM2 私钥文件。") from exc
        if len(priv) != PRIV_LEN:
            raise PluginError("SM2 私钥长度不正确（需要 32 字节）。")
        d = int.from_bytes(priv, "big")
        if not 1 <= d < _curve_params()["n"]:
            raise PluginError("SM2 私钥数值无效。")
        return priv
    finally:
        secure_zero(data)  # 私钥文件内容字节（含明文/密文信封），解析完立即清零


# ---------------------------------------------------------------- 内容层 SM4-GCM

def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _sm3(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SM3())
    h.update(data)
    return h.finalize()


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    enc = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct + enc.tag


def _gcm_decrypt(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    dec = Cipher(algorithms.SM4(key), modes.GCM(nonce, blob[-TAG_LEN:])).decryptor()
    return dec.update(blob[:-TAG_LEN]) + dec.finalize()


def _stream_encrypt(cek: bytes, nonce_prefix: bytes, src: BinaryIO, dst: BinaryIO,
                    on_progress: ProgressFn) -> int:
    total, index = 0, 0
    while True:
        chunk = _read_exact(src, CHUNK_SIZE)
        if not chunk:
            break
        nonce = nonce_prefix + index.to_bytes(4, "big")
        dst.write(_gcm_encrypt(cek, nonce, chunk))
        total += len(chunk)
        on_progress(len(chunk))
        index += 1
        if len(chunk) < CHUNK_SIZE:
            break
    return total


def _stream_decrypt(cek: bytes, nonce_prefix: bytes, expect_total: int,
                    src: BinaryIO, dst: BinaryIO, on_progress: ProgressFn) -> None:
    total, index = 0, 0
    while True:
        blob = _read_exact(src, CHUNK_SIZE + TAG_LEN)
        if not blob:
            break
        if len(blob) <= TAG_LEN:
            raise IntegrityError("密文块不完整，文件已损坏")
        nonce = nonce_prefix + index.to_bytes(4, "big")
        try:
            plain = _gcm_decrypt(cek, nonce, blob)
        except InvalidTag:
            raise WrongPasswordError("私钥不匹配，或文件已被篡改/损坏")
        dst.write(plain)
        total += len(plain)
        on_progress(len(plain))
        index += 1
    if total != expect_total:
        raise IntegrityError(
            f"解密长度不符（期望 {expect_total} 字节，实际 {total} 字节），文件可能被截断"
        )


class Plugin(CryptoPlugin):
    id = "sm2-sm4-gcm"
    name = "SM2 混合加密（国密套件）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = (
        "密钥文件模式（国密）：SM2 公钥保护随机 SM4 内容密钥（附 SM3 校验），"
        "文件逐块 SM4-GCM 加密；加密选公钥文件，解密选私钥文件"
    )
    credential_mode = "keyfile"
    encrypt_credential_hint = "公钥文件"
    decrypt_credential_hint = "私钥文件"
    supports_keygen = True
    keyfile_needs_passphrase = True   # 私钥可能带口令（SM4-GCM 信封）

    def describe_credential(self, credential, passphrase=None) -> str:
        try:
            data = Path(credential).read_bytes()
        except OSError:
            return ""
        if b"BEGIN SM2 PUBLIC KEY" in data:
            return "SM2 公钥（国密 sm2p256v1 曲线，256 位 ≈ 128 位安全强度）"
        if b"ENCRYPTED SM2 PRIVATE KEY" in data:
            return "SM2 私钥（口令保护信封，sm2p256v1 曲线，≈128 位安全强度）"
        if b"BEGIN SM2 PRIVATE KEY" in data:
            return "SM2 私钥（明文，sm2p256v1 曲线，≈128 位安全强度）"
        return ""

    def generate_keypair(self, dest_dir, passphrase=None) -> Tuple[Path, Path]:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        pub_path = dest / "sm2_public_key.pem"
        priv_path = dest / "sm2_private_key.pem"
        if pub_path.exists() or priv_path.exists():
            raise PluginError(
                f"目录下已存在 {pub_path.name} / {priv_path.name}，请换一个目录或先删除旧密钥。"
            )
        priv, pub = _generate_keypair_raw()
        try:
            pub_path.write_bytes(_armor("SM2 PUBLIC KEY", pub))
            if passphrase:
                salt = os.urandom(SALT_LEN)
                nonce = os.urandom(WRAP_NONCE_LEN)
                key = PBKDF2HMAC(
                    algorithm=hashes.SM3(), length=SM4_KEY_LEN, salt=salt,
                    iterations=KEYFILE_ROUNDS,
                ).derive(passphrase.encode("utf-8"))
                try:
                    blob = salt + nonce + _gcm_encrypt(key, nonce, priv)
                finally:
                    secure_zero(key)
                    secure_zero(salt)  # 盐不保密，但保持信封材料一并清理
                priv_path.write_bytes(_armor("ENCRYPTED SM2 PRIVATE KEY", blob))
            else:
                priv_path.write_bytes(_armor("SM2 PRIVATE KEY", priv))
            return pub_path, priv_path
        finally:
            secure_zero(priv)

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        credential: Optional[str],
        on_progress: ProgressFn,
        passphrase: Optional[str] = None,  # 公钥无需口令，忽略
    ) -> bytes:
        pub = _load_public_key(credential or "")
        cek = os.urandom(CEK_LEN)
        try:
            crypt = gm_sm2.CryptSM2(
                public_key=pub.hex(), private_key="", mode=1, asn1=False
            )
            try:
                wrapped = crypt.encrypt(cek)
            except Exception as exc:
                raise PluginError(f"SM2 加密内容密钥失败：{exc}") from exc
            if len(wrapped) != SM2_CT_LEN:
                raise PluginError(f"SM2 密文长度异常（{len(wrapped)} 字节）。")

            nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
            total = _stream_encrypt(cek, nonce_prefix, src, dst, on_progress)
            return (
                len(wrapped).to_bytes(2, "big")
                + wrapped + _sm3(cek) + nonce_prefix + total.to_bytes(8, "big")
            )
        finally:
            secure_zero(cek)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        credential: Optional[str],
        on_progress: ProgressFn,
        passphrase: Optional[str] = None,
    ) -> None:
        if len(metadata) < 2 + _META_TAIL_LEN:
            raise IntegrityError("元数据不完整，文件可能已损坏")
        ct_len = int.from_bytes(metadata[:2], "big")
        wrapped = metadata[2 : 2 + ct_len]
        off = 2 + ct_len
        cek_check = metadata[off : off + 32]
        nonce_prefix = metadata[off + 32 : off + 32 + NONCE_PREFIX_LEN]
        expect_total = int.from_bytes(metadata[off + 32 + NONCE_PREFIX_LEN : off + _META_TAIL_LEN], "big")
        if len(wrapped) != ct_len or len(cek_check) != 32 or len(nonce_prefix) != NONCE_PREFIX_LEN:
            raise IntegrityError("元数据不完整，文件可能已损坏")

        priv = _load_private_key(credential or "", passphrase)
        cek = None
        try:
            crypt = gm_sm2.CryptSM2(
                public_key="", private_key=priv.hex(), mode=1, asn1=False
            )
            try:
                cek = crypt.decrypt(wrapped)
            except Exception as exc:
                raise IntegrityError(f"SM2 解密内容密钥失败：{exc}") from exc
            # gmssl 对错误私钥静默返回乱码，用 SM3(CEK) 判定私钥是否正确
            if not cek or _sm3(cek) != cek_check:
                raise WrongPasswordError("私钥不匹配，或文件已被篡改/损坏")
            _stream_decrypt(cek, nonce_prefix, expect_total, src, dst, on_progress)
        finally:
            # 注：priv.hex() 会产生一份不可变十六进制字符串副本，str 无法可靠清零
            # （CPython 限制，见 securemem 模块文档）；字节副本在此全部清零。
            if cek is not None:
                secure_zero(cek)
            secure_zero(priv)
