"""SM2 混合加密插件（国密套件，密钥文件模式）——审计修复后 v2 实现。

红队审计（attack_lab，F1/F3/F7）后的重写要点：

  * **随机数全接管**：私钥与每次加密的临时密钥 k 全部来自 CSPRNG
    （``CryptoPlugin.secure_random_int``，os.urandom 拒绝采样）。不再使用
    gmssl 的 ``random_hex``（MT19937，审计实测可预测私钥，F1）；
  * **不再调用 gmssl 的 encrypt/decrypt**，SM2 加解密在本插件内自实现：
    - 解密前校验 C1 在标准曲线上（F3，GB/T 32918 强制要求）；
    - 解密时校验 C3（gmssl 原实现跳过，错误私钥会静默输出乱码）；
    - 全程 bytes/bytearray，无十六进制字符串副本（F7 的 CEK hex 残留路径）；
  * 依赖仅剩 cryptography（SM3/SM4）；gmssl 只在测试中用于交叉验证。

结构（完整国密三件套）：

  1. 每次加密随机生成 16 字节内容密钥 CEK（SM4 密钥长度）；
  2. 文件内容用 CEK 做逐块 SM4-GCM（共享层 encryptor/aead.py，块 AAD 绑定
     插件 id，元数据尾 MAC 认证全部字段，修复无声截断 F2）；
  3. CEK 用接收方 SM2 公钥加密（C1C3C2 格式），连同元数据 MAC 一起存入容器。

密钥文件格式（Encryptor 自有封装，标准 SM2 推荐曲线参数）::

    公钥     -----BEGIN SM2 PUBLIC KEY-----          base64(64 字节 x||y)
    私钥     -----BEGIN SM2 PRIVATE KEY-----         base64(32 字节)
    加密私钥 -----BEGIN ENCRYPTED SM2 PRIVATE KEY-----
             base64(salt(16) || nonce(12) || SM4-GCM 密文(48))   ← 口令保护

元数据布局（大端，v2）::

    ver(1)=2 || sm2 密文 C1(64)‖C3(32)‖C2(16) || nonce_prefix(8)
    || 明文总长(8) || MAC(32)

  MAC = HMAC-SM3(mac_key, 上述除 MAC 外全部字节 ‖ 插件 id)，mac_key 由 CEK 派生。
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms as _ciphers
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from encryptor import aead
from encryptor.sdk import (
    CryptoPlugin,
    IntegrityError,
    PluginError,
    ProgressFn,
    WrongPasswordError,
    secure_zero,
)

# ---------------------------------------------------------------- SM2 曲线
# GB/T 32918-2016 推荐曲线参数（256 位）。tests/test_sm2_crypto.py 会与
# gmssl 的 default_ecc_table 交叉核对，防止抄写错误。

_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_G = (
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
)

CEK_LEN = 16                       # SM4 密钥 128 位
SM2_CT_LEN = 112                   # C1(64) || C3(32) || C2(=CEK 16)
CHUNK_SIZE = aead.CHUNK_SIZE
NONCE_PREFIX_LEN = aead.NONCE_PREFIX_LEN
TAG_LEN = aead.TAG_LEN
SALT_LEN = 16
WRAP_NONCE_LEN = 12
PRIV_LEN = 32
PUB_LEN = 64
KEYFILE_ROUNDS = aead.DEFAULT_ITERATIONS
SM4_KEY_LEN = 16
_META_HEAD_LEN = 1 + SM2_CT_LEN + NONCE_PREFIX_LEN + 8   # ver + sm2ct + np + total
_META_LEN = _META_HEAD_LEN + aead.MAC_LEN


# ---------------------------------------------------------------- 点运算

def _inv(x: int) -> int:
    return pow(x, -1, _P)


def _add(p1, p2):
    """仿射坐标点加；None 表示无穷远点。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _mul(k: int, point):
    """二进制展开标量乘（非常数时间：本地工具，无远程计时面，见审计 F6）。"""
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _on_curve(point) -> bool:
    x, y = point
    if not (0 <= x < _P and 0 <= y < _P):
        return False
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _point_to_bytes(point) -> bytes:
    return point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def _bytes_to_point(data: bytes):
    return int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big")


# ---------------------------------------------------------------- SM3 / KDF

def _sm3(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SM3())
    h.update(data)
    return h.finalize()


def _kdf(z: bytes, klen: int) -> bytes:
    """GM/T 0003.4 KDF：t = SM3(Z ‖ ct)，ct = 1,2,…（不校验全零输出由调用方负责）。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += _sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


# ---------------------------------------------------------------- SM2 加解密

def _sm2_encrypt(plaintext: bytes, pub_point) -> bytes:
    """GB/T 32918 标准加密，输出 C1(64B) ‖ C3(32B) ‖ C2。k 来自 CSPRNG。

    C3 = SM3(x2 ‖ M ‖ y2)，x2/y2 来自共享点 S = k·P（不是 C1）。
    """
    for _ in range(64):  # t 全零的概率约 2^-128，循环仅为形式完备
        k = CryptoPlugin.secure_random_int(_N)
        c1 = _mul(k, _G)
        s = _mul(k, pub_point)
        if c1 is None or s is None:
            continue
        z = _point_to_bytes(s)
        t = _kdf(z, len(plaintext))
        if any(t):
            try:
                c2 = bytes(a ^ b for a, b in zip(plaintext, t))
                c3 = _sm3(z[:32] + plaintext + z[32:])
                return _point_to_bytes(c1) + c3 + c2
            finally:
                secure_zero(t)
                secure_zero(z)
    raise PluginError("SM2 加密：KDF 输出异常")


def _sm2_decrypt(wrapped: bytes, priv: int):
    """解密并校验 C1 在曲线 / C3 一致。返回明文；任何失败按异常报告。"""
    if len(wrapped) != SM2_CT_LEN:
        raise IntegrityError("SM2 密文长度不正确，文件可能已损坏")
    c1_bytes, c3, c2 = wrapped[:64], wrapped[64:96], wrapped[96:]
    c1 = _bytes_to_point(c1_bytes)
    if not _on_curve(c1):
        raise IntegrityError("SM2 密文 C1 不在标准曲线上，文件无效或被篡改")
    s = _mul(priv, c1)
    if s is None:
        raise IntegrityError("SM2 解密得到无穷远点，文件无效")
    z = _point_to_bytes(s)
    t = _kdf(z, len(c2))
    try:
        plaintext = bytes(a ^ b for a, b in zip(c2, t))
        c3_check = _sm3(z[:32] + plaintext + z[32:])
    finally:
        secure_zero(t)
        secure_zero(z)
    if c3_check != c3:
        raise WrongPasswordError("私钥不匹配，或文件已被篡改/损坏")
    return plaintext


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
    if not _on_curve(_bytes_to_point(pub)):
        raise PluginError("SM2 公钥不在标准曲线上，文件无效。")
    return pub


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return aead.gcm_encrypt(key, _ciphers.SM4, nonce, plaintext, b"")


def _gcm_decrypt(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    return aead.gcm_decrypt(key, _ciphers.SM4, nonce, blob, b"")


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
        return _gcm_decrypt(key, nonce, ct)
    except WrongPasswordError:
        raise WrongPasswordError("私钥口令错误，或私钥文件已损坏。") from None
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
        if not 1 <= int.from_bytes(priv, "big") < _N:
            raise PluginError("SM2 私钥数值无效。")
        return priv
    finally:
        secure_zero(data)  # 私钥文件内容字节，解析完立即清零


class Plugin(CryptoPlugin):
    id = "sm2-sm4-gcm"
    name = "SM2 混合加密（国密套件）"
    version = "2.0.0"
    author = "Encryptor 内置示例"
    description = (
        "密钥文件模式（国密）：SM2 公钥保护随机 SM4 内容密钥，文件逐块 SM4-GCM "
        "认证加密；加密选公钥文件，解密选私钥文件"
    )
    credential_mode = "keyfile"
    encrypt_credential_hint = "公钥文件"
    decrypt_credential_hint = "私钥文件"
    supports_keygen = True
    keyfile_needs_passphrase = True   # 私钥可能带口令（SM4-GCM 信封）
    authenticated = True

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
        # CSPRNG 私钥（审计 F1 修复：不再使用 gmssl random_hex/MT19937）
        d = self.secure_random_int(_N)
        pub_point = _mul(d, _G)
        if pub_point is None:
            raise PluginError("SM2 公钥生成失败")
        priv = d.to_bytes(PRIV_LEN, "big")
        try:
            pub_path.write_bytes(_armor("SM2 PUBLIC KEY", _point_to_bytes(pub_point)))
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
        mac_key = None
        try:
            wrapped = _sm2_encrypt(cek, _bytes_to_point(pub))
            nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
            total = aead.stream_encrypt(
                cek, _ciphers.SM4, nonce_prefix, src, dst, on_progress, self.id.encode("ascii")
            )
            mac_key = aead.meta_mac_key(cek, hashes.SM3)
            meta = (
                bytes([aead.META_VERSION]) + wrapped + nonce_prefix
                + total.to_bytes(8, "big")
            )
            return meta + aead.hmac_digest(hashes.SM3, mac_key, meta + self.id.encode("ascii"))
        finally:
            secure_zero(cek, mac_key)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        credential: Optional[str],
        on_progress: ProgressFn,
        passphrase: Optional[str] = None,
    ) -> None:
        if len(metadata) != _META_LEN or metadata[0] != aead.META_VERSION:
            raise IntegrityError("元数据长度或版本不正确，文件可能已损坏")
        wrapped = metadata[1 : 1 + SM2_CT_LEN]
        off = 1 + SM2_CT_LEN
        nonce_prefix = metadata[off : off + NONCE_PREFIX_LEN]
        expect_total = int.from_bytes(metadata[off + NONCE_PREFIX_LEN : -aead.MAC_LEN], "big")
        mac = metadata[-aead.MAC_LEN:]

        priv = _load_private_key(credential or "", passphrase)
        cek = None
        mac_key = None
        try:
            cek = _sm2_decrypt(wrapped, int.from_bytes(priv, "big"))
            mac_key = aead.meta_mac_key(cek, hashes.SM3)
            expect_mac = aead.hmac_digest(
                hashes.SM3, mac_key, metadata[:-aead.MAC_LEN] + self.id.encode("ascii")
            )
            if expect_mac != mac:
                raise IntegrityError("元数据校验失败，文件已被篡改或损坏。")
            aead.stream_decrypt(
                cek, _ciphers.SM4, nonce_prefix, expect_total, src, dst,
                on_progress, self.id.encode("ascii"),
            )
        finally:
            if cek is not None:
                secure_zero(cek)
            if mac_key is not None:
                secure_zero(mac_key)
