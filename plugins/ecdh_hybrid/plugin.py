"""ECDH + AES-256-GCM 混合加密插件（密钥文件模式，ECIES 风格）。

ECC 公钥加密同样不能直接处理大文件，采用椭圆曲线集成加密（ECIES）思路：

  1. 随机生成 32 字节内容密钥 CEK；
  2. 文件内容用 CEK 做逐块 AES-256-GCM（分块方案同 aes-256-gcm 插件）；
  3. 每次加密生成一个临时 ECC 密钥对，与接收方公钥做 ECDH 密钥协商，
     经 HKDF-SHA256 派生出密钥加密密钥 KEK，用 KEK(AES-GCM) 包裹 CEK；
     临时公钥与包裹结果一起存入容器元数据。

解密方用自己的私钥 + 元数据中的临时公钥重演出相同 KEK，解开 CEK。
该结构提供前向保密语义外的标准 ECIES 安全性（每次加密 CEK 独立随机）。

密钥文件为标准 PEM 格式（公钥 SubjectPublicKeyInfo / 私钥 PKCS#8），与
openssl 生成的 ECC 密钥互通（曲线不限，建议 P-256 及以上）：
  openssl ecparam -name prime256v1 -genkey -noout -out ecc_private_key.pem
  openssl ec -in ecc_private_key.pem -pubout -out ecc_public_key.pem

用法：加密选公钥文件，解密选私钥文件（无需密码）。

元数据布局（大端）::

    eph_pub_len(2) || 临时公钥压缩点 || wrap_nonce(12) || wrapped_cek(48)
    || nonce_prefix(8) || 明文总长(8)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as _exc:  # 由插件管理器捕获并展示原因
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

CHUNK_SIZE = 1024 * 1024          # 1 MiB，同 aes-256-gcm 插件
CEK_LEN = 32
WRAP_NONCE_LEN = 12               # 包裹 CEK 用的 GCM nonce
WRAPPED_LEN = CEK_LEN + 16        # CEK + GCM 标签
NONCE_PREFIX_LEN = 8
TAG_LEN = 16
HKDF_INFO = b"encryptor/ecdh-aes256gcm/kek"

# 元数据中"包裹部分"之后的内容段固定长度
_META_TAIL_LEN = WRAP_NONCE_LEN + WRAPPED_LEN + NONCE_PREFIX_LEN + 8


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _ensure_strength(key) -> None:
    """ECC 曲线强度下限：低于 256 位曲线（约 128 位安全强度）直接拒绝。"""
    size = key.curve.key_size
    if size < 256:
        raise PluginError(
            f"曲线 {key.curve.name} 强度不足（{size} 位，低于 256 位），已拒绝使用。"
            "请使用 P-256 / P-384 / P-521 曲线密钥。"
        )


def _describe_curve(key) -> str:
    size = key.curve.key_size
    return f"ECC {key.curve.name}（{size} 位曲线，约 {size // 2} 位安全强度）"


def _load_public_key(credential: str) -> ec.EllipticCurvePublicKey:
    path = Path(credential)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PluginError(f"无法读取公钥文件：{exc}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise PluginError(f"公钥文件解析失败（需要 PEM 格式）：{exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise PluginError("该文件不是 ECC 公钥（可能是 RSA 公钥或其他格式）")
    _ensure_strength(key)
    return key


def _load_private_key(credential: str, passphrase: Optional[str] = None) -> ec.EllipticCurvePrivateKey:
    path = Path(credential)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PluginError(f"无法读取私钥文件：{exc}") from exc
    try:
        pwd = passphrase.encode("utf-8") if passphrase else None
        try:
            key = serialization.load_pem_private_key(data, password=pwd)
        except TypeError:
            if pwd is None:
                raise PluginError(
                    "该私钥文件设有口令保护，请在解密页的『口令』栏输入口令后重试。"
                ) from None
            # 文件本身未加密而用户多输了口令：忽略口令直接加载
            try:
                key = serialization.load_pem_private_key(data, password=None)
            except (ValueError, TypeError) as exc:
                raise PluginError(f"私钥文件解析失败（需要 PEM 格式）：{exc}") from exc
        except ValueError as exc:
            raise WrongPasswordError("私钥口令错误，或私钥文件已损坏。") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise PluginError("该文件不是 ECC 私钥（可能是 RSA 私钥或其他格式）")
        _ensure_strength(key)
        return key
    finally:
        secure_zero(data)  # 私钥文件内容字节，解析完立即清零


def _derive_kek(shared_secret: bytes, eph_pub_bytes: bytes) -> bytes:
    """ECDH 共享秘密 → HKDF → 32 字节 KEK。临时公钥作为盐绑定进派生。"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub_bytes,
        info=HKDF_INFO,
    ).derive(shared_secret)


def _stream_encrypt(cipher: AESGCM, nonce_prefix: bytes, src: BinaryIO, dst: BinaryIO,
                    on_progress: ProgressFn) -> int:
    total, index = 0, 0
    while True:
        chunk = _read_exact(src, CHUNK_SIZE)
        if not chunk:
            break
        nonce = nonce_prefix + index.to_bytes(4, "big")
        dst.write(cipher.encrypt(nonce, chunk, None))
        total += len(chunk)
        on_progress(len(chunk))
        index += 1
        if len(chunk) < CHUNK_SIZE:
            break
    return total


def _stream_decrypt(cipher: AESGCM, nonce_prefix: bytes, expect_total: int,
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
            plain = cipher.decrypt(nonce, blob, None)
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
    id = "ecdh-aes256gcm"
    name = "ECC 混合加密（ECDH）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = (
        "密钥文件模式：文件用随机 AES-256-GCM 密钥加密，该密钥经临时密钥 ECDH 协商"
        " + HKDF 派生密钥保护（ECIES 风格）；加密选公钥文件，解密选私钥文件"
    )
    credential_mode = "keyfile"
    encrypt_credential_hint = "公钥文件"
    decrypt_credential_hint = "私钥文件"
    supports_keygen = True
    keyfile_needs_passphrase = True   # 私钥可能是带口令的加密 PEM

    def describe_credential(self, credential, passphrase=None) -> str:
        try:
            data = Path(credential).read_bytes()
        except OSError:
            return ""
        key = None
        try:
            key = serialization.load_pem_public_key(data)
        except Exception:
            try:
                key = serialization.load_pem_private_key(
                    data, password=passphrase.encode("utf-8") if passphrase else None
                )
            except Exception:
                return ""
        if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
            return _describe_curve(key)
        return ""

    def generate_keypair(self, dest_dir, passphrase=None) -> Tuple[Path, Path]:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        pub_path = dest / "ecc_public_key.pem"
        priv_path = dest / "ecc_private_key.pem"
        if pub_path.exists() or priv_path.exists():
            raise PluginError(
                f"目录下已存在 {pub_path.name} / {priv_path.name}，请换一个目录或先删除旧密钥。"
            )
        key = ec.generate_private_key(ec.SECP256R1())
        pub_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        # 给出口令 → 标准加密私钥（PBKDF2+AES 信封，openssl 互通）；否则明文私钥
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
            if passphrase
            else serialization.NoEncryption()
        )
        priv_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            )
        )
        return pub_path, priv_path

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        credential: Optional[str],
        on_progress: ProgressFn,
        passphrase: Optional[str] = None,  # 公钥无需口令，忽略
    ) -> bytes:
        recip_pub = _load_public_key(credential or "")
        cek = os.urandom(CEK_LEN)
        shared = kek = None
        try:
            # 临时密钥对：曲线跟随接收方公钥
            eph_priv = ec.generate_private_key(recip_pub.curve)
            eph_pub_bytes = eph_priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
            shared = eph_priv.exchange(ec.ECDH(), recip_pub)
            kek = _derive_kek(shared, eph_pub_bytes)
            wrap_nonce = os.urandom(WRAP_NONCE_LEN)
            wrapped = AESGCM(kek).encrypt(wrap_nonce, cek, None)

            nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
            total = _stream_encrypt(AESGCM(cek), nonce_prefix, src, dst, on_progress)
            return (
                len(eph_pub_bytes).to_bytes(2, "big")
                + eph_pub_bytes + wrap_nonce + wrapped
                + nonce_prefix + total.to_bytes(8, "big")
            )
        finally:
            secure_zero(cek, shared, kek)

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
        eph_len = int.from_bytes(metadata[:2], "big")
        eph_pub_bytes = metadata[2 : 2 + eph_len]
        off = 2 + eph_len
        wrap_nonce = metadata[off : off + WRAP_NONCE_LEN]
        wrapped = metadata[off + WRAP_NONCE_LEN : off + WRAP_NONCE_LEN + WRAPPED_LEN]
        tail = metadata[off + WRAP_NONCE_LEN + WRAPPED_LEN : off + _META_TAIL_LEN]
        if (
            len(eph_pub_bytes) != eph_len
            or len(wrap_nonce) != WRAP_NONCE_LEN
            or len(wrapped) != WRAPPED_LEN
            or len(tail) != NONCE_PREFIX_LEN + 8
        ):
            raise IntegrityError("元数据不完整，文件可能已损坏")
        nonce_prefix = tail[:NONCE_PREFIX_LEN]
        expect_total = int.from_bytes(tail[NONCE_PREFIX_LEN:], "big")

        priv = _load_private_key(credential or "", passphrase)
        cek = shared = kek = None
        try:
            try:
                eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph_pub_bytes)
                shared = priv.exchange(ec.ECDH(), eph_pub)
            except ValueError as exc:
                raise IntegrityError(
                    "无法建立 ECDH 共享密钥（曲线不匹配、私钥不对应或文件已损坏）"
                ) from exc
            kek = _derive_kek(shared, eph_pub_bytes)
            try:
                cek = AESGCM(kek).decrypt(wrap_nonce, wrapped, None)
            except InvalidTag as exc:
                raise WrongPasswordError("私钥不匹配，或文件已被篡改/损坏") from exc
            _stream_decrypt(AESGCM(cek), nonce_prefix, expect_total, src, dst, on_progress)
        finally:
            secure_zero(cek, shared, kek)
