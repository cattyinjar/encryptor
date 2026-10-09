"""RSA-OAEP + AES-256-GCM 混合加密插件（密钥文件模式）。

为什么是"混合"：RSA 单次只能加密略小于模长的数据（3072 位密钥约 360 字节），
无法直接加密大文件。本插件采用与 TLS/PGP 相同的标准思路：

  1. 随机生成 32 字节内容密钥 CEK；
  2. 文件内容用 CEK 做逐块 AES-256-GCM（分块方案同 aes-256-gcm 插件）；
  3. CEK 用接收方 RSA 公钥做 OAEP(SHA-256) 加密，密文存入容器元数据。

密钥文件为标准 PEM 格式（公钥 SubjectPublicKeyInfo / 私钥 PKCS#8），
与 openssl 等工具生成的密钥互相通用：
  openssl genrsa -out rsa_private_key.pem 3072
  openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

用法：加密选公钥文件，解密选私钥文件（无需密码）。

元数据布局（大端）::

    wrapped_cek_len(2) || wrapped_cek(=RSA 模长字节数) || nonce_prefix(8) || 明文总长(8)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
CEK_LEN = 32                      # AES-256 内容密钥
NONCE_PREFIX_LEN = 8              # + 4 字节块计数 = 12 字节 GCM nonce
TAG_LEN = 16                      # GCM 认证标签
KEYGEN_BITS = 3072
_META_TAIL_LEN = NONCE_PREFIX_LEN + 8


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _oaep():
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _ensure_strength(key) -> None:
    """RSA 密钥强度下限：低于 2048 位（约 112 位安全强度）直接拒绝。"""
    if key.key_size < 2048:
        raise PluginError(
            f"RSA-{key.key_size} 密钥强度不足（低于 2048 位），已拒绝使用。"
            "请用『生成密钥对』或 openssl 生成 RSA-3072 及以上密钥。"
        )


def _describe_rsa_size(bits: int) -> str:
    if bits >= 3072:
        return f"RSA-{bits}（约 128 位安全强度）"
    return f"RSA-{bits}（约 112 位安全强度，建议升级至 3072）"


def _load_public_key(credential: str) -> rsa.RSAPublicKey:
    path = Path(credential)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PluginError(f"无法读取公钥文件：{exc}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise PluginError(f"公钥文件解析失败（需要 PEM 格式）：{exc}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise PluginError("该文件不是 RSA 公钥（可能是 ECC 公钥或其他格式）")
    _ensure_strength(key)
    return key


def _load_private_key(credential: str, passphrase: Optional[str] = None) -> rsa.RSAPrivateKey:
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
        if not isinstance(key, rsa.RSAPrivateKey):
            raise PluginError("该文件不是 RSA 私钥（可能是 ECC 私钥或其他格式）")
        _ensure_strength(key)
        return key
    finally:
        secure_zero(data)  # 私钥文件内容字节，解析完立即清零


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
    id = "rsa-oaep-aes256gcm"
    name = "RSA 混合加密（OAEP）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = (
        "密钥文件模式：文件用随机 AES-256-GCM 密钥加密，该密钥再用你的 RSA 公钥"
        "（OAEP-SHA256）加密；加密选公钥文件，解密选私钥文件"
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
        if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
            return _describe_rsa_size(key.key_size)
        return ""

    def generate_keypair(self, dest_dir, passphrase=None) -> Tuple[Path, Path]:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        pub_path = dest / "rsa_public_key.pem"
        priv_path = dest / "rsa_private_key.pem"
        if pub_path.exists() or priv_path.exists():
            raise PluginError(
                f"目录下已存在 {pub_path.name} / {priv_path.name}，请换一个目录或先删除旧密钥。"
            )
        key = rsa.generate_private_key(public_exponent=65537, key_size=KEYGEN_BITS)
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
        public_key = _load_public_key(credential or "")
        cek = os.urandom(CEK_LEN)
        try:
            nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
            wrapped = public_key.encrypt(cek, _oaep())
            total = _stream_encrypt(AESGCM(cek), nonce_prefix, src, dst, on_progress)
            return (
                len(wrapped).to_bytes(2, "big") + wrapped + nonce_prefix + total.to_bytes(8, "big")
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
        wrap_len = int.from_bytes(metadata[:2], "big")
        wrapped = metadata[2 : 2 + wrap_len]
        off = 2 + wrap_len
        nonce_prefix = metadata[off : off + NONCE_PREFIX_LEN]
        expect_total = int.from_bytes(metadata[off + NONCE_PREFIX_LEN : off + _META_TAIL_LEN], "big")
        if len(wrapped) != wrap_len or len(nonce_prefix) != NONCE_PREFIX_LEN:
            raise IntegrityError("元数据不完整，文件可能已损坏")

        private_key = _load_private_key(credential or "", passphrase)
        cek = None
        try:
            try:
                cek = private_key.decrypt(wrapped, _oaep())
            except ValueError as exc:
                raise WrongPasswordError("私钥不匹配，或文件已被篡改/损坏") from exc
            _stream_decrypt(AESGCM(cek), nonce_prefix, expect_total, src, dst, on_progress)
        finally:
            if cek is not None:
                secure_zero(cek)
