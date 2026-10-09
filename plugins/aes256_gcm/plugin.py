"""AES-256-GCM 分块认证加密插件（依赖第三方库 cryptography）。

结构（encrypt-then-authenticate，逐块 AEAD）：

  密钥   = PBKDF2-HMAC-SHA256(密码, salt, 32 字节, 200_000 轮)
  明文按 1 MiB 分块，第 i 块使用 96 位 nonce = nonce_prefix(8B) || i(4B)
  独立做 AES-256-GCM 认证加密，密文块 = 密文 || 16 字节认证标签。

元数据布局（共 32 字节）::

    salt(16) || nonce_prefix(8) || 明文总长度(8, 大端)

特性：逐块认证（改一个字节整块解密失败）、截断检测（总长度校验）、
错密码与损坏文件在解密时报 WrongPasswordError / IntegrityError。
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as _exc:  # 由插件管理器捕获并展示原因
    raise ImportError(
        "本插件依赖第三方库 cryptography，请先执行: pip install cryptography"
    ) from _exc

from encryptor.sdk import (
    CryptoPlugin,
    IntegrityError,
    ProgressFn,
    WrongPasswordError,
    secure_zero,
)

CHUNK_SIZE = 1024 * 1024          # 1 MiB
KEY_LEN = 32                      # AES-256
SALT_LEN = 16
NONCE_PREFIX_LEN = 8              # + 4 字节块计数 = 12 字节 GCM nonce
TAG_LEN = 16                      # GCM 认证标签
PBKDF2_ROUNDS = 200_000
META_LEN = SALT_LEN + NONCE_PREFIX_LEN + 8


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


class Plugin(CryptoPlugin):
    id = "aes-256-gcm"
    name = "AES-256-GCM"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = "工业级认证加密：PBKDF2 派生密钥 + 逐块 AES-GCM，防篡改、防截断（推荐）"

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(SALT_LEN)
        nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        key = self.derive_key(password or "", salt, KEY_LEN, PBKDF2_ROUNDS)
        try:
            cipher = AESGCM(key)

            total = 0
            index = 0
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

            return salt + nonce_prefix + total.to_bytes(8, "big")
        finally:
            secure_zero(key)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> None:
        if len(metadata) != META_LEN:
            raise IntegrityError("元数据长度不正确，文件可能已损坏")
        salt = metadata[:SALT_LEN]
        nonce_prefix = metadata[SALT_LEN : SALT_LEN + NONCE_PREFIX_LEN]
        expect_total = int.from_bytes(metadata[SALT_LEN + NONCE_PREFIX_LEN :], "big")

        key = self.derive_key(password or "", salt, KEY_LEN, PBKDF2_ROUNDS)
        try:
            cipher = AESGCM(key)

            total = 0
            index = 0
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
                    raise WrongPasswordError("密码错误，或文件已被篡改/损坏")
                dst.write(plain)
                total += len(plain)
                on_progress(len(plain))
                index += 1
        finally:
            secure_zero(key)

        if total != expect_total:
            raise IntegrityError(
                f"解密长度不符（期望 {expect_total} 字节，实际 {total} 字节），文件可能被截断"
            )
