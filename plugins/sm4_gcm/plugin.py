"""SM4-GCM 国密对称加密插件（密码模式）。

国密套件的标准组合思路，全部使用国密原语：

  密钥 = PBKDF2-HMAC-SM3(密码, salt, 32 字节, 200_000 轮)
  内容 = 逐块 SM4-GCM 认证加密（1 MiB 分块，nonce = 随机前缀 8B || 块计数 4B）

结构上与 aes-256-gcm 插件一一对应：SM3 替代 SHA-256 做密钥派生，
SM4（GB/T 32907-2016，128 位分组/密钥）替代 AES。逐块认证、截断检测、
错密码检测能力与 AES 插件完全一致。

元数据布局（共 32 字节）::

    salt(16) || nonce_prefix(8) || 明文总长度(8, 大端)

依赖：cryptography >= 36（提供 SM4 分组密码与 SM3 哈希）。
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

CHUNK_SIZE = 1024 * 1024          # 1 MiB，同 aes-256-gcm 插件
KEY_LEN = 16                      # SM4 密钥 128 位
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


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SM3(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ROUNDS
    ).derive(password.encode("utf-8"))


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """单块 SM4-GCM：返回 密文||16 字节标签（与 AESGCM 一次性接口格式一致）。"""
    enc = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct + enc.tag


def _gcm_decrypt(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    dec = Cipher(algorithms.SM4(key), modes.GCM(nonce, blob[-TAG_LEN:])).decryptor()
    return dec.update(blob[:-TAG_LEN]) + dec.finalize()  # 失败抛 InvalidTag


class Plugin(CryptoPlugin):
    id = "sm4-gcm"
    name = "SM4-GCM（国密）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = "国密对称认证加密：PBKDF2-HMAC-SM3 派生密钥 + 逐块 SM4-GCM，防篡改、防截断"

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(SALT_LEN)
        nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        key = _derive_key(password or "", salt)
        try:
            total, index = 0, 0
            while True:
                chunk = _read_exact(src, CHUNK_SIZE)
                if not chunk:
                    break
                nonce = nonce_prefix + index.to_bytes(4, "big")
                dst.write(_gcm_encrypt(key, nonce, chunk))
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
        key = _derive_key(password or "", salt)
        try:
            total, index = 0, 0
            while True:
                blob = _read_exact(src, CHUNK_SIZE + TAG_LEN)
                if not blob:
                    break
                if len(blob) <= TAG_LEN:
                    raise IntegrityError("密文块不完整，文件已损坏")
                nonce = nonce_prefix + index.to_bytes(4, "big")
                try:
                    plain = _gcm_decrypt(key, nonce, blob)
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
