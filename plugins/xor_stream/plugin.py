"""XOR 流加密插件 —— 纯标准库实现，兼作插件开发模板。

结构（密码本模式 keystream）：

  密钥     = PBKDF2-HMAC-SHA256(密码, salt, 32 字节, 150_000 轮)
  密钥流第 i 块 = SHA-256(key || salt || i(8 字节大端))
  密文 = 明文 XOR 密钥流

元数据布局（16 字节）：salt

⚠️ 该算法用于演示插件接口与教学，安全性有限（无认证标签，不能防篡改）。
   保护重要数据请使用 AES-256-GCM 等带认证的算法。
"""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO, Optional

from encryptor.sdk import CryptoPlugin, IntegrityError, ProgressFn, secure_zero

SALT_LEN = 16
KEY_LEN = 32
ROUNDS = 150_000
CHUNK_SIZE = 64 * 1024  # 64 KiB
KEYSTREAM_BLOCK = 32    # SHA-256 输出长度


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _xor_stream(key: bytes, salt: bytes, src: BinaryIO, dst: BinaryIO, on_progress: ProgressFn) -> None:
    """加解密共用：把 src 与 SHA-256 计数器密钥流异或后写入 dst。

    每个密钥流块用完即清零（密钥流由密钥派生，属敏感材料）。
    """
    block_index = 0
    offset_in_block = 0
    keystream = b""
    try:
        while True:
            chunk = _read_exact(src, CHUNK_SIZE)
            if not chunk:
                break
            out = bytearray(len(chunk))
            pos = 0
            while pos < len(chunk):
                if offset_in_block == 0:
                    secure_zero(keystream)  # 上一块用完即清零
                    counter = block_index.to_bytes(8, "big")
                    keystream = hashlib.sha256(key + salt + counter).digest()
                take = min(KEYSTREAM_BLOCK - offset_in_block, len(chunk) - pos)
                out[pos : pos + take] = (
                    b ^ k for b, k in zip(chunk[pos : pos + take], keystream[offset_in_block : offset_in_block + take])
                )
                pos += take
                offset_in_block += take
                if offset_in_block == KEYSTREAM_BLOCK:
                    offset_in_block = 0
                    block_index += 1
            dst.write(out)
            on_progress(len(chunk))
    finally:
        secure_zero(keystream)


class Plugin(CryptoPlugin):
    id = "xor-stream"
    name = "XOR 流加密（示例）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = "纯标准库演示算法：SHA-256 计数器密钥流 XOR，适合作为插件开发模板"

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(SALT_LEN)
        key = self.derive_key(password or "", salt, KEY_LEN, ROUNDS)
        try:
            _xor_stream(key, salt, src, dst, on_progress)
            return salt
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
        if len(metadata) != SALT_LEN:
            raise IntegrityError("元数据长度不正确，文件可能已损坏")
        salt = metadata
        key = self.derive_key(password or "", salt, KEY_LEN, ROUNDS)
        try:
            # XOR 对称，解密与加密是同一过程
            _xor_stream(key, salt, src, dst, on_progress)
        finally:
            secure_zero(key)
