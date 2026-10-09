"""SM3 密钥流加密插件 —— 国密哈希 SM3 构造的流加密（密码模式，教学示例）。

与 xor-stream 插件一一对应的国密版本，用于演示"哈希计数器密钥流"构造：

  密钥     = PBKDF2-HMAC-SM3(密码, salt, 32 字节, 150_000 轮)
  密钥流第 i 块 = SM3(key || salt || i(8 字节大端))
  密文 = 明文 XOR 密钥流

元数据布局（16 字节）：salt

⚠️ 与 xor-stream 相同：仅作插件接口演示与教学，无认证标签、不防篡改。
   保护重要数据请使用 SM4-GCM / AES-256-GCM 等认证加密。

依赖：cryptography（提供 SM3 哈希）。
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from encryptor.sdk import CryptoPlugin, IntegrityError, ProgressFn, secure_zero

SALT_LEN = 16
KEY_LEN = 32
ROUNDS = 150_000
CHUNK_SIZE = 64 * 1024  # 64 KiB
BLOCK = 32              # SM3 输出长度


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


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SM3(), length=KEY_LEN, salt=salt, iterations=ROUNDS
    ).derive(password.encode("utf-8"))


def _xor_stream(key: bytes, salt: bytes, src: BinaryIO, dst: BinaryIO,
                on_progress: ProgressFn) -> None:
    """加解密共用：把 src 与 SM3 计数器密钥流异或后写入 dst。

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
                    keystream = _sm3(key + salt + counter)
                take = min(BLOCK - offset_in_block, len(chunk) - pos)
                out[pos : pos + take] = (
                    b ^ k
                    for b, k in zip(
                        chunk[pos : pos + take],
                        keystream[offset_in_block : offset_in_block + take],
                    )
                )
                pos += take
                offset_in_block += take
                if offset_in_block == BLOCK:
                    offset_in_block = 0
                    block_index += 1
            dst.write(out)
            on_progress(len(chunk))
    finally:
        secure_zero(keystream)


class Plugin(CryptoPlugin):
    id = "sm3-stream"
    name = "SM3 密钥流（国密·示例）"
    version = "1.0.0"
    author = "Encryptor 内置示例"
    description = "国密教学示例：SM3 计数器密钥流 XOR（纯演示，无认证能力）"

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(SALT_LEN)
        key = _derive_key(password or "", salt)
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
        key = _derive_key(password or "", salt)
        try:
            # XOR 对称，解密与加密是同一过程
            _xor_stream(key, salt, src, dst, on_progress)
        finally:
            secure_zero(key)
