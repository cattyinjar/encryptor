"""SM3 密钥流加密插件 —— 国密哈希 SM3 构造的流加密（密码模式，元数据 v2）。

xor-stream 的国密镜像，教学模板 + 完整性层（审计 F5 修复后）：

  密钥对 = PBKDF2-HMAC-SM3(密码, salt, 600_000 轮) → 32B 流密钥 + 32B MAC 密钥
  密钥流第 i 块 = SM3(key ‖ salt ‖ i(8B 大端))
  完整性 = HMAC-SM3(mac_key, "stream-mac" ‖ 插件 id ‖ 全部密文字节)
          + 口令预验证器（错口令立即报错）

元数据布局（大端，v2）::

    ver(1)=2 ‖ kdf_id ‖ 迭代数(4) ‖ salt(16) ‖ 验证器(16) ‖ MAC(32)

⚠️ 密钥流构造为教学演示；保护重要数据请使用 SM4-GCM / AES-256-GCM。

依赖：cryptography（SM3 哈希）。
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

from encryptor import aead
from encryptor.sdk import CryptoPlugin, IntegrityError, ProgressFn, WrongPasswordError, secure_zero

KDF_ID = aead.KDF_PBKDF2_SM3
ITERATIONS = aead.DEFAULT_ITERATIONS     # 600k（审计 F4）
CHUNK_SIZE = 64 * 1024
BLOCK = 32                               # SM3 输出长度
VERIFIER_LEN = 16
_META_LEN = 1 + 1 + 4 + 16 + VERIFIER_LEN + aead.MAC_LEN


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


def _xor_stream(key: bytes, salt: bytes, src: BinaryIO, sink, on_progress: ProgressFn,
                tap=None) -> None:
    """把 src 与 SM3 计数器密钥流异或，结果逐块交给 sink；tap 收到输入块原文。"""
    block_index = 0
    offset_in_block = 0
    keystream = b""
    try:
        while True:
            chunk = _read_exact(src, CHUNK_SIZE)
            if not chunk:
                break
            if tap is not None:
                tap(chunk)
            out = bytearray(len(chunk))
            pos = 0
            while pos < len(chunk):
                if offset_in_block == 0:
                    secure_zero(keystream)
                    counter = block_index.to_bytes(8, "big")
                    keystream = _sm3(key + salt + counter)
                take = min(BLOCK - offset_in_block, len(chunk) - pos)
                out[pos : pos + take] = (
                    b ^ k for b, k in zip(
                        chunk[pos : pos + take],
                        keystream[offset_in_block : offset_in_block + take],
                    )
                )
                pos += take
                offset_in_block += take
                if offset_in_block == BLOCK:
                    offset_in_block = 0
                    block_index += 1
            sink(bytes(out))
            on_progress(len(chunk))
    finally:
        secure_zero(keystream)


def _hmac_new(key: bytes, data: bytes):
    mac = HMAC(key, hashes.SM3())
    mac.update(data)
    return mac


class Plugin(CryptoPlugin):
    id = "sm3-stream"
    name = "SM3 密钥流（国密·示例）"
    version = "2.0.0"
    author = "Encryptor 内置示例"
    description = "国密教学示例：SM3 计数器密钥流 XOR + HMAC-SM3 完整性（附口令预验证）"
    authenticated = True

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(16)
        key, mac_key = aead.derive_dual_key(password or "", salt, ITERATIONS, 32, KDF_ID)
        try:
            verifier = aead.hmac_digest(
                hashes.SM3, mac_key, b"encryptor/stream-verifier"
            )[:VERIFIER_LEN]
            mac_ctx = _hmac_new(
                mac_key, b"encryptor/stream-mac" + self.id.encode("ascii")
            )

            def sink(ct: bytes) -> None:
                mac_ctx.update(ct)
                dst.write(ct)

            _xor_stream(key, salt, src, sink, on_progress)
            head = (
                bytes([aead.META_VERSION, KDF_ID])
                + ITERATIONS.to_bytes(4, "big") + salt + verifier
            )
            return head + mac_ctx.finalize()
        finally:
            secure_zero(key, mac_key)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> None:
        if len(metadata) != _META_LEN or metadata[0] != aead.META_VERSION:
            raise IntegrityError("元数据长度或版本不正确，文件可能已损坏")
        kdf_id = metadata[1]
        if kdf_id != KDF_ID:
            raise IntegrityError(f"KDF 标识不匹配（{kdf_id}），文件可能已损坏")
        iterations = int.from_bytes(metadata[2:6], "big")
        salt = metadata[6:22]
        verifier = metadata[22 : 22 + VERIFIER_LEN]
        mac = metadata[-aead.MAC_LEN:]

        key = mac_key = None
        try:
            key, mac_key = aead.derive_dual_key(password or "", salt, iterations, 32, kdf_id)
            # 口令预验证：错口令立即报错
            check = aead.hmac_digest(
                hashes.SM3, mac_key, b"encryptor/stream-verifier"
            )[:VERIFIER_LEN]
            if not aead.constant_time_equal(check, verifier):
                raise WrongPasswordError("密码错误，或文件已被篡改/损坏。")

            mac_ctx = _hmac_new(
                mac_key, b"encryptor/stream-mac" + self.id.encode("ascii")
            )
            # XOR 对称：输入是密文（经 tap 喂给 MAC），输出是明文
            _xor_stream(key, salt, src, dst.write, on_progress, tap=mac_ctx.update)

            if not aead.constant_time_equal(mac_ctx.finalize(), mac):
                raise IntegrityError("密文校验失败：文件已被篡改（如比特翻转或截断）。")
        finally:
            secure_zero(key, mac_key)
