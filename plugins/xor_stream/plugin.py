"""XOR 流加密插件 —— 纯标准库实现，兼作插件开发模板（元数据 v2）。

结构（密码本模式 keystream + 审计 F5 修复后的完整性层）：

  密钥对 = PBKDF2-HMAC-SHA256(密码, salt, 600_000 轮) → 32B 流密钥 + 32B MAC 密钥
  密钥流第 i 块 = SHA-256(key ‖ salt ‖ i(8B 大端))，密文 = 明文 XOR 密钥流
  完整性 = HMAC-SHA256(mac_key, "stream-mac" ‖ 插件 id ‖ 全部密文字节)
          + 开工前的口令验证器（错口令立即报错，不再静默输出乱码）

v2 起密钥流教学插件也具备防篡改与错口令检测：比特翻转/密文截断/头部
插件 id 交换（xor ↔ sm3）全部在 MAC 处被拒绝。

元数据布局（大端，v2）::

    ver(1)=2 ‖ kdf_id ‖ 迭代数(4) ‖ salt(16) ‖ 验证器(16) ‖ MAC(32)

⚠️ 密钥流构造（哈希计数器）为教学演示，未经标准化评审；保护重要数据
   请使用 AES-256-GCM / SM4-GCM 等标准认证加密。
"""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO, Optional

from encryptor import aead
from encryptor.sdk import CryptoPlugin, IntegrityError, ProgressFn, WrongPasswordError, secure_zero

KDF_ID = aead.KDF_PBKDF2_SHA256
ITERATIONS = aead.DEFAULT_ITERATIONS     # 600k（审计 F4）
CHUNK_SIZE = 64 * 1024
KEYSTREAM_BLOCK = 32                     # SHA-256 输出长度
_META_LEN = 1 + 1 + 4 + 16 + aead.MAC_LEN * 2   # ver|kdf|iters|salt|pre_mac|mac


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def _xor_stream(key: bytes, salt: bytes, src: BinaryIO, sink, on_progress: ProgressFn,
                tap=None) -> None:
    """把 src 与 SHA-256 计数器密钥流异或，结果逐块交给 sink。

    tap（可选）在每块处理前收到**输入块**原文——加密时即明文（不用），
    解密时即密文（用于 MAC 覆盖全部密文）。每个密钥流块用完即清零。
    """
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
                    keystream = hashlib.sha256(key + salt + counter).digest()
                take = min(KEYSTREAM_BLOCK - offset_in_block, len(chunk) - pos)
                out[pos : pos + take] = (
                    b ^ k for b, k in zip(
                        chunk[pos : pos + take],
                        keystream[offset_in_block : offset_in_block + take],
                    )
                )
                pos += take
                offset_in_block += take
                if offset_in_block == KEYSTREAM_BLOCK:
                    offset_in_block = 0
                    block_index += 1
            sink(bytes(out))
            on_progress(len(chunk))
    finally:
        secure_zero(keystream)


def _hmac_new(hash_cls, key: bytes, data: bytes):
    from cryptography.hazmat.primitives.hmac import HMAC
    mac = HMAC(key, hash_cls())
    mac.update(data)
    return mac


class Plugin(CryptoPlugin):
    id = "xor-stream"
    name = "XOR 流加密（示例）"
    version = "2.0.0"
    author = "Encryptor 内置示例"
    description = "教学示例：SHA-256 计数器密钥流 XOR + HMAC-SHA256 完整性（附口令预验证）"
    authenticated = True

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        from cryptography.hazmat.primitives import hashes

        salt = os.urandom(16)
        key, mac_key, pre_key = aead.derive_dual_key(password or "", salt, ITERATIONS, 32, KDF_ID)
        try:
            mac_ctx = _hmac_new(
                hashes.SHA256, mac_key,
                b"encryptor/stream-mac" + self.id.encode("ascii"),
            )

            def sink(ct: bytes) -> None:
                mac_ctx.update(ct)
                dst.write(ct)

            _xor_stream(key, salt, src, sink, on_progress)
            params = (
                bytes([aead.META_VERSION, KDF_ID])
                + ITERATIONS.to_bytes(4, "big") + salt
            )
            pre_mac = aead.hmac_digest(
                hashes.SHA256, pre_key, params + self.id.encode("ascii")
            )
            return params + pre_mac + mac_ctx.finalize()
        finally:
            secure_zero(key, mac_key, pre_key)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> None:
        from cryptography.hazmat.primitives import hashes

        if len(metadata) != _META_LEN or metadata[0] != aead.META_VERSION:
            raise IntegrityError("元数据长度或版本不正确，文件可能已损坏")
        kdf_id = metadata[1]
        if kdf_id != KDF_ID:
            raise IntegrityError(f"KDF 标识不匹配（{kdf_id}），文件可能已损坏")
        iterations = int.from_bytes(metadata[2:6], "big")
        if not 1000 <= iterations <= aead.MAX_ITERATIONS:
            raise IntegrityError("KDF 迭代数不合理，文件可能已损坏")
        salt = metadata[6:22]
        mac = metadata[-aead.MAC_LEN:]

        key = mac_key = pre_key = None
        try:
            # 廉价预验（N1）：先以固定 ~1 万轮验证参数与口令，再做全量派生
            pre_key = aead.derive_pre_key(password or "", salt, kdf_id)
            params = metadata[: -aead.MAC_LEN * 2]
            expect_pre = aead.hmac_digest(
                hashes.SHA256, pre_key, params + self.id.encode("ascii")
            )
            if not aead.constant_time_equal(expect_pre, metadata[-aead.MAC_LEN * 2 : -aead.MAC_LEN]):
                raise WrongPasswordError("密码错误，或文件已被篡改/损坏。")
            key, mac_key = aead.derive_dual_key_from_pre(
                pre_key, salt, iterations, 32, kdf_id
            )

            mac_ctx = _hmac_new(
                hashes.SHA256, mac_key,
                b"encryptor/stream-mac" + self.id.encode("ascii"),
            )
            # XOR 对称：输入是密文（经 tap 喂给 MAC），输出是明文
            _xor_stream(key, salt, src, dst.write, on_progress, tap=mac_ctx.update)

            if not aead.constant_time_equal(mac_ctx.finalize(), mac):
                raise IntegrityError("密文校验失败：文件已被篡改（如比特翻转或截断）。")
        finally:
            secure_zero(key, mac_key, pre_key)
