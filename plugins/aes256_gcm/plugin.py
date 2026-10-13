"""AES-256-GCM 分块认证加密插件（密码模式，元数据 v2）。

结构（内容层由共享层 encryptor/aead.py 提供，修复审计发现 F2 的无声截断）：

  密钥对 = PBKDF2-HMAC-SHA256(密码, salt, 600_000 轮) → 32B 加密密钥 + 32B MAC 密钥
  内容   = 逐块 AES-256-GCM（1 MiB 分块，块 AAD 绑定插件 id）
  元数据 = ver(2) ‖ kdf_id ‖ 迭代数(4B) ‖ salt(16) ‖ nonce_prefix(8) ‖ 总长(8) ‖ MAC(32)

trailer MAC 认证全部元数据字段（含总长）与插件 id：改写任何字段——包括
"删尾块 + 改总长"的无声截断攻击——在解密一开始即被拒绝；对密码模式还
兼作错误口令的立即检测（空文件也适用）。KDF 参数自描述，未来可安全调参。

依赖：cryptography。
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms as _algs

from encryptor import aead
from encryptor.sdk import (
    CryptoPlugin,
    IntegrityError,
    ProgressFn,
    WrongPasswordError,
    secure_zero,
)

KDF_ID = aead.KDF_PBKDF2_SHA256
ITERATIONS = aead.DEFAULT_ITERATIONS     # 600k（审计 F4：OWASP 2023 建议值）
ENC_KEY_LEN = 32                         # AES-256


class Plugin(CryptoPlugin):
    id = "aes-256-gcm"
    name = "AES-256-GCM"
    version = "2.0.0"
    author = "Encryptor 内置示例"
    description = "工业级认证加密：PBKDF2 派生密钥 + 逐块 AES-GCM，防篡改、防截断（推荐）"
    authenticated = True

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        salt = os.urandom(16)
        nonce_prefix = os.urandom(aead.NONCE_PREFIX_LEN)
        enc_key, mac_key = aead.derive_dual_key(
            password or "", salt, ITERATIONS, ENC_KEY_LEN, KDF_ID
        )
        try:
            total = aead.stream_encrypt(
                enc_key, _algs.AES, nonce_prefix, src, dst,
                on_progress, self.id.encode("ascii"),
            )
            return aead.build_password_meta(
                self.id, KDF_ID, ITERATIONS, salt, nonce_prefix, total,
                mac_key, hashes.SHA256,
            )
        finally:
            secure_zero(enc_key, mac_key)

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> None:
        kdf_id, iterations, salt, nonce_prefix, total, mac = aead.verify_password_meta(
            metadata, self.id
        )
        if kdf_id != KDF_ID:
            raise IntegrityError(f"KDF 标识不匹配（{kdf_id}），文件可能已损坏")
        enc_key = mac_key = None
        try:
            enc_key, mac_key = aead.derive_dual_key(
                password or "", salt, iterations, ENC_KEY_LEN, kdf_id
            )
            # 先验 trailer MAC：错口令 / 元数据篡改 / 无声截断（F2）在此立即暴露
            mac_input, expect = aead.password_meta_mac_input(metadata, self.id)
            actual = aead.hmac_digest(hashes.SHA256, mac_key, mac_input)
            if not aead.constant_time_equal(actual, expect):
                raise WrongPasswordError("密码错误，或文件已被篡改/损坏")
            aead.stream_decrypt(
                enc_key, _algs.AES, nonce_prefix, total, src, dst,
                on_progress, self.id.encode("ascii"),
            )
        finally:
            secure_zero(enc_key, mac_key)
