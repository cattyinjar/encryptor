"""SM4-GCM 国密对称加密插件（密码模式，元数据 v2）。

与 aes-256-gcm 插件结构一一对应，全部使用国密原语；内容层由共享层
encryptor/aead.py 提供（块 AAD 绑定插件 id、trailer MAC 认证全部元数据，
修复审计发现 F2 的无声截断）：

  密钥对 = PBKDF2-HMAC-SM3(密码, salt, 600_000 轮) → 16B 加密密钥 + 32B MAC 密钥
  内容   = 逐块 SM4-GCM（GB/T 32907 SM4，1 MiB 分块）
  元数据 = ver(2) ‖ kdf_id ‖ 迭代数(4B) ‖ salt(16) ‖ nonce_prefix(8) ‖ 总长(8) ‖ MAC(32)

依赖：cryptography（SM4 分组密码与 SM3 哈希）。
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

KDF_ID = aead.KDF_PBKDF2_SM3
ITERATIONS = aead.DEFAULT_ITERATIONS     # 600k（审计 F4）
ENC_KEY_LEN = 16                         # SM4 密钥 128 位


class Plugin(CryptoPlugin):
    id = "sm4-gcm"
    name = "SM4-GCM（国密）"
    version = "2.0.0"
    author = "Encryptor 内置示例"
    description = "国密对称认证加密：PBKDF2-HMAC-SM3 派生密钥 + 逐块 SM4-GCM，防篡改、防截断"
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
                enc_key, _algs.SM4, nonce_prefix, src, dst,
                on_progress, self.id.encode("ascii"),
            )
            return aead.build_password_meta(
                self.id, KDF_ID, ITERATIONS, salt, nonce_prefix, total,
                mac_key, hashes.SM3,
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
            mac_input, expect = aead.password_meta_mac_input(metadata, self.id)
            actual = aead.hmac_digest(hashes.SM3, mac_key, mac_input)
            if not aead.constant_time_equal(actual, expect):
                raise WrongPasswordError("密码错误，或文件已被篡改/损坏")
            aead.stream_decrypt(
                enc_key, _algs.SM4, nonce_prefix, total, src, dst,
                on_progress, self.id.encode("ascii"),
            )
        finally:
            secure_zero(enc_key, mac_key)
