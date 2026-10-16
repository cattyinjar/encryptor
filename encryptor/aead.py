"""分块认证加密共享层（容器元数据 v2 规范）。

为什么存在这个模块（审计发现 F2 的结构性修复）："分块 GCM + 元数据" 的
正确用法曾经被每个插件各写一遍，且都漏掉了对元数据的认证——攻击者删掉
尾部整块密文、改写元数据里的总长字段后，解密"成功"且无声丢数据。

本模块把安全关键逻辑收敛为唯一实现，全部插件共用：

  1. 每个密文块的 AAD 绑定插件 id（块与算法身份绑定，防跨插件拼接）；
  2. 元数据尾部的 MAC 认证**全部元数据字段 + 总长 + 插件 id**
     （trailer MAC）——改写任何字段（含无声截断攻击的总长）在解密一开始
     就被拒绝；对密码模式还兼作"错误口令立即检测"；
  3. KDF 参数（算法/迭代数）自描述地存入元数据——提升默认参数不再破坏
     旧文件的解密（本次为开发期，未保留 v1 回退路径）。

v2 元数据布局由各插件定义，但都遵守：首字节为版本号 2，末 32 字节为
trailer MAC，MAC 覆盖"除 MAC 自身外的全部元数据字节 + 插件 id"。

依赖：cryptography（AES/SM4 分组密码、SHA-256/SM3 哈希、PBKDF2、HMAC）。
"""

from __future__ import annotations

from typing import BinaryIO, Callable, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .sdk import IntegrityError, WrongPasswordError

ProgressFn = Callable[[int], None]

META_VERSION = 3
CHUNK_SIZE = 1024 * 1024
TAG_LEN = 16                      # GCM 认证标签
NONCE_PREFIX_LEN = 8              # + 4 字节块计数 = 12 字节 GCM nonce
MAC_LEN = 32                      # trailer MAC（SHA-256 与 SM3 均为 32 字节）
DEFAULT_ITERATIONS = 600_000      # OWASP 2023 起 PBKDF2 建议值
PRE_ITERS = 10_000                # 预验 KDF 固定轮数（N1：攻击者成本上限 ≈ 5ms）
MAX_ITERATIONS = 20_000_000       # 合理性上限（预验生效后仅为防线，非 DoS 杠杆）

# KDF 算法标识（写入元数据，自描述）
KDF_PBKDF2_SHA256 = 1
KDF_PBKDF2_SM3 = 2

_KDF_HASH = {
    KDF_PBKDF2_SHA256: hashes.SHA256,
    KDF_PBKDF2_SM3: hashes.SM3,
}


def _read_exact(src: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = src.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


# ---------------------------------------------------------------- 哈希/MAC/KDF

def hmac_digest(hash_cls, key: bytes, data: bytes) -> bytes:
    mac = HMAC(key, hash_cls())
    mac.update(data)
    return mac.finalize()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a, b)


def kdf_hash_cls(kdf_id: int):
    return _KDF_HASH[kdf_id]


def meta_mac_key(cek: bytes, hash_cls) -> bytes:
    """由内容密钥派生元数据 MAC 密钥（域分隔，不复用 CEK 本身）。"""
    return hmac_digest(hash_cls, cek, b"encryptor/meta-mac-key/v2")


def derive_pre_key(password: str, salt: bytes, kdf_id: int) -> bytes:
    """第一级派生：固定 PRE_ITERS 轮（与文件声明的迭代数无关）。

    用于元数据预验 MAC（N1 修复）——攻击者篡改迭代数等字段时，受害者在
    花费固定 ~1 万轮（毫秒级）后即可拒绝，无法再借元数据撬动任意 CPU 算力。
    返回值由调用方负责 secure_zero。
    """
    return PBKDF2HMAC(
        algorithm=_KDF_HASH[kdf_id](), length=32, salt=salt, iterations=PRE_ITERS
    ).derive(password.encode("utf-8"))


def derive_dual_key(password: str, salt: bytes, iterations: int, enc_len: int,
                    kdf_id: int) -> Tuple[bytes, bytes, bytes]:
    """两级口令派生：口令 →(1 万轮)→ pre_key →(声明轮数)→ (enc_key, mac_key, pre_key)。

    第二级以 pre_key 为口令继续 PBKDF2——合法文件的总开销仅多 ~1 万轮，
    而任何对声明轮数的篡改都会在廉价的第一级预验处被拒（N1）。
    返回的三个密钥由调用方负责 secure_zero。
    """
    pre_key = derive_pre_key(password, salt, kdf_id)
    dk = PBKDF2HMAC(
        algorithm=_KDF_HASH[kdf_id](), length=enc_len + MAC_LEN,
        salt=salt, iterations=iterations,
    ).derive(pre_key)
    return dk[:enc_len], dk[enc_len:], pre_key


def derive_dual_key_from_pre(pre_key: bytes, salt: bytes, iterations: int,
                             enc_len: int, kdf_id: int) -> Tuple[bytes, bytes]:
    """两级派生的第二级：预验通过后，从已验证的 pre_key 继续派生，不重复第一级。"""
    dk = PBKDF2HMAC(
        algorithm=_KDF_HASH[kdf_id](), length=enc_len + MAC_LEN,
        salt=salt, iterations=iterations,
    ).derive(pre_key)
    return dk[:enc_len], dk[enc_len:]


def build_password_meta(plugin_id: str, kdf_id: int, iterations: int,
                        salt: bytes, nonce_prefix: bytes, total: int,
                        pre_key: bytes, mac_key: bytes, hash_cls) -> bytes:
    """密码模式元数据（v3）：… ‖ pre_mac(32) ‖ mac(32)。

    pre_mac = HMAC(pre_key, 参数字段 ‖ 插件 id)   —— 廉价预验（N1）
    mac     = HMAC(mac_key, 参数字段 ‖ pre_mac ‖ 插件 id)
    """
    params = (
        bytes([META_VERSION, kdf_id])
        + iterations.to_bytes(4, "big")
        + salt + nonce_prefix + total.to_bytes(8, "big")
    )
    pre_mac = hmac_digest(hash_cls, pre_key, params + plugin_id.encode("ascii"))
    mac = hmac_digest(hash_cls, mac_key, params + pre_mac + plugin_id.encode("ascii"))
    return params + pre_mac + mac


def verify_password_meta(metadata: bytes, plugin_id: str):
    """解析密码模式元数据（v3），返回 (kdf_id, iters, salt, np, total, pre_mac, mac)。

    只做结构校验；pre_mac 的验证见 verify_password_pre_mac（必须先于全量 KDF）。
    """
    fixed = 2 + 4 + 16 + NONCE_PREFIX_LEN + 8 + MAC_LEN * 2
    if len(metadata) != fixed or metadata[0] != META_VERSION:
        raise IntegrityError("元数据长度或版本不正确，文件可能已损坏")
    kdf_id = metadata[1]
    if kdf_id not in _KDF_HASH:
        raise IntegrityError(f"未知的 KDF 标识 {kdf_id}")
    iterations = int.from_bytes(metadata[2:6], "big")
    if not 1000 <= iterations <= MAX_ITERATIONS:
        raise IntegrityError("KDF 迭代数不合理，文件可能已损坏")
    salt = metadata[6:22]
    nonce_prefix = metadata[22 : 22 + NONCE_PREFIX_LEN]
    total = int.from_bytes(metadata[22 + NONCE_PREFIX_LEN : -MAC_LEN * 2], "big")
    pre_mac = metadata[-MAC_LEN * 2 : -MAC_LEN]
    mac = metadata[-MAC_LEN:]
    return kdf_id, iterations, salt, nonce_prefix, total, pre_mac, mac


def verify_password_pre_mac(metadata: bytes, plugin_id: str, pre_key: bytes,
                            hash_cls) -> bool:
    """廉价预验（N1）：固定 PRE_ITERS 轮派生后验证 pre_mac。

    覆盖全部参数字段（含声明的迭代数）与插件 id——通过后才允许执行
    声明轮数的全量 KDF。失败按"密码错误或文件被篡改"处理。
    """
    params = metadata[: -MAC_LEN * 2]
    expect = hmac_digest(hash_cls, pre_key, params + plugin_id.encode("ascii"))
    return constant_time_equal(expect, metadata[-MAC_LEN * 2 : -MAC_LEN])


def password_meta_mac_input(metadata: bytes, plugin_id: str) -> Tuple[bytes, bytes]:
    """返回 (待认证的元数据字节, 期望的 MAC)。"""
    return metadata[:-MAC_LEN] + plugin_id.encode("ascii"), metadata[-MAC_LEN:]


# ---------------------------------------------------------------- 分块 GCM

def gcm_encrypt(key: bytes, cipher_alg, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """单块 GCM：返回 密文‖16 字节标签。cipher_alg 传 algorithms.AES / SM4。"""
    enc = Cipher(cipher_alg(key), modes.GCM(nonce)).encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return ct + enc.tag


def gcm_decrypt(key: bytes, cipher_alg, nonce: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) <= TAG_LEN:
        raise IntegrityError("密文块不完整，文件已损坏")
    dec = Cipher(cipher_alg(key), modes.GCM(nonce, blob[-TAG_LEN:])).decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    try:
        return dec.update(blob[:-TAG_LEN]) + dec.finalize()
    except InvalidTag:
        raise WrongPasswordError("密码错误，或文件已被篡改/损坏")


def stream_encrypt(key: bytes, cipher_alg, nonce_prefix: bytes,
                   src: BinaryIO, dst: BinaryIO, on_progress: ProgressFn,
                   aad: bytes) -> int:
    total, index = 0, 0
    while True:
        chunk = _read_exact(src, CHUNK_SIZE)
        if not chunk:
            break
        nonce = nonce_prefix + index.to_bytes(4, "big")
        dst.write(gcm_encrypt(key, cipher_alg, nonce, chunk, aad))
        total += len(chunk)
        on_progress(len(chunk))
        index += 1
        if len(chunk) < CHUNK_SIZE:
            break
    return total


def stream_decrypt(key: bytes, cipher_alg, nonce_prefix: bytes, expect_total: int,
                   src: BinaryIO, dst: BinaryIO, on_progress: ProgressFn,
                   aad: bytes) -> None:
    total, index = 0, 0
    while True:
        blob = _read_exact(src, CHUNK_SIZE + TAG_LEN)
        if not blob:
            break
        nonce = nonce_prefix + index.to_bytes(4, "big")
        plain = gcm_decrypt(key, cipher_alg, nonce, blob, aad)
        dst.write(plain)
        total += len(plain)
        on_progress(len(plain))
        index += 1
    if total != expect_total:
        raise IntegrityError(
            f"解密长度不符（期望 {expect_total} 字节，实际 {total} 字节），文件可能被截断"
        )
