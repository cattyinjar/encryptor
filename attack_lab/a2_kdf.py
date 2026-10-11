"""攻击2：KDF 离线口令爆破。

攻击者模型：只持有 .encx 文件（盐在尾部元数据中明文可见），
在自己的机器上跑字典 —— 不需要接触受害者软件。
- aes-256-gcm/sm4-gcm：候选口令 → PBKDF2 → 解第一块 GCM，标签即验证器。
- xor-stream/sm3-stream：无认证标签，用已知明文头（文件格式魔数）验证。
"""

from __future__ import annotations

import hashlib
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from lab import SAMPLES, parse

# 迷你口令字典（现实攻击用 rockyou 1.4 亿条 / GPU 集群）
WORDLIST = ["password", "12345678", "admin", "qwerty", "letmein",
            "123456", "iloveyou", "111111", "abc123", "hunter2",
            "P@ssw0rd", "S3cret-P@ss2026!"]


def crack_aes_gcm(path, verify_len=64) -> tuple[str, float] | None:
    """对 aes-256-gcm 密文做字典爆破；用第一块 GCM 标签验证口令。"""
    _, hlen, payload, meta = parse(path)
    salt, nonce_prefix = meta[:16], meta[16:24]
    blob = payload[: 1024 * 1024 + 16]  # 只需第一块
    nonce = nonce_prefix + (0).to_bytes(4, "big")
    t0 = time.perf_counter()
    for pw in WORDLIST:
        key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000, dklen=32)
        try:
            AESGCM(key).decrypt(nonce, blob, None)
            return pw, time.perf_counter() - t0
        except Exception:
            continue
    return None, time.perf_counter() - t0


def crack_xor_stream(path, known_prefix: bytes) -> tuple[str, float] | None:
    """xor-stream 无标签：以已知明文前缀做验证器（现实中用文件格式魔数）。"""
    _, hlen, payload, meta = parse(path)
    salt = meta
    need = len(known_prefix)
    # 重现密钥流前 need 字节：SHA256(key||salt||counter) 拼接
    from lib_attack import xor_keystream_prefix
    t0 = time.perf_counter()
    for pw in WORDLIST:
        key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 150_000, dklen=32)
        ks = xor_keystream_prefix(key, salt, need)
        if bytes(a ^ b for a, b in zip(payload[:need], ks)) == known_prefix:
            return pw, time.perf_counter() - t0
    return None, time.perf_counter() - t0


def bench_kdf() -> dict:
    salt = b"\x00" * 16
    out = {}
    # SHA256 200k（aes 插件）
    t0 = time.perf_counter()
    for i in range(10):
        hashlib.pbkdf2_hmac("sha256", b"x", salt, 200_000, dklen=32)
    out["PBKDF2-HMAC-SHA256 x200k"] = 10 / (time.perf_counter() - t0)
    # SM3 200k（sm4 插件）
    t0 = time.perf_counter()
    for i in range(10):
        PBKDF2HMAC(algorithm=hashes.SM3(), length=16, salt=salt,
                   iterations=200_000).derive(b"x")
    out["PBKDF2-HMAC-SM3     x200k"] = 10 / (time.perf_counter() - t0)
    return out


def main() -> None:
    print("=" * 78)
    print("A) 本机（CPU）KDF 速率基准")
    for name, hps in bench_kdf().items():
        print(f"  {name}: {hps:,.0f} hash/s")

    print()
    print("=" * 78)
    print("B) aes-256-gcm 弱口令密文离线爆破（真实文件 weak.aes.encx，口令在字典中）")
    pw, sec = crack_aes_gcm(SAMPLES / "weak.aes.encx")
    print(f"  破解结果: {pw!r}  耗时 {sec:.1f}s（12 个候选，含 4 个错误候选在前面）")

    print()
    print("=" * 78)
    print("C) xor-stream 弱口令密文离线爆破（以已知明文前缀为验证器）")
    pw, sec = crack_xor_stream(SAMPLES / "weak.xor.encx",
                               b"weak password demo payload ")
    print(f"  破解结果: {pw!r}  耗时 {sec:.1f}s")

    print()
    print("=" * 78)
    print("D) 口令空间成本估算（aes-256-gcm, 200k 轮）")
    hps = bench_kdf()["PBKDF2-HMAC-SHA256 x200k"]
    for label, space in [("8 位纯数字", 1e8), ("8 位小写字母", 2.68e11),
                         ("8 位大小写+数字", 2.18e14), ("12 位随机 ASCII", 9.5e23)]:
        t = space / 2 / hps / 86400 / 365
        unit = "年"
        if t > 1e6:
            t, unit = f"{t:.1e}", "年"
        else:
            t = f"{t:,.0f}"
        print(f"  {label:<18} 期望耗时(本机CPU): {t} {unit}")


if __name__ == "__main__":
    main()
