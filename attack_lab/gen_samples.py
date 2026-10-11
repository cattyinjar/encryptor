"""生成攻击样本：明文 + 全部 7 插件的真实密文 + 密钥文件。"""

from __future__ import annotations

import os

from lab import KEYS, SAMPLES, ALL_PLUGINS, enc, get, registry

PASSWORD = "S3cret-P@ss2026!"      # 假设的受害者强口令
WEAK_PASSWORD = "123456"           # 用于弱口令爆破演示


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)
    KEYS.mkdir(exist_ok=True)

    # ---- 明文样本 ----
    secret = ("绝密行动简报\n"
              "代号：夜枭\n"
              "会合时间：2026-10-11 03:00\n"
              "坐标：39.9042 N, 116.4074 E\n"
              "联络人：Mr. Smith, +1-555-0100\n").encode("utf-8")
    (SAMPLES / "secret.txt").write_bytes(secret)

    # 3 MiB + 1 字节：多块场景（截断/拼接攻击用），首 64 字节为已知文件头
    big = b"%PDF-1.7 ATTACK-TEST-BIGFILE\n" + os.urandom(3 * 1024 * 1024 - 29 + 1)
    (SAMPLES / "big3m.bin").write_bytes(big)

    # 弱口令样本（aes 与 xor 各一份）
    (SAMPLES / "weak_plain.txt").write_bytes(
        b"weak password demo payload " + os.urandom(1024))

    reg = registry()
    print("已加载插件:", [p.id for p in reg.loaded])

    # ---- 密码模式插件 × 4 ----
    for pid in ("aes-256-gcm", "xor-stream", "sm4-gcm", "sm3-stream"):
        n = enc(SAMPLES / "secret.txt", SAMPLES / f"secret.{pid}.encx", PASSWORD, pid)
        print(f"[password] {pid}: {n} B 明文 -> secret.{pid}.encx")
        enc(SAMPLES / "big3m.bin", SAMPLES / f"big3m.{pid}.encx", PASSWORD, pid)
        # 同口令同明文加密两次 → 检查确定性
        enc(SAMPLES / "secret.txt", SAMPLES / f"secret.{pid}.encx.2", PASSWORD, pid)

    # 弱口令样本
    enc(SAMPLES / "weak_plain.txt", SAMPLES / "weak.aes.encx", WEAK_PASSWORD, "aes-256-gcm")
    enc(SAMPLES / "weak_plain.txt", SAMPLES / "weak.xor.encx", WEAK_PASSWORD, "xor-stream")

    # ---- 密钥文件模式插件 × 3：生成密钥对（无口令 + 带口令各一套） ----
    for pid in ("rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"):
        p = get(pid)
        pub_n, priv_n = p.generate_keypair(KEYS / pid)                 # 无口令
        pub_p, priv_p = p.generate_keypair(KEYS / (pid + "-pass"),
                                           passphrase="key-pass-9")    # 带口令
        n = enc(SAMPLES / "secret.txt", SAMPLES / f"secret.{pid}.encx", str(pub_n), pid)
        print(f"[keyfile]   {pid}: {n} B 明文 -> secret.{pid}.encx")
        enc(SAMPLES / "big3m.bin", SAMPLES / f"big3m.{pid}.encx", str(pub_n), pid)
        # 带口令密钥对样本
        enc(SAMPLES / "secret.txt", SAMPLES / f"secret.{pid}.pass.encx", str(pub_p), pid)

    print("样本生成完毕 ->", SAMPLES)


if __name__ == "__main__":
    main()
