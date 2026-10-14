"""修复验证重放：F2 无声截断 / F5 流密码与头部交换 / 新增 DoS 探测（v2 格式）。

向量：
  A) 删末块 + 改总长（v2 布局）→ 应被 trailer MAC 拒绝（不再无声成功）
  A2) 删末块不改总长 → 长度校验拒绝
  B) 块重排 → 拒绝
  C) xor/sm3 比特翻转 → MAC 拒绝
  D) 头部插件 id 交换 xor↔sm3 → 拒绝（不再静默乱码）
  E) 盐篡改 → 拒绝
  F) 追加整块垃圾 → 拒绝
  G) KDF 迭代数字段 DoS：篡改为 100_000_000 → 测量受害者耗时（MAC 在
     PBKDF2 之后才校验，字段上界 1e8 即最坏情况；记录实测秒数）
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

from lab import KEYS, SAMPLES, build_encx, dec, enc, parse

PASSWORD = "S3cret-P@ss2026!"
CHUNK = 1024 * 1024 + 16
ART = Path(__file__).resolve().parent / "artifacts_replay2"


def try_decrypt(path: Path, out: Path, cred: str, passphrase=None) -> str:
    try:
        n = dec(path, out, cred, passphrase=passphrase)
        return f"成功({n}B)"
    except WrongPasswordError:
        return "WrongPasswordError"
    except IntegrityError as e:
        return f"IntegrityError({str(e)[:22]})"
    except PluginError as e:
        return f"PluginError({str(e)[:22]})"
    except Exception as e:
        return f"{type(e).__name__}({str(e)[:22]})"


def v2_patch_total(meta: bytes, new_total: int) -> bytes:
    """v2 元数据：总长在 MAC 前 8 字节（各插件统一尾部 MAC=32B）。"""
    return meta[:-32 - 8] + new_total.to_bytes(8, "big") + meta[-32:]


def main() -> None:
    import shutil
    if ART.exists():
        shutil.rmtree(ART)
    ART.mkdir()

    print("=" * 78)
    print("A) 无声截断（F2 核心向量）：删末块 + 改总长 → v2 应拒绝")
    cases = [
        ("aes-256-gcm", PASSWORD),
        ("sm4-gcm", PASSWORD),
        ("rsa-oaep-aes256gcm", str(KEYS / "rsa-oaep-aes256gcm" / "rsa_private_key.pem")),
        ("ecdh-aes256gcm", str(KEYS / "ecdh-aes256gcm" / "ecc_private_key.pem")),
        ("sm2-sm4-gcm", str(KEYS / "sm2-sm4-gcm" / "sm2_private_key.pem")),
    ]
    for pid, cred in cases:
        src = SAMPLES / f"big3m.{pid}.encx"
        _, _, payload, meta = parse(src)
        blocks = [payload[i : i + CHUNK] for i in range(0, len(payload), CHUNK)]
        cut = b"".join(blocks[:-1])
        plain_len = sum(len(b) - 16 for b in blocks[:-1])
        f = ART / f"trunc.{pid}.encx"
        f.write_bytes(build_encx(pid, cut, v2_patch_total(meta, plain_len)))
        r1 = try_decrypt(f, ART / "t1.out", cred)
        f.write_bytes(build_encx(pid, cut, meta))
        r2 = try_decrypt(f, ART / "t2.out", cred)
        print(f"  {pid:<20} 改总长→{r1}  不改总长→{r2}")

    print()
    print("=" * 78)
    print("B) 块重排（aes / ecdh）")
    for pid, cred in (("aes-256-gcm", PASSWORD),
                      ("ecdh-aes256gcm", str(KEYS / "ecdh-aes256gcm" / "ecc_private_key.pem"))):
        _, _, payload, meta = parse(SAMPLES / f"big3m.{pid}.encx")
        blocks = [payload[i : i + CHUNK] for i in range(0, len(payload), CHUNK)]
        blocks[0], blocks[1] = blocks[1], blocks[0]
        f = ART / f"reord.{pid}.encx"
        f.write_bytes(build_encx(pid, b"".join(blocks), meta))
        print(f"  {pid:<20} {try_decrypt(f, ART / 'r.out', cred)}")

    print()
    print("=" * 78)
    print("C) 流密码比特翻转（xor / sm3）")
    plain = (SAMPLES / "secret.txt").read_bytes()
    for pid in ("xor-stream", "sm3-stream"):
        _, _, payload, meta = parse(SAMPLES / f"secret.{pid}.encx")
        off = plain.index(b"03:00")
        diff = bytes(a ^ b for a, b in zip(b"03:00", b"09:30"))
        forged = bytearray(payload)
        for i, d in enumerate(diff):
            forged[off + i] ^= d
        f = ART / f"flip.{pid}.encx"
        f.write_bytes(build_encx(pid, bytes(forged), meta))
        print(f"  {pid:<20} {try_decrypt(f, ART / 'f.out', PASSWORD)}")

    print()
    print("=" * 78)
    print("D) 头部插件 id 交换（xor ↔ sm3）")
    data = (SAMPLES / "secret.xor-stream.encx").read_bytes()
    forged = data.replace(b"ENCX\x01\x0a\x00xor-stream", b"ENCX\x01\x0a\x00sm3-stream")
    f = ART / "swap.encx"
    f.write_bytes(forged)
    print(f"  xor→sm3            {try_decrypt(f, ART / 's.out', PASSWORD)}")
    # 反向
    data = (SAMPLES / "secret.sm3-stream.encx").read_bytes()
    forged = data.replace(b"ENCX\x01\x0a\x00sm3-stream", b"ENCX\x01\x0a\x00xor-stream")
    f.write_bytes(forged)
    print(f"  sm3→xor            {try_decrypt(f, ART / 's2.out', PASSWORD)}")

    print()
    print("=" * 78)
    print("E) 盐篡改（aes） / F) 追加垃圾整块（aes）")
    _, _, payload, meta = parse(SAMPLES / "secret.aes-256-gcm.encx")
    m2 = bytearray(meta); m2[6] ^= 1   # v2: salt 在 [6:22]
    f = ART / "salt.encx"; f.write_bytes(build_encx("aes-256-gcm", payload, bytes(m2)))
    print(f"  盐翻 1 字节         {try_decrypt(f, ART / 'sa.out', PASSWORD)}")
    import os
    f.write_bytes(build_encx("aes-256-gcm", payload + os.urandom(CHUNK), meta))
    print(f"  追加垃圾整块        {try_decrypt(f, ART / 'ap.out', PASSWORD)}")

    print()
    print("=" * 78)
    print("G) KDF 迭代数 DoS 探测（aes：篡改 iterations=100_000_000 后测量解密耗时）")
    _, _, payload, meta = parse(SAMPLES / "secret.aes-256-gcm.encx")
    m3 = bytearray(meta)
    m3[2:6] = (100_000_000).to_bytes(4, "big")   # v2: iterations 在 [2:6]
    f = ART / "dos.encx"; f.write_bytes(build_encx("aes-256-gcm", payload, bytes(m3)))
    t0 = time.perf_counter()
    r = try_decrypt(f, ART / "dos.out", PASSWORD)
    dt = time.perf_counter() - t0
    print(f"  耗时 {dt:.1f}s → {r}   （上界 1e8 轮 ≈ 本机 {dt:.0f}s 单文件最坏 DoS）")


if __name__ == "__main__":
    main()
