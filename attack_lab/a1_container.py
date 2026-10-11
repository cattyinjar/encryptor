"""攻击1：容器格式分析 —— 头部泄露、明文残留、熵/统计特性、确定性、相关性。

攻击者视角：只拿到 .encx 文件字节，不运行任何解密代码。
"""

from __future__ import annotations

import math
from collections import Counter

from lab import SAMPLES, dec, parse

PASSWORD = "S3cret-P@ss2026!"
PLAIN = (SAMPLES / "secret.txt").read_bytes()
PLAIN_BIG = (SAMPLES / "big3m.bin").read_bytes()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def chi_square(data: bytes) -> float:
    c = Counter(data)
    n = len(data)
    exp = n / 256
    return sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))


def hexdump(b: bytes, width: int = 32) -> str:
    rows = []
    for i in range(0, len(b), width):
        chunk = b[i : i + width]
        rows.append(f"  +{i:04d}  {chunk.hex(' ')}  |{''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)}|")
    return "\n".join(rows)


def find_substrings(hay: bytes, needles: list[bytes]) -> list[str]:
    hits = []
    for nd in needles:
        if nd in hay:
            hits.append(nd.decode("utf-8", "replace"))
    return hits


def main() -> None:
    print("=" * 78)
    print("0) 先做一次正常解密回环（确认软件本身可用，排除‘测了个坏软件’）")
    for pid in ("aes-256-gcm", "xor-stream", "sm4-gcm", "sm3-stream"):
        out = SAMPLES / f"rt.{pid}"
        n = dec(SAMPLES / f"secret.{pid}.encx", out, PASSWORD)
        assert out.read_bytes() == PLAIN, f"{pid} 回环失败"
        out.unlink()
        print(f"  [ok] {pid}: {n}B 回环一致")

    print()
    print("=" * 78)
    print("A) 容器结构 / 明文泄露扫描 / 熵")
    needles = ["夜枭".encode(), "39.9042".encode(), "Mr. Smith".encode(),
               "%PDF-1.7".encode(), b"ATTACK-TEST-BIGFILE", b"S3cret"]
    for f in sorted(SAMPLES.glob("secret.*.encx")) + sorted(SAMPLES.glob("big3m.*.encx")):
        pid, hlen, payload, meta = parse(f)
        leaks = find_substrings(f.read_bytes(), needles)
        print(f"  {f.name}")
        print(f"    plugin_id(明文)={pid!r} 头长={hlen} 载荷={len(payload)}B 元数据={len(meta)}B "
              f"总开销={f.stat().st_size - len(PLAIN if 'big3m' not in f.name else PLAIN_BIG)}B")
        print(f"    熵={shannon_entropy(payload):.4f} bit/byte  χ²={chi_square(payload[:65536]):.1f}(df=255, 期望≈255±22)")
        print(f"    明文子串命中: {leaks if leaks else '无'}")
        if f.name.startswith("secret.aes") or f.name.startswith("secret.xor"):
            print(f"    头 48B:\n{hexdump(f.read_bytes()[:48])}")
            print(f"    尾 40B:\n{hexdump(f.read_bytes()[-40:])}")

    print()
    print("=" * 78)
    print("B) 确定性检验：同口令同明文加密两次")
    for pid in ("aes-256-gcm", "xor-stream", "sm4-gcm", "sm3-stream"):
        f1 = (SAMPLES / f"secret.{pid}.encx").read_bytes()
        f2 = (SAMPLES / f"secret.{pid}.encx.2").read_bytes()
        _, _, p1, m1 = parse(SAMPLES / f"secret.{pid}.encx")
        _, _, p2, m2 = parse(SAMPLES / f"secret.{pid}.encx.2")
        print(f"  {pid}: 全文件不同={f1 != f2}  密文区不同={p1 != p2}  元数据不同={m1 != m2}")

    print()
    print("=" * 78)
    print("C) 同口令跨文件相关性：C1 ⊕ C2 应为随机（密钥流/nonce 无复用）")
    _, _, pa1, _ = parse(SAMPLES / "secret.aes-256-gcm.encx")
    _, _, pa2, _ = parse(SAMPLES / "secret.aes-256-gcm.encx.2")
    x = bytes(a ^ b for a, b in zip(pa1, pa2))
    print(f"  aes-256-gcm   同口令两文件 C⊕C' 熵={shannon_entropy(x):.4f}（随机期望≈8，明文⊕明文≈6.x）")

    _, _, px1, m1 = parse(SAMPLES / "secret.xor-stream.encx")
    _, _, px2, m2 = parse(SAMPLES / "secret.xor-stream.encx.2")
    x = bytes(a ^ b for a, b in zip(px1, px2))
    print(f"  xor-stream    同口令两文件 C⊕C' 熵={shannon_entropy(x):.4f}  盐复用={m1 == m2}")
    # 已知明文恢复密钥流（xor-stream 单文件内）
    ks = bytes(a ^ b for a, b in zip(px1, PLAIN))
    ks2 = bytes(a ^ b for a, b in zip(px2, PLAIN))
    print(f"  xor-stream    已知明文恢复 KS1==KS2（跨文件复用）={ks == ks2}  KS 熵={shannon_entropy(ks):.4f}")

    print()
    print("=" * 78)
    print("D) 混合加密元数据检查（wrapped CEK / 临时公钥是否每次不同）")
    for pid in ("rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"):
        _, _, _, m1 = parse(SAMPLES / f"secret.{pid}.encx")
        _, _, _, m2 = parse(SAMPLES / f"big3m.{pid}.encx")
        print(f"  {pid}: 元数据(len={len(m1)}/{len(m2)}) 两次加密完全不同={m1[:40] != m2[:40]}")

    print()
    print("结论: 见报告 A1 节。")


if __name__ == "__main__":
    main()
