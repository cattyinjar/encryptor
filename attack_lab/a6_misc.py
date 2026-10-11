"""攻击6：容器模糊测试 / .part 残留 / 进程内存残留 / SM2 时序旁路。"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import statistics
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor.sdk import CancelledError, PluginError, WrongPasswordError

from lab import KEYS, SAMPLES, build_encx, dec, enc, get, parse

PASSWORD = "S3cret-P@ss2026!"
ART = Path(__file__).resolve().parent / "artifacts_misc"


def fuzz_container() -> None:
    good = (SAMPLES / "secret.aes-256-gcm.encx").read_bytes()
    cases = {
        "空文件": b"",
        "只有魔数": b"ENCX",
        "错误魔数": b"XXXX" + good[4:],
        "版本号=2": good[:4] + b"\x02" + good[5:],
        "pid_len=0": good[:5] + b"\x00\x00" + good[7:],
        "pid_len=257": good[:5] + b"\x01\x01" + good[7:],
        "pid_len=65535": good[:5] + b"\xff\xff" + good[7:],
        "尾部截断 4B": good[:-4],
        "meta_len=0xFFFFFFFF": good[:-4] + b"\xff\xff\xff\xff",
        "meta_len 巨大但合法字段": good[:-4] + (10**9).to_bytes(4, "little"),
        "插件id=不存在": good[:7] + b"no-such-plugin" + good[7 + len(b"aes-256-gcm"):],
        "插件id=路径穿越尝试": good[:7] + b"..%2f..%2fevil" + good[7 + len(b"aes-256-gcm"):],
        "随机字节 1KB": __import__("os").urandom(1024),
    }
    for name, blob in cases.items():
        f = ART / "fuzz.encx"
        f.write_bytes(blob)
        try:
            dec(f, ART / "fuzz.out", PASSWORD)
            r = "成功(!)"
        except Exception as e:
            r = f"{type(e).__name__}: {str(e)[:40]}"
        (ART / "fuzz.out").unlink(missing_ok=True)
        print(f"  {name:<22} → {r}")


def part_residue() -> None:
    print()
    print("=" * 78)
    print("B) .part 临时文件残留（错误口令 / 取消 / 正常完成 三路径）")
    dst = ART / "part.encx"
    # 错误口令解密
    try:
        dec(SAMPLES / "secret.aes-256-gcm.encx", dst, "wrong-password", plugin_id="aes-256-gcm")
    except Exception:
        pass
    print(f"  错误口令后 .part 残留 = {(ART / 'part.encx.part').exists()}")
    # 取消：用大文件 + 立即取消
    cancel = threading.Event()

    def prog(n):
        if n > 0:
            cancel.set()

    from encryptor import engine
    dst2 = ART / "part2.encx"
    try:
        engine.decrypt_file(get("aes-256-gcm"), SAMPLES / "big3m.aes-256-gcm.encx",
                            dst2, PASSWORD, on_progress=prog, cancel=cancel)
    except CancelledError:
        pass
    print(f"  中途取消后 .part 残留 = {(ART / 'part2.encx.part').exists()}"
          f"  输出文件残留 = {dst2.exists()}")


def memory_residue() -> None:
    print()
    print("=" * 78)
    print("C) 进程内存残留：任务完成后搜索口令/CEK 字节（Windows 虚存扫描）")

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetCurrentProcess()

    def scan(needle: bytes) -> int:
        hits = 0
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        readable = 0x02 | 0x04 | 0x20 | 0x40  # R, RW, RX, RWX
        while addr < 0x7FFFFFFFFFFF:
            if ctypes.windll.kernel32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            if mbi.State == 0x1000 and (mbi.Protect & 0xFF) & readable and mbi.Protect not in (0x01, 0x100):  # commit & 可读 & 非guard/noaccess
                size = mbi.RegionSize
                buf = ctypes.create_string_buffer(size)
                if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, None):
                    data = buf.raw
                    if needle in data:
                        hits += 1
            addr += mbi.RegionSize
        return hits

    # 一次真实加密，然后扫描口令的 UTF-8 与 CEK
    marker_pw = "M3m0ry-Residue-Test-口令!".encode()
    src = ART / "mem_plain.bin"
    src.write_bytes(b"A" * 4096)
    enc(src, ART / "mem.encx", marker_pw.decode(), "aes-256-gcm")
    import gc
    gc.collect()
    pw_hits = scan(marker_pw)
    print(f"  加密返回+gc 后，口令字节仍出现在进程内存: {pw_hits} 个区域 (≠0 即为残留)")
    # CEK 只有 32B 随机，无已知值可比——用口令字节即可证明 Python 堆不清零问题


def sm2_timing() -> None:
    print()
    print("=" * 78)
    print("D) SM2 解密时序旁路：纯 Python _kg 的耗时依赖 d 的汉明重量")
    import base64
    from gmssl import sm2 as gm_sm2

    def make_keyfile(d_int: int) -> Path:
        f = ART / f"key_{d_int % 100}.pem"
        f.write_text("-----BEGIN SM2 PRIVATE KEY-----\n"
                     + base64.b64encode(d_int.to_bytes(32, "big")).decode()
                     + "\n-----END SM2 PRIVATE KEY-----\n")
        return f

    # 稀疏 d（popcount=1）与稠密 d
    sparse = 1 << 250
    dense = (1 << 253) - 1
    ks, kd = make_keyfile(sparse), make_keyfile(dense)

    pub_sparse = gm_sm2.CryptSM2(public_key="", private_key=f"{sparse:064x}", mode=1, asn1=False)._kg(
        sparse, gm_sm2.CryptSM2(public_key="", private_key="", mode=1, asn1=False).ecc_table["g"])

    # 构造合法密文：用稀疏公钥加密 16B CEK
    enc_crypt = gm_sm2.CryptSM2(public_key=pub_sparse, private_key="", mode=1, asn1=False)
    wrapped = enc_crypt.encrypt(b"T" * 16)
    cek_check = __import__("hashlib") if False else None

    from gmssl.sm3 import sm3_hash as gm_sm3_hash
    meta = (len(wrapped).to_bytes(2, "big") + wrapped
            + bytes.fromhex(gm_sm3_hash([i for i in b"T" * 16])) + b"\x00" * 8
            + (0).to_bytes(8, "big"))
    f = ART / "timing.encx"
    f.write_bytes(build_encx("sm2-sm4-gcm", b"", meta))

    plugin = get("sm2-sm4-gcm")
    def time_decrypt(keyfile: Path) -> float:
        t0 = time.perf_counter()
        try:
            plugin.decrypt_stream(meta, open(f, "rb"), open(ART / "t.out", "wb"),
                                  str(keyfile), lambda n: None)
        except Exception:
            pass
        return time.perf_counter() - t0

    ts = sorted(time_decrypt(ks) for _ in range(60))
    td = sorted(time_decrypt(kd) for _ in range(60))
    print(f"  稀疏 d (popcount=1):  中位 {statistics.median(ts)*1000:.2f} ms")
    print(f"  稠密 d (popcount=253): 中位 {statistics.median(td)*1000:.2f} ms")
    print(f"  比值 = {statistics.median(td)/statistics.median(ts):.2f}  （>1 即时序依赖密钥位型）")


def main() -> None:
    ART.mkdir(exist_ok=True)
    print("=" * 78)
    print("A) 容器模糊测试")
    fuzz_container()
    part_residue()
    memory_residue()
    sm2_timing()


if __name__ == "__main__":
    main()
