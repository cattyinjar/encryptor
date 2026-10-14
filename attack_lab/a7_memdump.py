"""内存镜像 + 全局密钥搜索攻击（取证式，表示形式完备版）。

对每个场景（全部插件 / 单插件）分别：
  受害者子进程跑真实 加密+解密 → 空闲存活
  → 外部 MiniDumpWithFullMemory 全内存镜像（受害者零扰动）
  → 离线搜索密钥材料的**所有可能内存表示**：
      raw 大端字节 / OpenSSL BIGNUM 小端 limb / 十六进制 ASCII 字符串 /
      大写十六进制 / UTF-8 口令 / 明文对照组
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gmssl import sm2 as gm_sm2

from lab import parse, get

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WORK = HERE / "artifacts_memdump"
PASSWORD = "MemDump-Attack-2026-口令Xy9#qL7z"
HKDF_INFO = b"encryptor/ecdh-aes256gcm/kek"


# ---------------------------------------------------------------- 转储

def dump_process(pid: int, out: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    # 句柄是 64 位指针：必须显式声明 restype，否则被截断成 c_int
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD,
                                     ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    PROCESS_ALL_ACCESS = 0x1F0FFF
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise OSError("OpenProcess失败", ctypes.get_last_error())
    hfile = kernel32.CreateFileW(str(out), 0x40000000, 0, None, 2, 0x80, None)
    if not hfile or hfile == 0xFFFFFFFFFFFFFFFF:
        e = ctypes.get_last_error()
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise OSError("CreateFileW失败", e)
    # 2 = MiniDumpWithFullMemory（procdump -ma 同款）
    ok = dbghelp.MiniDumpWriteDump(
        ctypes.c_void_p(handle), ctypes.c_uint32(pid), ctypes.c_void_p(hfile),
        ctypes.c_uint32(2), None, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(ctypes.c_void_p(hfile))
    kernel32.CloseHandle(ctypes.c_void_p(handle))
    if not ok:
        raise OSError("MiniDumpWriteDump失败", err)


def scan_dump(dmp: Path, needles: dict[str, bytes]) -> dict[str, list[int]]:
    maxn = max(len(v) for v in needles.values()) if needles else 1
    hits: dict[str, list[int]] = {k: [] for k in needles}
    CH = 1 << 22
    with open(dmp, "rb") as f:
        off, prev_tail = 0, b""
        while True:
            blk = f.read(CH)
            if not blk:
                break
            data = prev_tail + blk
            base = off - len(prev_tail)
            for name, nd in needles.items():
                start = 0
                while True:
                    i = data.find(nd, start)
                    if i < 0:
                        break
                    hits[name].append(base + i)
                    start = i + 1
            prev_tail = data[-(maxn - 1):] if len(data) >= maxn - 1 else data
            off += len(blk)
    return hits


# ---------------------------------------------------------------- 搜索针

def be(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


def build_needles(work: Path) -> dict[str, bytes]:
    """按 work 目录中实际存在的工件构造全表示搜索针。"""
    keys = WORK / "keys"
    n: dict[str, bytes] = {}

    n["口令 UTF-8"] = PASSWORD.encode("utf-8")
    n["[对照] 明文"] = b"MEMORY-DUMP-ATTACK-CONTROL-PLAINTEXT"

    def add_key(name: str, raw: bytes, hexable: bool = True):
        n[f"{name}·raw大端"] = raw
        n[f"{name}·BN小端limb"] = raw[::-1] if len(raw) % 8 == 0 else raw[::-1]
        if hexable and len(raw) in (16, 32):
            n[f"{name}·hex串"] = raw.hex().encode("ascii")
            n[f"{name}·HEX串"] = raw.hex().upper().encode("ascii")

    # 密码模式派生密钥
    if (work / "aes.encx").exists():
        _, _, _, meta = parse(work / "aes.encx")
        k = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), meta[:16], 200_000, dklen=32)
        add_key("AES派生密钥", k)
    if (work / "sm4.encx").exists():
        _, _, _, meta = parse(work / "sm4.encx")
        k = PBKDF2HMAC(algorithm=hashes.SM3(), length=16, salt=meta[:16],
                       iterations=200_000).derive(PASSWORD.encode())
        add_key("SM4派生密钥", k)
    if (work / "xor.encx").exists():
        _, _, _, meta = parse(work / "xor.encx")
        k = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), meta, 150_000, dklen=32)
        add_key("XOR派生密钥", k)
        n["XOR密钥流首块·raw"] = hashlib.sha256(k + meta + (0).to_bytes(8, "big")).digest()

    # RSA
    if (work / "rsa.encx").exists():
        priv = serialization.load_pem_private_key(
            (keys / "rsa_private_key.pem").read_bytes(), password=None)
        nums = priv.private_numbers()
        for label, val in (("RSA私钥d", nums.d), ("RSA素数p", nums.p),
                           ("RSA素数q", nums.q)):
            ln = (val.bit_length() + 7) // 8
            n[f"{label}·raw大端48B"] = be(val, ln)[:48]
            n[f"{label}·BN小端limb"] = be(val, ln + (-ln % 8))[:48][::-1]
            n[f"{label}·hex串"] = (be(val, ln).hex())[:64].encode("ascii")
        _, _, _, meta = parse(work / "rsa.encx")
        wrap_len = int.from_bytes(meta[:2], "big")
        wrapped = meta[2 : 2 + wrap_len]
        oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None)
        add_key("RSA场景CEK", priv.decrypt(wrapped, oaep))
        n["[对照] wrappedCEK"] = wrapped[:24]

    # ECDH
    if (work / "ecdh.encx").exists():
        priv = serialization.load_pem_private_key(
            (keys / "ecc_private_key.pem").read_bytes(), password=None)
        v = priv.private_numbers().private_value
        n["ECC私钥标量·raw大端"] = be(v, 32)
        n["ECC私钥标量·BN小端"] = be(v, 32)[::-1]
        n["ECC私钥标量·hex串"] = f"{v:064x}".encode("ascii")
        _, _, _, meta = parse(work / "ecdh.encx")
        eph_len = int.from_bytes(meta[:2], "big")
        eph = meta[2 : 2 + eph_len]
        off = 2 + eph_len
        wn, we = meta[off : off + 12], meta[off + 12 : off + 12 + 48]
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph)
        shared = priv.exchange(ec.ECDH(), eph_pub)
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph, info=HKDF_INFO).derive(shared)
        add_key("ECDH共享秘密", shared)
        add_key("ECDH场景KEK", kek)
        add_key("ECDH场景CEK", AESGCM(kek).decrypt(wn, we, None))

    # SM2
    if (work / "sm2.encx").exists():
        sm2_hex = base64.b64decode("".join(
            (keys / "sm2_private_key.pem").read_text()
            .split("-----BEGIN SM2 PRIVATE KEY-----")[1]
            .split("-----END SM2 PRIVATE KEY-----")[0].split())).hex()
        add_key("SM2私钥", bytes.fromhex(sm2_hex))
        _, _, _, meta = parse(work / "sm2.encx")
        ct_len = int.from_bytes(meta[:2], "big")
        wrapped = meta[2 : 2 + ct_len]
        cek = gm_sm2.CryptSM2(public_key="", private_key=sm2_hex, mode=1, asn1=False).decrypt(wrapped)
        add_key("SM2场景CEK", cek)

    return n


# ---------------------------------------------------------------- 主流程

def run_mode(mode: str) -> dict[str, list[int]]:
    mdir = WORK / mode
    if mdir.exists():
        shutil.rmtree(mdir)
    mdir.mkdir()
    proc = subprocess.Popen([sys.executable, str(HERE / "a7_victim.py"), mode, str(mdir)],
                            cwd=str(HERE))
    t0 = time.time()
    while not (mdir / "READY").exists():
        if proc.poll() is not None:
            raise RuntimeError(f"[{mode}] 受害者提前退出 code={proc.returncode}")
        if time.time() - t0 > 300:
            proc.kill()
            raise TimeoutError(mode)
        time.sleep(0.3)
    dmp = mdir / "victim.dmp"
    dump_process(proc.pid, dmp)
    (mdir / "EXIT").write_text("1")
    proc.wait(timeout=30)
    needles = build_needles(mdir)
    hits = scan_dump(dmp, needles)
    size = dmp.stat().st_size / 1048576
    dmp.unlink()
    print(f"  [{mode}] 镜像 {size:.0f} MiB，搜索针 {len(needles)} 个")
    for name, offs in hits.items():
        if offs:
            print(f"      命中 {name:<24} ×{len(offs)}  首偏移 +0x{offs[0]:X}")
    ctl = hits.get("[对照] 明文")
    if not ctl:
        print(f"      ⚠ 明文对照组未命中——该镜像不可信，结果作废！")
    return hits


def main() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()
    (WORK / "keys").mkdir()
    for pid in ("rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"):
        get(pid).generate_keypair(WORK / "keys")

    print("=" * 78)
    print("内存镜像 + 全局密钥搜索（每场景独立受害者进程与镜像）")
    all_hits: dict[str, dict] = {}
    for mode in ("aes", "sm4", "xor", "rsa", "ecdh", "sm2", "all"):
        all_hits[mode] = run_mode(mode)

    print()
    print("=" * 78)
    print("汇总（命中 = 该密钥材料以某种内存表示物理残留于'使用后'镜像）")
    print(f"  {'场景':<6} {'口令':<4} {'对称派生密钥':<12} {'CEK':<4} {'私钥材料':<10} {'共享秘密/KEK':<12}")
    for mode, h in all_hits.items():
        pw = "残留" if h.get("口令 UTF-8") else "-"
        dk = [k for k in h if "派生密钥" in k or "密钥流" in k and h[k]]
        ck = [k for k in h if "CEK" in k and "对照" not in k and h[k]]
        pk = [k for k in h if ("私钥" in k or "素数" in k) and h[k]]
        sk = [k for k in h if ("共享秘密" in k or "KEK" in k) and h[k]]
        print(f"  {mode:<6} {pw:<4} {len(dk):<12} {len(ck):<4} {len(pk):<10} {len(sk):<12}")
        for grp, lst in (("派生密钥", dk), ("CEK", ck), ("私钥", pk), ("共享/KEK", sk)):
            for k in lst:
                print(f"        - {k} ×{len(h[k])}")


if __name__ == "__main__":
    main()
