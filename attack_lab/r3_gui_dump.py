"""F7 修复验证：GUI 父进程任务后全内存镜像 + 全表示密钥搜索。

同时验证"任务执行中"的子进程残余窗口（文档承认的边界）：
  1. GUI 跑完 aes/xor/rsa/ecdh/sm2 全部加解密 → 空闲存活 → dump 父进程
  2. 搜索：口令(UTF-8/UTF-16)、派生密钥、MAC 密钥、CEK、私钥大数、明文对照
  3.（补充）任务执行中枚举子进程并 dump —— 预期能抓到密钥（残余窗口实证）
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

from a7_memdump import dump_process, scan_dump
from lab import get, parse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WORK = HERE / "artifacts_gui"
PASSWORD = "MemDump-GUI-2026-口令Wq8#zL2m"
HKDF_INFO = b"encryptor/ecdh-aes256gcm/kek"


def child_pids(parent_pid: int) -> list[int]:
    """CreateToolhelp32Snapshot 枚举 parent_pid 的 python.exe 子进程。"""
    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    out = []
    if k32.Process32FirstW(snap, ctypes.byref(e)):
        while True:
            if (e.th32ParentProcessID == parent_pid
                    and e.szExeFile.lower().startswith(("python", "pythonw"))):
                out.append(e.th32ProcessID)
            if not k32.Process32NextW(snap, ctypes.byref(e)):
                break
    k32.CloseHandle(snap)
    return out


def build_needles() -> dict[str, bytes]:
    keys = WORK / "keys"
    n: dict[str, bytes] = {}
    n["口令 UTF-8"] = PASSWORD.encode("utf-8")
    n["口令 UTF-16LE"] = PASSWORD.encode("utf-16-le")
    n["[对照] 明文"] = b"GUI-MEMDUMP-CONTROL-PLAINTEXT"

    def add_key(name, raw):
        n[f"{name}·raw"] = raw
        if len(raw) in (16, 32, 48):
            n[f"{name}·hex"] = raw.hex().encode()
            n[f"{name}·LE"] = raw[::-1]

    # aes v2: salt=meta[6:22], iters=meta[2:6], dual key
    _, _, _, meta = parse(WORK / "aes-256-gcm.encx")
    iters = int.from_bytes(meta[2:6], "big")
    dk = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=meta[6:22],
                    iterations=iters).derive(PASSWORD.encode())
    add_key("AES加密密钥", dk[:32]); add_key("AES的MAC密钥", dk[32:])

    _, _, _, meta = parse(WORK / "xor-stream.encx")
    iters = int.from_bytes(meta[2:6], "big")
    dk = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=meta[6:22],
                    iterations=iters).derive(PASSWORD.encode())
    add_key("XOR流密钥", dk[:32]); add_key("XOR的MAC密钥", dk[32:])

    # RSA CEK + 私钥
    priv = serialization.load_pem_private_key((keys / "rsa_private_key.pem").read_bytes(), None)
    nums = priv.private_numbers()
    d = nums.d; ln = (d.bit_length() + 7) // 8
    n["RSA私钥d·BE48"] = d.to_bytes(ln, "big")[:48]
    n["RSA私钥d·LE"] = d.to_bytes(ln + (-ln % 8), "big")[:48][::-1]
    n["RSA私钥d·hex"] = d.to_bytes(ln, "big").hex()[:64].encode()
    _, _, _, meta = parse(WORK / "rsa-oaep-aes256gcm.encx")
    wl = int.from_bytes(meta[1:3], "big")   # v2: ver(1) + wraplen(2)? 由 rsa 插件布局决定
    # rsa v2 布局: ver || wraplen(2) || wrapped || nonce_prefix || total || MAC
    wrapped = meta[3 : 3 + wl]
    oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
    add_key("RSA场景CEK", priv.decrypt(wrapped, oaep))

    # ECC
    epriv = serialization.load_pem_private_key((keys / "ecc_private_key.pem").read_bytes(), None)
    v = epriv.private_numbers().private_value
    n["ECC私钥·BE"] = v.to_bytes(32, "big")
    n["ECC私钥·LE"] = v.to_bytes(32, "big")[::-1]
    n["ECC私钥·hex"] = f"{v:064x}".encode()
    _, _, _, meta = parse(WORK / "ecdh-aes256gcm.encx")
    el = int.from_bytes(meta[1:3], "big")
    eph = meta[3 : 3 + el]
    off = 3 + el
    wn, we = meta[off : off + 12], meta[off + 12 : off + 60]
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(epriv.curve, eph)
    shared = epriv.exchange(ec.ECDH(), eph_pub)
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph, info=HKDF_INFO).derive(shared)
    add_key("ECDH共享秘密", shared)
    add_key("ECDH场景CEK", AESGCM(kek).decrypt(wn, we, None))

    # SM2
    sm2_hex = base64.b64decode("".join(
        (keys / "sm2_private_key.pem").read_text()
        .split("-----BEGIN SM2 PRIVATE KEY-----")[1]
        .split("-----END SM2 PRIVATE KEY-----")[0].split())).hex()
    add_key("SM2私钥", bytes.fromhex(sm2_hex))
    _, _, _, meta = parse(WORK / "sm2-sm4-gcm.encx")
    wrapped = meta[1 : 1 + 112]
    sys.path.insert(0, str(ROOT))
    from plugins.sm2_hybrid.plugin import _sm2_decrypt
    cek = _sm2_decrypt(wrapped, int(sm2_hex, 16))
    add_key("SM2场景CEK", cek)
    return n


def main() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()
    (WORK / "keys").mkdir()
    for pid in ("rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"):
        d = WORK / "keys" / pid
        get(pid).generate_keypair(d)
        for f in d.iterdir():
            (WORK / "keys" / f.name).write_bytes(f.read_bytes())

    # ---------- 阶段 1：任务执行中 dump 子进程（残余窗口实证） ----------
    print("=" * 78)
    print("阶段1：任务执行中的子进程镜像（文档承认的残余窗口）")
    big = WORK / "big.bin"
    big.write_bytes(b"B" * (6 * 1024 * 1024))
    # 用一个小驱动进程跑 GUI 并触发大任务，随后我们抓子进程
    # （直接内联：启动 GUI 受害者脚本前，先手动做一次）
    # —— 简化：本阶段用引擎+jobrunner 直接跑一个长任务并 dump 其子进程
    import multiprocessing as mp
    from encryptor import jobrunner
    q_events = []
    import threading
    spec = {"kind": "crypto", "encrypt": True, "plugin_id": "aes-256-gcm",
            "src": str(big), "dst": str(WORK / "big.encx"),
            "password": PASSWORD, "passphrase": None, "credential": None,
            "total": big.stat().st_size}
    done = threading.Event()
    def runner():
        jobrunner.run_in_subprocess(spec, on_event=lambda ev: None)
        done.set()
    th = threading.Thread(target=runner, daemon=True)
    th.start()
    child = None
    for _ in range(100):
        time.sleep(0.05)
        cands = child_pids(0)  # 占位，下一行用真实父 pid
        # 找本进程的子进程
        me = ctypes.windll.kernel32.GetCurrentProcessId()
        kids = child_pids(me)
        pykids = [k for k in kids]
        if pykids:
            child = pykids[0]
            break
    if child:
        dmp = WORK / "child_midjob.dmp"
        dump_process(child, dmp)
        print(f"  已 dump 执行中子进程 pid={child}")
        done.wait(60)
        ndl = {"口令 UTF-8": PASSWORD.encode("utf-8"),
               "[对照]_不存在_随便搜": b"\x00NO_SUCH_NEEDLE\x00"}
        h = scan_dump(dmp, ndl)
        print(f"  子进程内口令命中: {len(h['口令 UTF-8'])} 处（预期>0：残余窗口）")
        dmp.unlink()
    else:
        print("  未捕获到子进程（任务太快），跳过")

    # ---------- 阶段 2：GUI 父进程任务后镜像 ----------
    print()
    print("=" * 78)
    print("阶段2：GUI 父进程（全部任务完成后空闲）全内存镜像")
    proc = subprocess.Popen([sys.executable, str(HERE / "r3_gui_victim.py"),
                             str(WORK), str(WORK / "keys")], cwd=str(HERE))
    t0 = time.time()
    while not (WORK / "READY").exists():
        if proc.poll() is not None:
            raise RuntimeError(f"GUI 受害者退出 code={proc.returncode}")
        if time.time() - t0 > 600:
            proc.kill(); raise TimeoutError
        time.sleep(0.5)
    print(f"  GUI pid={proc.pid} 全部任务完成，处于空闲")
    dmp = WORK / "gui_parent.dmp"
    dump_process(proc.pid, dmp)
    print(f"  父进程镜像 {dmp.stat().st_size / 1048576:.0f} MiB")
    (WORK / "EXIT").write_text("1")
    proc.wait(timeout=60)

    needles = build_needles()
    hits = scan_dump(dmp, needles)
    print()
    print(f"  搜索针 {len(needles)} 个，命中情况：")
    for name, offs in hits.items():
        mark = "←★" if offs and "对照" not in name else ""
        if offs:
            print(f"    命中 {name:<22} ×{len(offs)}  +0x{offs[0]:X} {mark}")
    if not hits.get("[对照] 明文"):
        print("    ⚠ 明文对照组未命中——镜像不可信！")
    keys_hit = [k for k, v in hits.items() if v and "对照" not in k and "口令" not in k]
    print()
    print(f"  ★ 密钥材料残留: {keys_hit if keys_hit else '无'}")
    print(f"  ★ 口令残留: {sum(len(v) for k, v in hits.items() if '口令' in k)} 处")
    dmp.unlink()


if __name__ == "__main__":
    main()
