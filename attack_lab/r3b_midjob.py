"""任务执行中子进程的残余窗口验证：dump 正在解密的 jobrunner worker。

不枚举子进程（会误抓 mp 的临时子进程），而是本脚本自建 spawn 子进程
（与 jobrunner.run_in_subprocess 相同的调用方式），直接持有 proc.pid。
"""

from __future__ import annotations

import ctypes
import multiprocessing as mp
import queue as queue_mod
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from a7_memdump import dump_process, scan_dump
from encryptor.jobrunner import _child_job
from lab import parse

WORK = HERE / "artifacts_gui"
PASSWORD = "S3cret-P@ss2026!"


def run_spec_with_pid(spec) -> tuple[int, "mp.Queue"]:
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    proc = ctx.Process(target=_child_job, args=(q, spec), daemon=True)
    proc.start()
    return proc, q


def main() -> None:
    from encryptor import engine
    from lab import get

    if not (WORK / "big500.encx").exists():
        big = WORK / "big500.bin"
        big.write_bytes(b"\x00" * (500 * 1024 * 1024))
        engine.encrypt_file(get("aes-256-gcm"), big, WORK / "big500.encx", PASSWORD)
        big.unlink()

    _, _, _, meta = parse(WORK / "big500.encx")
    iters = int.from_bytes(meta[2:6], "big")
    dk = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=meta[6:22],
                    iterations=iters).derive(PASSWORD.encode())

    spec = {"kind": "crypto", "encrypt": False, "plugin_id": "aes-256-gcm",
            "src": str(WORK / "big500.encx"), "dst": str(WORK / "mid.out"),
            "password": PASSWORD, "passphrase": None, "credential": None,
            "total": 500 * 1024 * 1024}
    proc, q = run_spec_with_pid(spec)
    print(f"worker pid = {proc.pid}")

    # 等 worker 完成导入与 spec 反序列化（约 1.5s），再快速重试 dump
    dmp = WORK / "midjob.dmp"
    dumped = False
    time.sleep(1.6)
    t0 = time.time()
    while time.time() - t0 < 15:
        if not proc.is_alive():
            break
        try:
            dump_process(proc.pid, dmp)
            dumped = True
            break
        except OSError:
            time.sleep(0.05)
    if not dumped:
        print("未能 dump 存活期 worker")
        return
    print(f"已 dump 执行中的 worker（出生后 {time.time() - t0 + 1.6:.1f}s）")

    # 等任务结束
    while True:
        try:
            ev = q.get(timeout=0.3)
        except queue_mod.Empty:
            if not proc.is_alive():
                break
            continue
        if ev[0] == "done":
            print(f"任务结果: ok={ev[1]} {ev[2][:40]}")
            break
    proc.join(10)

    h = scan_dump(dmp, {
        "AES加密密钥·raw": dk[:32],
        "AES的MAC密钥·raw": dk[32:],
        "口令 UTF-8": PASSWORD.encode(),
    })
    print("子进程执行中镜像搜索结果:")
    print(f"  AES加密密钥 ×{len(h['AES加密密钥·raw'])}")
    print(f"  AES的MAC密钥 ×{len(h['AES的MAC密钥·raw'])}")
    print(f"  口令         ×{len(h['口令 UTF-8'])}")
    dmp.unlink()


if __name__ == "__main__":
    main()
