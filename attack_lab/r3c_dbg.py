"""诊断：为何对存活的 mp 子进程 OpenProcess 返回 87。"""

import ctypes
import ctypes.wintypes as wt
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from encryptor import jobrunner
from r3_gui_dump import child_pids

WORK = HERE / "artifacts_gui"
PASSWORD = "S3cret-P@ss2026!"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]


def alive(pid):
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    k32.CloseHandle(ctypes.c_void_p(h))
    return True


def main():
    spec = {"kind": "crypto", "encrypt": False, "plugin_id": "aes-256-gcm",
            "src": str(WORK / "big100.encx"), "dst": str(WORK / "mid.out"),
            "password": PASSWORD, "passphrase": None, "credential": None,
            "total": 100 * 1024 * 1024}
    done = threading.Event()
    threading.Thread(target=lambda: (jobrunner.run_in_subprocess(spec, on_event=lambda e: None), done.set()), daemon=True).start()
    me = ctypes.windll.kernel32.GetCurrentProcessId()
    t0 = time.time()
    child = None
    while time.time() - t0 < 30:
        kids = child_pids(me)
        if kids:
            child = kids[-1]
            print(f"捕获 pid={child}（kids={kids}）")
            break
        time.sleep(0.15)
    for i in range(60):
        a = alive(child)
        h_all = k32.OpenProcess(0x1F0FFF, False, child)
        h_vm = k32.OpenProcess(0x0410, False, child)  # VM_READ|QUERY_INFORMATION
        k32.CloseHandle(ctypes.c_void_p(h_all)) if h_all else None
        k32.CloseHandle(ctypes.c_void_p(h_vm)) if h_vm else None
        print(f"t+{time.time()-t0:4.1f}s alive(QUERY)={a} ALL_ACCESS={'0x%x' % h_all if h_all else 'FAIL(%d)' % ctypes.get_last_error()} VM_READ={'ok' if h_vm else 'FAIL(%d)' % ctypes.get_last_error()}")
        if i % 10 == 9 or not a:
            pass
        time.sleep(0.3)
        if not a:
            break
    done.wait(120)


if __name__ == "__main__":
    main()
