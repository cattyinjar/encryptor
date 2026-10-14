"""F7 修复验证 · GUI 受害者进程。

真实 GUI（EncryptorApp）跑完全部场景的 加密+解密 任务（经 jobrunner 子进程），
然后保持存活等待外部镜像。测试内存：父进程是否残留密钥材料。
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tkinter as tk

from encryptor.app import EncryptorApp

PASSWORD = "MemDump-GUI-2026-口令Wq8#zL2m"
WORK = Path(sys.argv[1])
KEYS = Path(sys.argv[2])


def wait_job(app, timeout: float = 180.0) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        app.root.update()
        if not app._busy:
            break
        time.sleep(0.02)
    app.root.update()
    return app.log_text.get("end-2c linestart", "end-1c").strip()


def run_job(app, encrypt: bool, plugin_display: str, src: Path, dst: Path, cred: str,
            confirm: str = "", passphrase: str = ""):
    if encrypt:
        app.enc_plugin_var.set(plugin_display)
        app._on_plugin_selected(encrypt=True)
        app.enc_src_var.set(str(src))
        app.enc_dst_var.set(str(dst))
        app.enc_pwd_var.set(cred)
        app.enc_pwd2_var.set(confirm)
        app._start_job(encrypt=True)
    else:
        app.dec_plugin_var.set(plugin_display)
        app._on_plugin_selected(encrypt=False)
        app.dec_src_var.set(str(src))
        app.dec_dst_var.set(str(dst))
        app.dec_pwd_var.set(cred)
        if passphrase:
            app.dec_keypwd_var.set(passphrase)
        app._start_job(encrypt=False)
    return wait_job(app)


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    app = EncryptorApp(root)

    plain = WORK / "plain.txt"
    plain.write_bytes(b"GUI-MEMDUMP-CONTROL-PLAINTEXT " + b"G" * 8192)

    names = {i.display_name: i.id for i in app.registry.loaded}
    id2name = {v: k for k, v in names.items()}

    # 密码模式：aes / xor
    for pid in ("aes-256-gcm", "xor-stream"):
        run_job(app, True, id2name[pid], plain, WORK / f"{pid}.encx", PASSWORD, PASSWORD)
        run_job(app, False, id2name[pid], WORK / f"{pid}.encx", WORK / f"{pid}.out", PASSWORD)
    # 混合模式：rsa / ecdh / sm2
    keyfile = {
        "rsa-oaep-aes256gcm": ("rsa_public_key.pem", "rsa_private_key.pem"),
        "ecdh-aes256gcm": ("ecc_public_key.pem", "ecc_private_key.pem"),
        "sm2-sm4-gcm": ("sm2_public_key.pem", "sm2_private_key.pem"),
    }
    for pid, (pub, priv) in keyfile.items():
        run_job(app, True, id2name[pid], plain, WORK / f"{pid}.encx", str(KEYS / pub))
        run_job(app, False, id2name[pid], WORK / f"{pid}.encx", WORK / f"{pid}.out", str(KEYS / priv))

    (WORK / "READY").write_text("1")
    while not (WORK / "EXIT").exists():
        root.update()
        time.sleep(0.1)
    root.destroy()


if __name__ == "__main__":
    main()
