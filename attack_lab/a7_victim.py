"""内存镜像攻击 · 受害者进程。

用法: python a7_victim.py <mode> <workdir>
mode ∈ all|aes|sm4|xor|rsa|ecdh|sm2 —— 决定运行哪个（组）插件的任务。
用真实引擎完成 加密+解密 后保持进程存活（模拟"软件用完还开着"），
等待外部转储，然后退出。
"""

from __future__ import annotations

import gc
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from encryptor import engine, plugin_manager

PASSWORD = "MemDump-Attack-2026-口令Xy9#qL7z"

PLUGINS = {
    "aes": "aes-256-gcm", "sm4": "sm4-gcm", "xor": "xor-stream",
    "rsa": "rsa-oaep-aes256gcm", "ecdh": "ecdh-aes256gcm", "sm2": "sm2-sm4-gcm",
}
KEYFILE = {
    "rsa": ("rsa_public_key.pem", "rsa_private_key.pem"),
    "ecdh": ("ecc_public_key.pem", "ecc_private_key.pem"),
    "sm2": ("sm2_public_key.pem", "sm2_private_key.pem"),
}


def main() -> None:
    mode, work = sys.argv[1], Path(sys.argv[2])
    reg = plugin_manager.scan_plugins()

    plain = work / "plain.txt"
    plain.write_bytes(b"MEMORY-DUMP-ATTACK-CONTROL-PLAINTEXT " + os.urandom(8192))

    modes = list(PLUGINS) if mode == "all" else [mode]

    def job():
        for m in modes:
            pid = PLUGINS[m]
            plugin = reg.find(pid)
            encx = work / f"{m}.encx"
            out = work / f"{m}.out"
            if m in KEYFILE:
                keys = work.parent / "keys"
                pub, priv = KEYFILE[m]
                engine.encrypt_file(plugin, plain, encx, str(keys / pub))
                engine.decrypt_file(plugin, encx, out, str(keys / priv))
            else:
                engine.encrypt_file(plugin, plain, encx, PASSWORD)
                engine.decrypt_file(plugin, encx, out, PASSWORD)

    job()
    gc.collect()
    (work / "READY").write_text("1")
    while not (work / "EXIT").exists():
        time.sleep(0.2)


if __name__ == "__main__":
    main()
