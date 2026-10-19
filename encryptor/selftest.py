"""打包后自检（``Encryptor.exe --selftest``）。

在没有控制台的 windowed 可执行文件上，通过**进程退出码**报告结果
（0 = 全部通过），细节写入日志文件（exe 同目录 selftest.log）与 stderr。
覆盖打包最易断的两点：插件能否被发现加载、multiprocessing 子进程任务
（jobrunner）在冻结模式下能否正常 spawn——后者是 PyInstaller 打包的
经典雷区，必须在 freeze_support 就位后实测。
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

RESULTS: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def run_selftest() -> int:
    log_path = Path(sys.executable).resolve().parent / "selftest.log" \
        if getattr(sys, "frozen", False) else Path("selftest.log")

    def _tee(msg: str) -> None:
        print(msg, file=sys.stderr)
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass

    try:
        log_path.unlink(missing_ok=True)
    except OSError:
        pass

    started = time.strftime("%Y-%m-%d %H:%M:%S")
    _tee(f"== Encryptor 自检 {started} ==")

    # 1) 插件发现与加载（exe 同目录的 plugins/）
    from encryptor import plugin_manager

    registry = plugin_manager.scan_plugins()
    loaded_ids = sorted(i.id for i in registry.loaded)
    _tee(f"插件目录：{plugin_manager.default_plugins_dir()}")
    _tee(f"已加载插件（{len(loaded_ids)}）：{loaded_ids}")
    if registry.failed:
        _tee(f"加载失败：{[(f.source.name, f.reason) for f in registry.failed]}")
    _check("插件全部加载（7 个）", len(loaded_ids) == 7 and not registry.failed)

    aes = registry.find("aes-256-gcm")
    if aes is None:
        _tee("== 自检结束：aes-256-gcm 不可用，中止 ==")
        return 1
    _check("aes-256-gcm 可用", True)

    # 2) 引擎进程内往返
    from encryptor import engine

    tmp = Path(tempfile.mkdtemp(prefix="encx_selftest_"))
    src = tmp / "selftest.bin"
    src.write_bytes(b"Encryptor frozen selftest payload \x00\x01\x02" * 512)
    enc, dec = tmp / "s.encx", tmp / "s.out"
    engine.encrypt_file(aes, src, enc, "selftest-password-1")
    engine.decrypt_file(aes, enc, dec, "selftest-password-1")
    _check("引擎进程内往返", dec.read_bytes() == src.read_bytes())

    # 3) jobrunner 子进程任务（冻结模式 spawn 的关键验证）
    from encryptor import jobrunner

    spec = {
        "kind": "crypto", "encrypt": True, "plugin_id": "aes-256-gcm",
        "src": str(src), "dst": str(enc), "password": "selftest-password-1",
        "passphrase": None, "credential": None, "total": src.stat().st_size,
    }
    ok, message = jobrunner.run_in_subprocess(spec, on_event=lambda ev: None)
    _check("jobrunner 子进程加密", ok, message)
    spec2 = dict(spec, encrypt=False, src=str(enc), dst=str(dec))
    ok2, message2 = jobrunner.run_in_subprocess(spec2, on_event=lambda ev: None)
    _check("jobrunner 子进程解密", ok2 and dec.read_bytes() == src.read_bytes(), message2)

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(RESULTS)
    _tee(f"== 自检结束：{passed}/{len(RESULTS)} 通过 ==")
    return 0 if all(RESULTS) else 1
