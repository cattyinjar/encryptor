"""GUI 冒烟测试：构建界面，通过内部状态变量驱动一次完整加解密任务。

不模拟鼠标点击，但覆盖 GUI -> 后台线程 -> 事件队列 -> 界面刷新 的完整链路。

运行::

    python tests/test_gui_smoke.py
"""

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tkinter as tk

from encryptor import ENC_EXTENSION
from encryptor.app import EncryptorApp


def wait_job(app: tk.Tk, timeout: float = 60.0) -> str:
    """泵事件循环直到任务结束，返回最后一条日志文本。"""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        app.root.update()
        if not app._busy:
            break
        time.sleep(0.02)
    app.root.update()
    return app.log_text.get("end-2c linestart", "end-1c").strip()


def main() -> int:
    failures = []

    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if not cond and detail else ""))
        if not cond:
            failures.append(name)

    root = tk.Tk()
    root.withdraw()  # 冒烟测试不显示窗口
    app = EncryptorApp(root)

    tmp = Path(tempfile.mkdtemp(prefix="encx_gui_"))
    src = tmp / "样本 文件.dat"
    src.write_bytes(b"GUI smoke test payload \x00\x01\x02" * 10000)

    try:
        # 初始状态
        check("两个算法插件出现在下拉框", len(app.enc_plugin_combo["values"]) == 2,
              str(app.enc_plugin_combo["values"]))
        check("默认选中第一个算法", bool(app.enc_plugin_var.get()))
        check("插件页表格有记录", len(app.plugin_tree.get_children()) == 2)

        # ---- 加密（经 GUI 状态驱动） ----
        app.enc_src_var.set(str(src))
        app.enc_dst_var.set(str(src) + ENC_EXTENSION)
        app.enc_pwd_var.set("gui-pw-123")
        app.enc_pwd2_var.set("gui-pw-123")
        app._start_job(encrypt=True)
        last = wait_job(app)
        enc_path = Path(str(src) + ENC_EXTENSION)
        check("加密任务完成", enc_path.is_file(), last)
        check("日志含完成信息", "加密完成" in last, last)

        # ---- 解密（自动识别插件路径） ----
        app.dec_src_var.set(str(enc_path))
        # 模拟 _pick_decrypt_source 的识别逻辑（不经文件对话框）
        from encryptor import engine as eng
        pid = eng.peek_plugin_id(enc_path)
        check("解密页可自动识别算法", pid == "aes-256-gcm", str(pid))
        for item in app.registry.loaded:
            if item.id == pid:
                app.dec_plugin_var.set(item.display_name)
        app.dec_dst_var.set(str(enc_path) + ".out")
        app.dec_pwd_var.set("gui-pw-123")
        app._start_job(encrypt=False)
        last = wait_job(app)
        dec_path = Path(str(enc_path) + ".out")
        check("解密任务完成", dec_path.is_file(), last)
        check("解密内容与原文一致", dec_path.read_bytes() == src.read_bytes())

        # ---- 错误密码场景 ----
        dec_bad = tmp / "bad.out"
        app.dec_src_var.set(str(enc_path))
        app.dec_dst_var.set(str(dec_bad))
        app.dec_pwd_var.set("wrong-password")
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("错误密码在 GUI 中报错", "密码错误" in last, last)
        check("错误密码不产生输出", not dec_bad.exists() and not Path(str(dec_bad) + '.part').exists())

        # ---- 刷新插件 ----
        app.reload_plugins()
        check("刷新后插件数量不变", len(app.registry.loaded) == 2)

        print(f"\nGUI 冒烟: {'全部通过' if not failures else '失败 ' + str(failures)}")
        return 1 if failures else 0
    finally:
        root.destroy()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
