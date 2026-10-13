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
        check("七个算法插件出现在下拉框", len(app.enc_plugin_combo["values"]) == 7,
              str(app.enc_plugin_combo["values"]))
        check("默认选中第一个算法", bool(app.enc_plugin_var.get()))
        check("插件页表格有记录", len(app.plugin_tree.get_children()) == 7)

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
        check("日志报告敏感内存已清零", "敏感内存已清零" in last, last)

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

        # ---- 口令策略（审计 F4）----
        app.enc_plugin_var.set(app.enc_plugin_combo["values"][0])  # AES
        app._on_plugin_selected(encrypt=True)
        app.enc_src_var.set(str(src))
        out_short = tmp / "short_pw.encx"
        app.enc_dst_var.set(str(out_short))
        app.enc_pwd_var.set("abc123")
        app.enc_pwd2_var.set("abc123")
        app._start_job(encrypt=True)
        app.root.update()
        check("过短密码被策略拒绝",
              "至少" in app.log_text.get("1.0", "end") and not out_short.exists())
        app.enc_pwd_var.set("12345678")
        app.enc_pwd2_var.set("12345678")
        app._start_job(encrypt=True)
        app.root.update()
        check("常见弱口令被策略拒绝",
              "弱口令" in app.log_text.get("1.0", "end") and not out_short.exists())

        # ---- 刷新插件 ----
        app.reload_plugins()
        check("刷新后插件数量不变", len(app.registry.loaded) == 7)

        # ---- 密钥文件插件（RSA）GUI 流程 ----
        print("  -- RSA 密钥文件模式 --")
        rsa_item = next(i for i in app.registry.loaded if i.id == "rsa-oaep-aes256gcm")
        app.enc_plugin_var.set(rsa_item.display_name)
        app._on_plugin_selected(encrypt=True)
        app.root.update()
        check("RSA 下凭据标签变为『公钥文件』", app.enc_pwd_label.cget("text") == "公钥文件")
        check("RSA 下输入框不掩码", app.enc_pwd_entry.cget("show") == "")
        check("RSA 下出现密钥选择按钮", app.enc_credential_browse.winfo_manager() == "grid")
        check("RSA 下确认密码行隐藏", app.enc_confirm_label.winfo_manager() == "")
        check("RSA 下显示生成密钥对按钮", app.enc_keygen_btn.winfo_manager() == "pack")
        check("RSA 下描述含密钥文件说明", "公钥文件" in app.enc_desc_label.cget("text"))

        keys_dir = tmp / "keys"
        rpub, rpriv = rsa_item.plugin.generate_keypair(keys_dir)
        enc_rsa = tmp / "样本 文件.dat.rsa.encx"
        app.enc_src_var.set(str(src))
        app.enc_dst_var.set(str(enc_rsa))
        app.enc_pwd_var.set(str(rpub))
        app.enc_pwd2_var.set("")  # 密钥文件模式无确认框
        app._start_job(encrypt=True)
        last = wait_job(app)
        check("RSA GUI 加密完成", enc_rsa.is_file(), last)
        check("日志显示密钥强度",
              "RSA-3072" in app.log_text.get("1.0", "end"),
              app.log_text.get("1.0", "end").splitlines()[-1])

        app.dec_plugin_var.set(rsa_item.display_name)
        app._on_plugin_selected(encrypt=False)
        app.root.update()
        check("解密侧标签变为『私钥文件』", app.dec_pwd_label.cget("text") == "私钥文件")
        dec_rsa = tmp / "样本 文件.dat.rsa.out"
        app.dec_src_var.set(str(enc_rsa))
        app.dec_dst_var.set(str(dec_rsa))
        app.dec_pwd_var.set(str(rpriv))
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("RSA GUI 解密完成且内容一致",
              dec_rsa.is_file() and dec_rsa.read_bytes() == src.read_bytes(), last)

        # 错误私钥（换一个不存在的输出名，避免触发覆盖确认对话框阻塞测试）
        _, rpriv2 = rsa_item.plugin.generate_keypair(tmp / "keys2")
        app.dec_dst_var.set(str(tmp / "wrongkey.out"))
        app.dec_pwd_var.set(str(rpriv2))
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("GUI 中错误私钥报错", "私钥" in last or "密钥" in last, last)
        check("错误私钥不产生输出", not (tmp / "wrongkey.out").exists())

        # 切回密码型插件后界面还原
        app.enc_plugin_var.set(app.enc_plugin_combo["values"][0])  # AES
        app._on_plugin_selected(encrypt=True)
        app.root.update()
        check("切回密码插件后恢复密码框",
              app.enc_pwd_label.cget("text") == "密码"
              and app.enc_pwd_entry.cget("show") == "●"
              and app.enc_keygen_btn.winfo_manager() == ""
              and app.enc_credential_browse.winfo_manager() == "")

        # ---- 带口令私钥（RSA）GUI 流程 ----
        print("  -- RSA 加密私钥 --")
        app.enc_plugin_var.set(rsa_item.display_name)
        app._on_plugin_selected(encrypt=True)
        app.dec_plugin_var.set(rsa_item.display_name)
        app._on_plugin_selected(encrypt=False)
        app.root.update()
        check("RSA 解密页出现私钥口令框", app.dec_keypwd_label.winfo_manager() == "grid")

        e_pub, e_priv = rsa_item.plugin.generate_keypair(tmp / "keys_enc", passphrase="gui-pw-456")
        check("GUI 生成的口令私钥为加密 PEM",
              b"BEGIN ENCRYPTED PRIVATE KEY" in e_priv.read_bytes())
        enc2 = tmp / "enc2.encx"
        app.enc_src_var.set(str(src))
        app.enc_dst_var.set(str(enc2))
        app.enc_pwd_var.set(str(e_pub))
        app._start_job(encrypt=True)
        last = wait_job(app)
        check("加密私钥对的公钥可加密", enc2.is_file(), last)

        out2 = tmp / "enc2.out"
        app.dec_src_var.set(str(enc2))
        app.dec_dst_var.set(str(out2))
        app.dec_pwd_var.set(str(e_priv))
        app.dec_keypwd_var.set("gui-pw-456")
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("GUI 口令私钥解密成功", out2.is_file() and out2.read_bytes() == src.read_bytes(), last)

        app.dec_dst_var.set(str(tmp / "wrongpw.out"))
        app.dec_keypwd_var.set("bad-pw")
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("GUI 错误口令报错", "口令" in last, last)

        app.dec_dst_var.set(str(tmp / "nopw.out"))
        app.dec_keypwd_var.set("")
        app._start_job(encrypt=False)
        last = wait_job(app)
        check("GUI 未填口令时给出提示", "口令" in last, last)

        app.dec_plugin_var.set(app.dec_plugin_combo["values"][0])  # AES
        app._on_plugin_selected(encrypt=False)
        app.root.update()
        check("切回 AES 后口令框隐藏", app.dec_keypwd_label.winfo_manager() == "")

        print(f"\nGUI 冒烟: {'全部通过' if not failures else '失败 ' + str(failures)}")
        return 1 if failures else 0
    finally:
        root.destroy()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
