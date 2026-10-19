"""Tkinter GUI：加密页 / 解密页 / 插件管理页。

约定：所有控件操作都在主线程；加密解密任务在后台线程执行，
通过 queue + root.after 把日志、进度、完成事件传回主线程。
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Optional

from . import ENC_EXTENSION, __version__
from . import engine, plugin_manager
from .container import ContainerError
from .sdk import CancelledError, IntegrityError, PluginError, WrongPasswordError

APP_TITLE = f"Encryptor 单机加密解密工具 v{__version__}"
GEOMETRY = "820x640"

# 弱口令策略（审计 F4）：长度下限 + 常见弱口令拒绝
MIN_PASSWORD_LEN = 8
WEAK_PASSWORDS = {
    "12345678", "123456789", "1234567890", "11111111", "00000000",
    "password", "password1", "qwertyui", "qwertyuiop", "aaaaaaaa",
    "abc12345", "abcd1234", "iloveyou", "sunshine", "letmein1",
    "admin123", "root1234", "66666666", "88888888", "12341234",
}


def check_password_policy(password: str) -> Optional[str]:
    """返回拒绝原因；通过时返回 None。"""
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码至少需要 {MIN_PASSWORD_LEN} 位（当前 {len(password)} 位）。"
    if password.lower() in WEAK_PASSWORDS:
        return "该密码属于常见弱口令，请更换。"
    return None


class KeygenDialog(tk.Toplevel):
    """生成密钥对子窗口：选择保存目录，并可选择是否为私钥设置口令。

    模态对话框。关闭后 ``result`` 为 ``(目录, 口令或 None)``，取消时为 None。
    """

    def __init__(self, root: tk.Tk, plugin) -> None:
        super().__init__(root)
        self.title(f"生成密钥对 — {plugin.name}")
        self.resizable(False, False)
        self.result = None
        self.transient(root)

        body = ttk.Frame(self, padding=16)
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)

        ttk.Label(body, text="保存目录").grid(row=0, column=0, sticky="w")
        dir_holder = ttk.Frame(body)
        dir_holder.grid(row=1, column=0, sticky="ew", pady=(2, 10))
        dir_holder.columnconfigure(0, weight=1)
        self.dir_var = tk.StringVar()
        ttk.Entry(dir_holder, textvariable=self.dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(dir_holder, text="浏览…", width=8, command=self._pick_dir).grid(
            row=0, column=1, padx=(6, 0))

        self.use_pass_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            body, text="为私钥文件设置口令保护（推荐）", variable=self.use_pass_var,
            command=self._sync_pass_state,
        ).grid(row=2, column=0, sticky="w", pady=(0, 4))

        self.pwd_var = tk.StringVar()
        self.pwd2_var = tk.StringVar()
        ttk.Label(body, text="口令").grid(row=3, column=0, sticky="w")
        self.pwd_entry = ttk.Entry(body, textvariable=self.pwd_var, show="●", width=44)
        self.pwd_entry.grid(row=4, column=0, sticky="w", pady=(2, 4))
        ttk.Label(body, text="确认口令").grid(row=5, column=0, sticky="w")
        self.pwd2_entry = ttk.Entry(body, textvariable=self.pwd2_var, show="●", width=44)
        self.pwd2_entry.grid(row=6, column=0, sticky="w", pady=(2, 4))
        ttk.Label(
            body, foreground="#555555", wraplength=360,
            text="口令只保护私钥文件本身；公钥不需要口令。"
                 "请牢记口令——口令丢失则私钥永久无法使用。",
        ).grid(row=7, column=0, sticky="w", pady=(6, 12))

        btns = ttk.Frame(body)
        btns.grid(row=8, column=0, sticky="e")
        ttk.Button(btns, text="生成", command=self._ok).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="取消", command=self._cancel).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self._sync_pass_state()
        self.grab_set()
        self.pwd_entry.focus_set()

    def _pick_dir(self) -> None:
        path = filedialog.askdirectory(title="选择密钥对保存目录", parent=self)
        if path:
            self.dir_var.set(path)

    def _sync_pass_state(self) -> None:
        state = "normal" if self.use_pass_var.get() else "disabled"
        for w in (self.pwd_entry, self.pwd2_entry):
            w.configure(state=state)

    def _validate_and_collect(self):
        dest = self.dir_var.get().strip()
        if not dest:
            messagebox.showwarning("缺少目录", "请先选择密钥对保存目录。", parent=self)
            return None
        if not Path(dest).is_dir():
            messagebox.showwarning("目录无效", f"目录不存在：\n{dest}", parent=self)
            return None
        if self.use_pass_var.get():
            p1, p2 = self.pwd_var.get(), self.pwd2_var.get()
            if not p1:
                messagebox.showwarning("缺少口令", "请输入私钥保护口令，或取消勾选口令保护。", parent=self)
                return None
            reason = check_password_policy(p1)
            if reason:
                messagebox.showwarning("口令强度不足", reason, parent=self)
                return None
            if p1 != p2:
                messagebox.showwarning("口令不一致", "两次输入的口令不一致。", parent=self)
                return None
            return dest, p1
        return dest, None

    def _ok(self) -> None:
        collected = self._validate_and_collect()
        if collected is not None:
            self.result = collected
            self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


class EncryptorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry(GEOMETRY)
        root.minsize(720, 560)

        self.registry = plugin_manager.PluginRegistry()
        self._event_queue: "queue.Queue[tuple]" = queue.Queue()
        self._busy = False
        self._cancel_flag: Optional[threading.Event] = None
        self._worker: Optional[threading.Thread] = None
        self._active_progress = (None, None)

        self._build_style()
        self._build_widgets()
        self.reload_plugins(quiet=True)
        self.root.after(80, self._poll_events)

    # ------------------------------------------------------------------
    # 界面搭建
    # ------------------------------------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        base = ttk.Frame(self.root)
        base.grid(row=0, column=0, sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        pad = {"padx": 14, "pady": (10, 4)}
        self.notebook = ttk.Notebook(base)
        self.notebook.grid(row=0, column=0, sticky="nsew", **pad)
        self.log_panel = ttk.LabelFrame(base, text="日志")
        self.log_panel.grid(row=1, column=0, sticky="nsew", **{"padx": 14, "pady": (4, 0)})
        self.status_bar = ttk.Frame(base)
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=14, pady=(4, 8))
        base.rowconfigure(0, weight=1)
        base.columnconfigure(0, weight=1)

        # 日志面板
        self.log_text = tk.Text(
            self.log_panel, height=8, state="disabled", wrap="none",
            font=("Consolas", 9),
        )
        scroll = ttk.Scrollbar(self.log_panel, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=6)
        scroll.grid(row=0, column=1, sticky="ns", pady=6)
        self.log_panel.rowconfigure(0, weight=1)
        self.log_panel.columnconfigure(0, weight=1)
        for tag, color in (("info", "#333333"), ("ok", "#0a7d32"), ("err", "#c0262c")):
            self.log_text.tag_configure(tag, foreground=color)

        # 状态栏
        self.status_plugins = ttk.Label(self.status_bar, text="插件：-")
        self.status_plugins.pack(side="left")
        self.status_job = ttk.Label(self.status_bar, text="就绪")
        self.status_job.pack(side="right")

    def _form_frame(self, parent: ttk.Notebook, title: str) -> ttk.Frame:
        page = ttk.Frame(parent, padding=16)
        parent.add(page, text=title)
        page.columnconfigure(1, weight=1)
        return page

    def _row(self, page: ttk.Frame, row: int, label: str):
        """创建 [标签 | 内容行] 布局，返回 (内容行容器, 标签控件)。"""
        label_widget = ttk.Label(page, text=label)
        label_widget.grid(row=row, column=0, sticky="e", padx=(0, 8), pady=5)
        holder = ttk.Frame(page)
        holder.grid(row=row, column=1, columnspan=2, sticky="ew")
        holder.columnconfigure(0, weight=1)
        return holder, label_widget

    def _build_widgets(self) -> None:
        self._build_encrypt_page()
        self._build_decrypt_page()
        self._build_plugins_page()

    def _build_encrypt_page(self) -> None:
        page = self._form_frame(self.notebook, "加密")
        self.enc_page = page

        ttk.Label(page, text="加密方式").grid(row=0, column=0, sticky="e", padx=(0, 8), pady=5)
        self.enc_plugin_var = tk.StringVar()
        self.enc_plugin_combo = ttk.Combobox(page, textvariable=self.enc_plugin_var, state="readonly")
        self.enc_plugin_combo.grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)
        self.enc_plugin_combo.bind("<<ComboboxSelected>>", lambda e: self._on_plugin_selected(encrypt=True))
        self.enc_desc_label = ttk.Label(page, text="", wraplength=560, foreground="#555555")
        self.enc_desc_label.grid(row=1, column=1, columnspan=2, sticky="w", pady=(0, 6))

        holder, _ = self._row(page, 2, "待加密文件")
        self.enc_src_var = tk.StringVar()
        self.enc_src_entry = ttk.Entry(holder, textvariable=self.enc_src_var)
        self.enc_src_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(holder, text="浏览…", width=8, command=self._pick_encrypt_source).grid(row=0, column=1, padx=(6, 0))

        holder, _ = self._row(page, 3, "加密后保存为")
        self.enc_dst_var = tk.StringVar()
        self.enc_dst_entry = ttk.Entry(holder, textvariable=self.enc_dst_var)
        self.enc_dst_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(holder, text="浏览…", width=8, command=self._pick_encrypt_dest).grid(row=0, column=1, padx=(6, 0))

        holder, self.enc_pwd_label = self._row(page, 4, "密码")
        self.enc_pwd_holder = holder
        self.enc_pwd_var = tk.StringVar()
        self.enc_pwd_entry = ttk.Entry(holder, textvariable=self.enc_pwd_var, show="●")
        self.enc_pwd_entry.grid(row=0, column=0, sticky="ew")
        # 密钥文件模式下显示的"选择密钥"按钮；是否布局由 _on_plugin_selected 决定
        self.enc_credential_browse = ttk.Button(
            holder, text="选择…", width=8, command=lambda: self._pick_credential_file(encrypt=True)
        )
        holder, self.enc_confirm_label = self._row(page, 5, "确认密码")
        self.enc_confirm_holder = holder
        self.enc_pwd2_var = tk.StringVar()
        self.enc_pwd2_entry = ttk.Entry(holder, textvariable=self.enc_pwd2_var, show="●")
        self.enc_pwd2_entry.grid(row=0, column=0, sticky="ew")

        self._build_progress_area(page, 6, encrypt=True)
        holder = ttk.Frame(page)
        holder.grid(row=7, column=1, columnspan=2, sticky="w", pady=(10, 0))
        self.enc_start_btn = ttk.Button(holder, text="开始加密", command=lambda: self._start_job(encrypt=True))
        self.enc_start_btn.pack(side="left")
        # 密钥文件插件（supports_keygen）显示的"生成密钥对"按钮
        self.enc_keygen_btn = ttk.Button(holder, text="生成密钥对…", command=self._generate_keypair)

    def _build_decrypt_page(self) -> None:
        page = self._form_frame(self.notebook, "解密")
        self.dec_page = page

        ttk.Label(page, text="解密方式").grid(row=0, column=0, sticky="e", padx=(0, 8), pady=5)
        self.dec_plugin_var = tk.StringVar()
        self.dec_plugin_combo = ttk.Combobox(page, textvariable=self.dec_plugin_var, state="readonly")
        self.dec_plugin_combo.grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)
        self.dec_plugin_combo.bind("<<ComboboxSelected>>", lambda e: self._on_plugin_selected(encrypt=False))
        ttk.Label(
            page, text="选择文件后会按文件头自动识别，通常无需手动修改",
            foreground="#555555",
        ).grid(row=1, column=1, columnspan=2, sticky="w", pady=(0, 6))
        self.dec_desc_label = ttk.Label(page, text="", wraplength=560, foreground="#555555")
        self.dec_desc_label.grid(row=2, column=1, columnspan=2, sticky="w", pady=(0, 6))

        holder, _ = self._row(page, 3, "待解密文件")
        self.dec_src_var = tk.StringVar()
        self.dec_src_entry = ttk.Entry(holder, textvariable=self.dec_src_var)
        self.dec_src_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(holder, text="浏览…", width=8, command=self._pick_decrypt_source).grid(row=0, column=1, padx=(6, 0))

        holder, _ = self._row(page, 4, "解密后保存为")
        self.dec_dst_var = tk.StringVar()
        self.dec_dst_entry = ttk.Entry(holder, textvariable=self.dec_dst_var)
        self.dec_dst_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(holder, text="浏览…", width=8, command=self._pick_decrypt_dest).grid(row=0, column=1, padx=(6, 0))

        holder, self.dec_pwd_label = self._row(page, 5, "密码")
        self.dec_pwd_var = tk.StringVar()
        self.dec_pwd_entry = ttk.Entry(holder, textvariable=self.dec_pwd_var, show="●")
        self.dec_pwd_entry.grid(row=0, column=0, sticky="ew")
        self.dec_credential_browse = ttk.Button(
            holder, text="选择…", width=8, command=lambda: self._pick_credential_file(encrypt=False)
        )

        # 密钥文件的口令框：仅声明 keyfile_needs_passphrase 的插件显示（如加密私钥）
        holder, self.dec_keypwd_label = self._row(page, 6, "口令")
        self.dec_keypwd_holder = holder
        self.dec_keypwd_var = tk.StringVar()
        self.dec_keypwd_entry = ttk.Entry(holder, textvariable=self.dec_keypwd_var, show="●")
        self.dec_keypwd_entry.grid(row=0, column=0, sticky="ew")

        self._build_progress_area(page, 7, encrypt=False)
        holder = ttk.Frame(page)
        holder.grid(row=8, column=1, columnspan=2, sticky="w", pady=(10, 0))
        self.dec_start_btn = ttk.Button(holder, text="开始解密", command=lambda: self._start_job(encrypt=False))
        self.dec_start_btn.pack(side="left")

    def _build_progress_area(self, page: ttk.Frame, row: int, encrypt: bool) -> None:
        holder = ttk.Frame(page)
        holder.grid(row=row, column=1, columnspan=2, sticky="ew", pady=(12, 0))
        holder.columnconfigure(0, weight=1)
        bar = ttk.Progressbar(holder, mode="determinate", maximum=100)
        bar.grid(row=0, column=0, sticky="ew")
        pct = ttk.Label(holder, text="0%", width=6, anchor="e")
        pct.grid(row=0, column=1, padx=(8, 0))
        cancel = ttk.Button(holder, text="取消", width=6, command=self._cancel_job)
        cancel.grid(row=0, column=2, padx=(8, 0))
        if encrypt:
            self.enc_bar, self.enc_bar_pct, self.enc_cancel_btn = bar, pct, cancel
        else:
            self.dec_bar, self.dec_bar_pct, self.dec_cancel_btn = bar, pct, cancel
        cancel.config(state="disabled")

    def _cancel_job(self) -> None:
        if self._cancel_flag is not None:
            self._cancel_flag.set()
            self.log("正在取消…", "info")

    def _build_plugins_page(self) -> None:
        page = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(page, text="插件")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(0, weight=1)

        columns = ("state", "name", "pid", "version", "author", "desc")
        self.plugin_tree = ttk.Treeview(page, columns=columns, show="headings", height=12)
        headers = {
            "state": ("状态", 80, "center"),
            "name": ("名称", 170, "w"),
            "pid": ("插件 ID", 130, "w"),
            "version": ("版本", 70, "center"),
            "author": ("作者", 130, "w"),
            "desc": ("说明", 320, "w"),
        }
        for col, (text, width, anchor) in headers.items():
            self.plugin_tree.heading(col, text=text)
            self.plugin_tree.column(col, width=width, anchor=anchor, stretch=(col == "desc"))
        self.plugin_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(page, orient="vertical", command=self.plugin_tree.yview)
        self.plugin_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")
        self.plugin_tree.bind("<Double-1>", self._show_plugin_detail)

        btns = ttk.Frame(page)
        btns.grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Button(btns, text="重新扫描插件", command=lambda: self.reload_plugins()).pack(side="left")
        ttk.Button(btns, text="打开插件目录", command=self._open_plugins_dir).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="插件开发指南", command=self._open_plugin_doc).pack(side="left", padx=(8, 0))

    # ------------------------------------------------------------------
    # 插件管理
    # ------------------------------------------------------------------

    def reload_plugins(self, quiet: bool = False) -> None:
        previous_enc = self._selected_plugin_id(encrypt=True)
        previous_dec = self._selected_plugin_id(encrypt=False)
        self.registry = plugin_manager.scan_plugins()
        names = [item.display_name for item in self.registry.loaded]
        for combo, var, prev in (
            (self.enc_plugin_combo, self.enc_plugin_var, previous_enc),
            (self.dec_plugin_combo, self.dec_plugin_var, previous_dec),
        ):
            combo["values"] = names
            var.set("")
            if prev:
                for item in self.registry.loaded:
                    if item.id == prev:
                        var.set(item.display_name)
            if not var.get() and names:
                var.set(names[0])
        self._on_plugin_selected(encrypt=True)
        self._on_plugin_selected(encrypt=False)

        self.plugin_tree.delete(*self.plugin_tree.get_children())
        for item in self.registry.loaded:
            p = item.plugin
            self.plugin_tree.insert("", "end", values=(
                "可用", p.name, p.id, p.version, p.author or "-", p.description or "-",
            ), tags=("ok",))
        for item in self.registry.failed:
            self.plugin_tree.insert("", "end", values=(
                "加载失败", item.source.stem, "-", "-", "-", item.reason,
            ), tags=("err",))
        self.plugin_tree.tag_configure("ok", foreground="#0a7d32")
        self.plugin_tree.tag_configure("err", foreground="#c0262c")

        self.status_plugins.config(
            text=f"插件：{len(self.registry.loaded)} 个可用"
            + (f"，{len(self.registry.failed)} 个加载失败" if self.registry.failed else "")
        )
        if not quiet:
            self.log(f"已重新扫描插件：{len(self.registry.loaded)} 个可用，{len(self.registry.failed)} 个失败。", "info")
        for item in self.registry.failed:
            self.log(f"插件加载失败 {item.source}: {item.reason}", "err")

    def _selected_plugin(self, encrypt: bool):
        var = self.enc_plugin_var if encrypt else self.dec_plugin_var
        display = var.get()
        for item in self.registry.loaded:
            if item.display_name == display:
                return item.plugin
        return None

    def _selected_plugin_id(self, encrypt: bool) -> Optional[str]:
        p = self._selected_plugin(encrypt)
        return p.id if p else None

    def _on_plugin_selected(self, encrypt: bool) -> None:
        plugin = self._selected_plugin(encrypt)
        if plugin is None:
            return
        desc = self.enc_desc_label if encrypt else self.dec_desc_label
        extra = "" if plugin.requires_password else "（该算法无需密码）"
        if not getattr(plugin, "authenticated", False):
            extra = "⚠ 该算法未声明完整性保护（无防篡改能力），请谨慎使用！" + extra
            desc.config(foreground="#c0262c")
        else:
            desc.config(foreground="#555555")
        desc.config(text=(plugin.description or "（无描述）") + extra)

        if encrypt:
            label = self.enc_pwd_label
            entry = self.enc_pwd_entry
            browse = self.enc_credential_browse
            confirm_widgets = (self.enc_confirm_label, self.enc_confirm_holder)
        else:
            label = self.dec_pwd_label
            entry = self.dec_pwd_entry
            browse = self.dec_credential_browse
            confirm_widgets = ()

        if getattr(plugin, "credential_mode", "password") == "keyfile":
            hint = (plugin.encrypt_credential_hint if encrypt else plugin.decrypt_credential_hint) or "密钥文件"
            label.config(text=hint)
            entry.configure(show="")
            browse.grid(row=0, column=1, padx=(6, 0))
            entry.grid()
            label.grid()
        else:
            label.config(text="密码")
            entry.configure(show="●")
            browse.grid_remove()
            if plugin.requires_password:
                entry.grid()
                label.grid()
            else:
                entry.grid_remove()
                label.grid_remove()

        # 解密页的密钥文件口令框（加密私钥场景）
        if not encrypt:
            show_keypwd = (
                getattr(plugin, "credential_mode", "password") == "keyfile"
                and getattr(plugin, "keyfile_needs_passphrase", False)
            )
            if show_keypwd:
                self.dec_keypwd_label.grid()
                self.dec_keypwd_holder.grid()
            else:
                self.dec_keypwd_label.grid_remove()
                self.dec_keypwd_holder.grid_remove()
                self.dec_keypwd_var.set("")

        for widget in confirm_widgets:  # 确认密码行只在密码模式且需要密码时出现
            if getattr(plugin, "credential_mode", "password") == "keyfile" or not plugin.requires_password:
                widget.grid_remove()
            else:
                widget.grid()

        if encrypt:  # "生成密钥对"按钮仅密钥文件插件显示
            if getattr(plugin, "supports_keygen", False):
                self.enc_keygen_btn.pack(side="left", padx=(10, 0))
            else:
                self.enc_keygen_btn.pack_forget()

    def _show_plugin_detail(self, _event=None) -> None:
        sel = self.plugin_tree.selection()
        if not sel:
            return
        values = self.plugin_tree.item(sel[0], "values")
        state, name, pid, version, author, desc = values
        if state == "可用":
            plugin = self.registry.find(pid)
            if plugin:
                msg = (
                    f"名称：{plugin.name}\n插件 ID：{plugin.id}\n版本：{plugin.version}\n"
                    f"作者：{plugin.author or '-'}\n需要密码：{'是' if plugin.requires_password else '否'}\n\n"
                    f"说明：{plugin.description or '-'}\n"
                )
                src = self.registry.get(pid)
                if src:
                    msg += f"\n源码位置：{src.source}"
                messagebox.showinfo("插件详情", msg)
        else:
            fail = next((f for f in self.registry.failed if f.source.stem == name), None)
            msg = f"加载失败：{name}\n\n原因：{fail.reason if fail else desc}\n\n源码位置：{fail.source if fail else '-'}"
            messagebox.showerror("插件详情", msg)

    def _open_plugins_dir(self) -> None:
        path = plugin_manager.default_plugins_dir()
        try:
            os.startfile(path)  # type: ignore[attr-defined]  # Windows
        except Exception:
            self.log(f"插件目录：{path}", "info")

    def _open_plugin_doc(self) -> None:
        if getattr(sys, "frozen", False):
            doc = Path(sys.executable).resolve().parent / "docs" / "PLUGIN_DEV.md"
        else:
            doc = Path(__file__).resolve().parent.parent / "docs" / "PLUGIN_DEV.md"
        if doc.is_file():
            try:
                os.startfile(doc)  # type: ignore[attr-defined]
                return
            except Exception:
                pass
        self.log(f"插件开发指南位置：{doc}", "info")

    # ------------------------------------------------------------------
    # 文件选择
    # ------------------------------------------------------------------

    def _pick_encrypt_source(self) -> None:
        path = filedialog.askopenfilename(title="选择待加密文件", parent=self.root)
        if not path:
            return
        self.enc_src_var.set(path)
        src = Path(path)
        self.enc_dst_var.set(str(src.with_name(engine.encrypted_name(src))))
        self.log(f"已选择待加密文件：{path}", "info")

    def _pick_encrypt_dest(self) -> None:
        initial = self.enc_dst_var.get() or (self.enc_src_var.get() + ENC_EXTENSION)
        path = filedialog.asksaveasfilename(
            title="选择加密文件保存位置",
            defaultextension=ENC_EXTENSION,
            filetypes=[("Encryptor 加密文件", f"*{ENC_EXTENSION}"), ("所有文件", "*.*")],
            initialfile=Path(initial).name if initial else "encrypted",
            parent=self.root,
        )
        if path:
            self.enc_dst_var.set(path)

    def _pick_decrypt_source(self) -> None:
        path = filedialog.askopenfilename(
            title="选择待解密文件",
            filetypes=[("Encryptor 加密文件", f"*{ENC_EXTENSION}"), ("所有文件", "*.*")],
            parent=self.root,
        )
        if path:
            self._handle_decrypt_source(path)

    def _handle_decrypt_source(self, path: str) -> None:
        self.dec_src_var.set(path)
        src = Path(path)
        self.dec_dst_var.set(str(src.with_name(engine.decrypted_name(src))))
        # 按文件头自动选择解密插件
        pid = engine.peek_plugin_id(src)
        if pid:
            hit = self.registry.find(pid)
            if hit:
                for item in self.registry.loaded:
                    if item.id == pid:
                        self.dec_plugin_var.set(item.display_name)
                        self._on_plugin_selected(encrypt=False)
                self.log(f"已识别加密算法：{hit.name}（{pid}）", "info")
            else:
                self.log(f"该文件由插件 [{pid}] 加密，但当前未加载该插件，请先安装/启用后再解密。", "err")
        else:
            self.log("警告：文件头不是有效的 Encryptor 加密格式，无法自动识别算法。", "err")
        self.log(f"已选择待解密文件：{path}", "info")

    def open_encx_file(self, path: str) -> None:
        """供双击 .encx / 命令行传参打开：切到解密页并预填。"""
        if not Path(path).is_file():
            return
        try:
            self.notebook.select(1)
        except tk.TclError:
            pass
        self._handle_decrypt_source(path)

    def _pick_decrypt_dest(self) -> None:
        initial = self.dec_dst_var.get()
        path = filedialog.asksaveasfilename(
            title="选择解密文件保存位置",
            initialfile=Path(initial).name if initial else "decrypted",
            parent=self.root,
        )
        if path:
            self.dec_dst_var.set(path)

    def _pick_credential_file(self, encrypt: bool) -> None:
        plugin = self._selected_plugin(encrypt)
        filetypes = getattr(plugin, "credential_filetypes", None) or [("所有文件", "*.*")]
        title = "选择公钥文件" if encrypt else "选择私钥文件"
        path = filedialog.askopenfilename(title=title, filetypes=list(filetypes), parent=self.root)
        if path:
            (self.enc_pwd_var if encrypt else self.dec_pwd_var).set(path)

    def _generate_keypair(self) -> None:
        """密钥对生成：在短命子进程中完成，父进程（GUI）不接触密钥字节。"""
        if self._busy:
            return
        plugin = self._selected_plugin(encrypt=True)
        if plugin is None:
            return
        dialog = KeygenDialog(self.root, plugin)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return
        dest, passphrase = dialog.result

        from . import jobrunner

        protection = "口令保护" if passphrase else "无保护（明文私钥，请妥善保管）"
        self._cancel_flag = None  # 密钥生成不提供取消
        self._set_busy(True, "正在生成密钥对…")
        self._keygen_ctx = (plugin.name, protection)
        self.log(f"开始生成密钥对（{plugin.name}，私钥{protection}），目录：{dest}", "info")

        def worker():
            ok, message = jobrunner.run_in_subprocess(
                {"kind": "keygen", "plugin_id": plugin.id,
                 "dest": str(dest), "passphrase": passphrase},
                on_event=lambda ev: self._event_queue.put(ev),
            )
            self._event_queue.put(("done", ok, message))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # 任务执行
    # ------------------------------------------------------------------

    def _set_busy(self, busy: bool, job_text: str = "") -> None:
        self._busy = busy
        for btn in (self.enc_start_btn, self.dec_start_btn):
            btn.config(state="disabled" if busy else "normal")
        for btn in (self.enc_cancel_btn, self.dec_cancel_btn):
            btn.config(state="normal" if busy else "disabled")
        self.status_job.config(text=job_text if busy else "就绪")
        if not busy:
            self._cancel_flag = None
            # N2：任务结束（成功/出错/取消）即清空口令类输入，缩短驻留窗口。
            # 只清"秘密"：密码/确认密码/私钥口令；密钥文件路径不是秘密，保留
            # 以免多文件解密时反复重选（keyfile 模式的路径存于 dec_pwd_var）。
            keygen_done = getattr(self, "_keygen_ctx", None)
            self.enc_pwd2_var.set("")
            self.dec_keypwd_var.set("")
            if not keygen_done:
                self.enc_pwd_var.set("")
            if getattr(self, "_last_job_password_mode", False):
                self.dec_pwd_var.set("")   # 密码模式下该框装的是密码
            if keygen_done:
                self._keygen_ctx = None
            self.log("任务结束：已清空口令输入框。", "info")

    def _validate(self, encrypt: bool):
        src_var = self.enc_src_var if encrypt else self.dec_src_var
        dst_var = self.enc_dst_var if encrypt else self.dec_dst_var
        plugin = self._selected_plugin(encrypt)
        if plugin is None:
            if not self.registry.loaded:
                raise PluginError("没有可用的加密插件，请先在『插件』页检查插件加载情况。")
            raise PluginError("请选择加密/解密方式。")
        src = Path(src_var.get().strip())
        if not src_var.get().strip():
            raise PluginError("请选择待处理文件。")
        if not src.is_file():
            raise PluginError(f"文件不存在：{src}")
        dst = Path(dst_var.get().strip())
        if not dst_var.get().strip():
            raise PluginError("请选择输出保存位置。")
        if dst == src:
            raise PluginError("输出路径不能与源文件相同。")
        password = None
        passphrase = None
        mode = getattr(plugin, "credential_mode", "password")
        cred_var = self.enc_pwd_var if encrypt else self.dec_pwd_var
        if mode == "keyfile":
            cred = cred_var.get().strip()
            if not cred:
                raise PluginError("请选择密钥文件。")
            key_path = Path(cred)
            if not key_path.is_file():
                raise PluginError(f"密钥文件不存在：{key_path}")
            password = str(key_path)
            if not encrypt and getattr(plugin, "keyfile_needs_passphrase", False):
                passphrase = self.dec_keypwd_var.get() or None
        elif plugin.requires_password:
            password = cred_var.get()
            if not password:
                raise PluginError("请输入密码。")
            # 口令策略只在加密侧强制：解密口令由既有文件决定，不做限制
            if encrypt:
                reason = check_password_policy(password)
                if reason:
                    raise PluginError(reason)
                if password != self.enc_pwd2_var.get():
                    raise PluginError("两次输入的密码不一致。")
        if dst.exists():
            ok = messagebox.askyesno(
                "覆盖确认", f"目标文件已存在，是否覆盖？\n\n{dst}", parent=self.root
            )
            if not ok:
                raise CancelledError("已取消：用户放弃覆盖目标文件。")
        return plugin, src, dst, password, passphrase

    def _start_job(self, encrypt: bool) -> None:
        if self._busy:
            return
        pre_plugin = self._selected_plugin(encrypt)
        if pre_plugin is not None and not getattr(pre_plugin, "authenticated", False):
            ok = messagebox.askyesno(
                "安全提示",
                f"算法 [{pre_plugin.name}] 未声明完整性保护（authenticated=False），\n"
                "密文可被篡改而无法察觉。\n\n确定继续使用该算法吗？",
                parent=self.root,
            )
            if not ok:
                return
        try:
            plugin, src, dst, password, passphrase = self._validate(encrypt)
        except CancelledError as exc:
            self.log(str(exc) or "已取消。", "info")
            return
        except PluginError as exc:
            self.log(str(exc), "err")
            return

        self._cancel_flag = threading.Event()
        action = "加密" if encrypt else "解密"
        # 记录本次任务的凭据形态：任务结束后据此决定是否清空解密页凭据框
        self._last_job_password_mode = (
            getattr(plugin, "credential_mode", "password") == "password"
            and plugin.requires_password
        )
        self._set_busy(True, f"正在{action}…")
        bar, pct = (self.enc_bar, self.enc_bar_pct) if encrypt else (self.dec_bar, self.dec_bar_pct)
        self._active_progress = (bar, pct)
        bar["value"] = 0
        pct.config(text="0%")
        total = src.stat().st_size
        cred_note = (
            f"\n  密钥文件：{password}" if getattr(plugin, "credential_mode", "password") == "keyfile" else ""
        )
        self.log(
            f"开始{action}：{src}\n  → {dst}\n  算法：{plugin.name}（{plugin.id} v{plugin.version}）{cred_note}",
            "info",
        )
        self._worker = threading.Thread(
            target=self._run_job,
            args=(encrypt, plugin, src, dst, password, passphrase, total),
            daemon=True,
        )
        self._worker.start()

    def _run_job(self, encrypt, plugin, src, dst, password, passphrase, total) -> None:
        from . import jobrunner

        q = self._event_queue
        spec = {
            "kind": "crypto",
            "encrypt": encrypt,
            "plugin_id": plugin.id,
            "src": str(src),
            "dst": str(dst),
            "password": password,
            "passphrase": passphrase,
            "credential": password if getattr(plugin, "credential_mode", "password") == "keyfile" else None,
            "total": total,
        }
        ok, message = jobrunner.run_in_subprocess(
            spec,
            on_event=lambda ev: q.put(ev),
            cancel_flag=self._cancel_flag,
        )
        q.put(("done", ok, message))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._event_queue.get_nowait()
                kind = event[0]
                if kind == "log":
                    _, text, level = event
                    self.log(text, level)
                elif kind == "keygen":
                    _, pub_path, priv_path = event
                    self.enc_pwd_var.set(pub_path)
                    self.log(
                        f"  公钥 {pub_path}\n  私钥 {priv_path}\n"
                        "公钥用于加密、私钥用于解密；私钥路径请妥善保管，公钥路径已自动填入。",
                        "ok",
                    )
                elif kind == "progress":
                    _, percent = event
                    bar, label = self._active_progress
                    if bar is not None:
                        bar["value"] = percent
                        label.config(text=f"{percent}%")
                elif kind == "done":
                    _, ok, message = event
                    self.log(message, "ok" if ok else "err")
                    bar, label = self._active_progress
                    if ok and bar is not None:
                        bar["value"] = 100
                        label.config(text="100%")
                    self._set_busy(False)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_events)

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------

    def log(self, message: str, level: str = "info") -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{stamp}] {message}\n", level)
        self.log_text.see("end")
        self.log_text.config(state="disabled")


def run_app(open_file: Optional[str] = None) -> None:
    root = tk.Tk()
    app = EncryptorApp(root)
    if open_file:
        app.open_encx_file(open_file)
    root.mainloop()


def main() -> None:
    run_app()
