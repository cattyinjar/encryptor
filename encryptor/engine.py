"""加密 / 解密任务执行引擎。

职责：
  - 组装容器：调用插件的流式接口，处理 .encx 头部与元数据尾部；
  - 事务性写盘：先写 ``<目标路径>.part`` 临时文件，成功后原子改名，
    失败/取消时清理，绝不留下半成品或破坏已有文件；
  - 进度回调与取消支持。
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable, Optional

from . import ENC_EXTENSION, container
from .sdk import CancelledError, CryptoPlugin, PluginError

ProgressFn = Callable[[int], None]
CancelFlag = threading.Event


def encrypted_name(src: Path) -> str:
    """加密输出的默认文件名：原文件名 + .encx"""
    return src.name + ENC_EXTENSION


def decrypted_name(src: Path) -> str:
    """解密输出的默认文件名：去掉 .encx 后缀；没有后缀则加 _decrypted。"""
    name = src.name
    low = name.lower()
    if low.endswith(ENC_EXTENSION):
        stripped = name[: -len(ENC_EXTENSION)]
        return stripped if stripped else name + "_decrypted"
    stem, dot, ext = name.partition(".")
    if not dot:
        return name + "_decrypted"
    return f"{stem}_decrypted.{ext}"


def peek_plugin_id(path: Path) -> Optional[str]:
    """只读文件头，快速探测加密时使用的插件 id（不校验尾部）。"""
    try:
        with open(path, "rb") as f:
            import struct

            head = f.read(4 + 1 + 2)
            if len(head) < 7:
                return None
            magic, version = struct.unpack_from("<4sB", head, 0)
            if magic != container.MAGIC or version != container.VERSION:
                return None
            (pid_len,) = struct.unpack_from("<H", head, 5)
            if not 0 < pid_len <= 256:
                return None
            pid = f.read(pid_len)
            return pid.decode("utf-8", errors="replace")
    except (OSError, struct.error):
        return None


class _ProgressGate:
    """把插件上报的字节数转发给上层，并承担取消检查。"""

    def __init__(self, on_progress: Optional[ProgressFn], cancel: Optional[CancelFlag]):
        self._on_progress = on_progress
        self._cancel = cancel

    def __call__(self, n: int) -> None:
        if self._cancel is not None and self._cancel.is_set():
            raise CancelledError("用户取消了任务")
        if self._on_progress is not None and n > 0:
            self._on_progress(n)


def _cleanup(part: Path) -> None:
    try:
        part.unlink(missing_ok=True)
    except OSError:
        pass


def _plugin_call_kwargs(plugin: CryptoPlugin, passphrase: Optional[str]) -> dict:
    """声明了 keyfile_needs_passphrase 的插件，额外收到 passphrase 关键字参数。"""
    if getattr(plugin, "keyfile_needs_passphrase", False):
        return {"passphrase": passphrase}
    return {}


def _check_encrypt_policy(plugin: CryptoPlugin, password: Optional[str]) -> None:
    """加密侧口令策略（N4）：engine 层强制，GUI/CLI/第三方脚本同一防线。

    仅对密码模式插件生效；keyfile 模式的 password 是路径，不做长度检查。
    """
    if (
        password is not None
        and getattr(plugin, "credential_mode", "password") == "password"
        and getattr(plugin, "requires_password", True)
    ):
        min_len = getattr(plugin, "min_password_len", 0)
        if min_len and len(password) < min_len:
            raise PluginError(
                f"密码至少需要 {min_len} 位（当前 {len(password)} 位）——engine 层策略。"
            )


def encrypt_file(
    plugin: CryptoPlugin,
    src_path: Path,
    dst_path: Path,
    password: Optional[str],
    on_progress: Optional[ProgressFn] = None,
    cancel: Optional[CancelFlag] = None,
    passphrase: Optional[str] = None,
) -> int:
    """加密 ``src_path`` → ``dst_path``，返回明文字节数。"""
    _check_encrypt_policy(plugin, password)
    gate = _ProgressGate(on_progress, cancel)
    part = dst_path.with_name(dst_path.name + ".part")
    total = 0
    try:
        with open(src_path, "rb") as src, open(part, "wb") as out:
            container.write_header(out, plugin.id)
            counter = {"n": 0}

            def wrapped(n: int) -> None:
                counter["n"] += n
                gate(n)

            metadata = plugin.encrypt_stream(src, out, password, wrapped,
                                             **_plugin_call_kwargs(plugin, passphrase))
            container.write_trailer(out, metadata)
            total = counter["n"]
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        _cleanup(part)
        raise
    os.replace(part, dst_path)
    return total


def decrypt_file(
    plugin: CryptoPlugin,
    src_path: Path,
    dst_path: Path,
    password: Optional[str],
    expect_plugin_id: Optional[str] = None,
    on_progress: Optional[ProgressFn] = None,
    cancel: Optional[CancelFlag] = None,
    passphrase: Optional[str] = None,
) -> int:
    """解密 ``src_path`` → ``dst_path``，返回明文字节数。

    :param expect_plugin_id: 若给定且与文件头不一致则报错（防呆）。
    """
    gate = _ProgressGate(on_progress, cancel)
    part = dst_path.with_name(dst_path.name + ".part")
    total = 0
    try:
        with open(src_path, "rb") as src:
            info = container.read_container(src)
            if expect_plugin_id and info.plugin_id != expect_plugin_id:
                raise container.ContainerError(
                    f"该文件由插件 [{info.plugin_id}] 加密，请使用对应插件解密"
                )
            if info.plugin_id != plugin.id:
                raise container.ContainerError(
                    f"插件不匹配：文件由 [{info.plugin_id}] 加密，当前选择的是 [{plugin.id}]"
                )
            payload = container.open_payload_reader(src, info)
            with open(part, "wb") as out:
                counter = {"n": 0}

                def wrapped(n: int) -> None:
                    counter["n"] += n
                    gate(n)

                plugin.decrypt_stream(info.metadata, payload, out, password, wrapped,
                                      **_plugin_call_kwargs(plugin, passphrase))
                total = counter["n"]
                out.flush()
                os.fsync(out.fileno())
    except BaseException:
        _cleanup(part)
        raise
    os.replace(part, dst_path)
    return total
