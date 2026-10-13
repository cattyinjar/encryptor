"""GUI 任务子进程执行器（审计 F7 的结构性修复）。

密钥材料只存在于**短命子进程**中：加密/解密、密钥对生成、密钥描述全部
在子进程完成，任务结束子进程退出，其地址空间（含第三方库内部的密钥
副本——实测会残留的 ECC DER、SM2 hex 串等）随之消亡，父进程（GUI）从
不接触任何密钥字节。

事件协议（子进程 → 父进程，multiprocessing.Queue）::

    ("progress", pct)        进度百分比
    ("log", text, level)     日志行（如密钥强度描述）
    ("keygen", pub, priv)    密钥对生成完成（仅路径，无密钥内容）
    ("done", ok, message)    任务结束（终态事件）

取消：父进程直接 terminate 子进程（硬终止），并负责清理 ``.part``
临时文件（子进程来不及走 finally）。
"""

from __future__ import annotations

import multiprocessing as mp
import queue as queue_mod
from pathlib import Path
from typing import Callable, Optional, Tuple


def _child_job(q, spec: dict) -> None:
    """子进程入口：加载插件并执行任务。密钥材料只存在于本进程。"""
    import sys
    import time

    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from encryptor import engine, plugin_manager, securemem
    from encryptor.container import ContainerError
    from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

    def done(ok: bool, message: str) -> None:
        q.put(("done", ok, message))

    kind = spec["kind"]
    try:
        registry = plugin_manager.scan_plugins()
        plugin = registry.find(spec["plugin_id"])
        if plugin is None:
            raise PluginError(f"插件 [{spec['plugin_id']}] 未加载，请到『插件』页检查。")

        if kind == "keygen":
            pub_path, priv_path = plugin.generate_keypair(
                Path(spec["dest"]), spec.get("passphrase")
            )
            q.put(("keygen", str(pub_path), str(priv_path)))
            done(True, f"已生成密钥对（{plugin.name}）。")
            return

        if kind == "describe":
            note = plugin.describe_credential(
                spec["credential"], passphrase=spec.get("passphrase")
            )
            done(True, note or "")
            return

        # ---- 加密 / 解密 ----
        mem_before = securemem.snapshot()
        total = spec["total"]

        # describe 并入任务进程：密钥强度日志（在读取密钥文件前发出）
        if spec.get("credential"):
            try:
                note = plugin.describe_credential(
                    spec["credential"], passphrase=spec.get("passphrase")
                )
                if note:
                    q.put(("log", f"密钥：{note}", "info"))
            except Exception:
                pass

        processed = [0]
        last_report = [0.0]

        def on_progress(n: int) -> None:
            processed[0] += n
            now = time.monotonic()
            if now - last_report[0] > 0.1 or processed[0] >= total:
                last_report[0] = now
                q.put(("progress", min(100, processed[0] * 100 // total) if total else 100))

        try:
            if spec["encrypt"]:
                n = engine.encrypt_file(
                    plugin, Path(spec["src"]), Path(spec["dst"]),
                    spec.get("password"), on_progress, None,
                    passphrase=spec.get("passphrase"),
                )
            else:
                n = engine.decrypt_file(
                    plugin, Path(spec["src"]), Path(spec["dst"]),
                    spec.get("password"), expect_plugin_id=spec["plugin_id"],
                    on_progress=on_progress, cancel=None,
                    passphrase=spec.get("passphrase"),
                )
        except WrongPasswordError as exc:
            done(False, f"密码错误或文件已损坏：{exc}")
            return
        except ContainerError as exc:
            done(False, f"文件格式错误：{exc}")
            return
        except IntegrityError as exc:
            done(False, f"数据校验失败：{exc}")
            return
        except PluginError as exc:
            done(False, f"插件错误：{exc}")
            return
        except Exception as exc:
            done(False, f"未知错误（{type(exc).__name__}）：{exc}")
            return

        delta = securemem.stats_delta(mem_before)
        note = (
            f"（敏感内存已清零 {delta['calls']} 处 / {delta['bytes']} 字节，任务结束前同步完成）"
            if delta["calls"] else ""
        )
        action = "加密" if spec["encrypt"] else "解密"
        done(True, f"{action}完成：{spec['dst']}（明文 {n:,} 字节）{note}")
    except Exception as exc:  # 加载插件等前置失败
        done(False, f"任务启动失败（{type(exc).__name__}）：{exc}")


def _cleanup_part(dst: str) -> None:
    try:
        Path(dst + ".part").unlink(missing_ok=True)
    except OSError:
        pass


def run_in_subprocess(
    spec: dict,
    on_event: Callable[[tuple], None],
    cancel_flag=None,
    poll: float = 0.15,
) -> Tuple[bool, str]:
    """在子进程中执行 spec 描述的任务，返回 (ok, message)。

    on_event 收到 ("progress", pct) / ("log", text, level) / ("keygen", pub, priv)。
    cancel_flag.is_set() 时硬终止子进程并清理 .part 文件。
    """
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    proc = ctx.Process(target=_child_job, args=(q, spec), daemon=True)
    proc.start()
    while True:
        try:
            event = q.get(timeout=poll)
        except queue_mod.Empty:
            if cancel_flag is not None and cancel_flag.is_set():
                proc.terminate()
                proc.join(2)
                if spec.get("dst"):
                    _cleanup_part(spec["dst"])
                return False, "已取消：用户取消。"
            if not proc.is_alive():
                # 给收尾事件一次机会（子进程可能在退出前刚放入 done）
                try:
                    event = q.get(timeout=0.5)
                except queue_mod.Empty:
                    return False, f"任务子进程异常退出（exitcode={proc.exitcode}）。"
            else:
                continue
        if event[0] == "done":
            proc.join(2)
            return event[1], event[2]
        on_event(event)
