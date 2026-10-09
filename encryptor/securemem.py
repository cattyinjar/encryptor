"""敏感内存的显式清理（secure zeroization）。

目标：密钥、内容密钥（CEK）等敏感缓冲区在流式方法返回**之前**——即同步地、
在 ``finally`` 块中——被原位覆写为零。单次清零为微秒级（32 字节约 1µs），
不依赖垃圾回收，满足"操作完成后亚毫秒内销毁"的要求；异常与用户取消路径
同样经过 ``finally``，不会跳过清理。

CPython 下诚实的能力边界：

- ``bytearray`` / 可写 ``memoryview``：原位覆写，完全可靠；
- ``bytes``（不可变）：通过 ctypes 按 CPython ``PyBytesObject`` 布局定位
  数据区覆写。导入时用金丝雀自检，布局不符则自动降级为不处理（宁可不
  清零也不能写错内存）；
- ``str``（口令等）：不可变且可能驻留共享，无法可靠清零；插件能做的是
  清零自己经手的字节副本（``password.encode()`` 的结果）；
- 第三方库内部副本（OpenSSL 的密钥对象、gmssl 的十六进制私钥串）不受
  Python 层控制；
- 明文数据块不在清零范围（与磁盘上的原文件同级敏感度）；
- 操作系统层面（换页文件、休眠文件、崩溃转储）超出本机制，高威胁环境
  请配合全盘加密。

``zero()`` 维护清零统计（次数/字节数）：GUI 在任务结束时向用户报告，
测试用它验证"函数返回前已完成清理"这一时序保证。
"""

from __future__ import annotations

import ctypes
from typing import Dict

# CPython PyBytesObject 头部：ob_refcnt + ob_type + ob_size + ob_shash
# （64 位解释器为 8*4=32 字节，32 位为 4*4=16）
_BYTES_HEADER = ctypes.sizeof(ctypes.c_ssize_t) * 4

_stats: Dict[str, int] = {"calls": 0, "bytes": 0}


def _self_check() -> bool:
    """验证 ctypes 路径在当前解释器上可用（金丝雀字节串覆写校验）。"""
    try:
        probe = b"canary-ZERO-probe!"
        ctypes.memset(id(probe) + _BYTES_HEADER, 0, len(probe))
        return probe == bytes(len(probe))
    except Exception:
        return False


_BYTES_PATH_OK = _self_check()


def zero(buf) -> None:
    """立即原位清零一个敏感缓冲区（bytes / bytearray / 可写 memoryview）。

    尽力而为：任何失败都不抛异常——清理逻辑绝不掩盖业务错误；
    只有确实覆写成功才计入统计。
    """
    try:
        n = len(buf)
        if n == 0:
            return
        if isinstance(buf, bytearray):
            buf[:] = bytes(n)
        elif isinstance(buf, memoryview):
            if buf.readonly:
                return
            buf[:] = bytes(n)
        elif isinstance(buf, bytes):
            if not _BYTES_PATH_OK:
                return
            ctypes.memset(id(buf) + _BYTES_HEADER, 0, n)
        else:
            return
        _stats["calls"] += 1
        _stats["bytes"] += n
    except Exception:
        pass


def zero_all(*bufs) -> None:
    """依次清零多个缓冲区（便于在 finally 中一行调用）。"""
    for buf in bufs:
        zero(buf)


def snapshot() -> Dict[str, int]:
    """当前清零统计的快照 {"calls": n, "bytes": m}。"""
    return dict(_stats)


def stats_delta(before: Dict[str, int]) -> Dict[str, int]:
    """相对某个快照的增量。"""
    return {k: _stats[k] - before.get(k, 0) for k in _stats}
