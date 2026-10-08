"""``.encx`` 加密容器格式的读写。

文件布局（小端序）::

    +--------+---------+----------------------+-----------------+---------+----------+
    | MAGIC  | version | plugin_id_len(uint16)| plugin_id (utf8)| 密文载荷 | 元数据尾部|
    | 4 字节 | 1 字节  | 2 字节               | N 字节          | ...变长  | 见下      |
    +--------+---------+----------------------+-----------------+---------+----------+

    元数据尾部（trailer）::

        metadata (meta_len 字节, 插件自定义二进制) + meta_len (uint32)

元数据由加密插件在加密完成时返回（例如盐、nonce、认证标签），框架把它
追加到文件末尾；解密时先从尾部取出元数据，再把"纯密文区间"交给插件。

载荷长度 = 文件大小 - 头部 - 尾部，因此支持任意大小的流式处理。
"""

from __future__ import annotations

import io
import os
import struct
from typing import BinaryIO

from .sdk import IntegrityError

MAGIC = b"ENCX"
VERSION = 1

_HEADER_FIXED = struct.Struct("<4sB")   # MAGIC + 版本
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
# 尾部 meta_len 字段本身占 4 字节
_TRAILER_LEN_SIZE = 4


class ContainerError(IntegrityError):
    """不是有效的 .encx 文件，或容器结构损坏。"""


class BoundedReader(io.RawIOBase):
    """只允许读取底层流中 [start, end) 区间数据的包装器。

    插件通过它读到的"全部内容"就是密文载荷本身，看不到容器头部与元数据。
    """

    def __init__(self, src: BinaryIO, limit: int):
        self._src = src
        self._remaining = limit

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        if size is None or size < 0:
            size = self._remaining
        size = min(size, self._remaining)
        if size <= 0:
            return b""
        data = self._src.read(size)
        if not data:
            # 底层流提前结束 = 文件被截断
            self._remaining = 0
            return b""
        self._remaining -= len(data)
        return data


def write_header(dst: BinaryIO, plugin_id: str) -> None:
    """写出容器头部（含插件 id）。随后即可由插件连续写入密文载荷。"""
    pid = plugin_id.encode("utf-8")
    if len(pid) > 0xFFFF:
        raise ValueError("插件 id 过长")
    dst.write(_HEADER_FIXED.pack(MAGIC, VERSION))
    dst.write(_U16.pack(len(pid)))
    dst.write(pid)


def write_trailer(dst: BinaryIO, metadata: bytes) -> None:
    """密文写完后调用：把插件元数据与长度追加到文件末尾。"""
    if len(metadata) > 0xFFFFFFFF:
        raise ValueError("插件元数据过长")
    dst.write(metadata)
    dst.write(_U32.pack(len(metadata)))


class ContainerInfo:
    """解密前从文件头/尾探测到的容器信息。"""

    __slots__ = ("plugin_id", "metadata", "payload_start", "payload_len", "file_size")

    def __init__(self, plugin_id: str, metadata: bytes, payload_start: int, payload_len: int, file_size: int):
        self.plugin_id = plugin_id
        self.metadata = metadata
        self.payload_start = payload_start
        self.payload_len = payload_len
        self.file_size = file_size


def read_container(src: BinaryIO) -> ContainerInfo:
    """解析已打开（二进制模式）的 .encx 文件，返回容器信息。

    返回后 ``src`` 的读位置停在头部结束处（载荷起点）。
    抛出 ContainerError 表示文件不是本软件的加密文件或已损坏。
    """
    head = src.read(_HEADER_FIXED.size + _U16.size)
    if len(head) < _HEADER_FIXED.size:
        raise ContainerError("文件过短，不是有效的加密文件")
    magic, version = _HEADER_FIXED.unpack_from(head, 0)
    if magic != MAGIC:
        raise ContainerError("文件头不匹配：不是本软件创建的加密文件")
    if version != VERSION:
        raise ContainerError(f"不支持的容器版本 v{version}（本软件支持 v{VERSION}）")
    (pid_len,) = _U16.unpack_from(head, _HEADER_FIXED.size)
    if pid_len == 0 or pid_len > 256:
        raise ContainerError("容器头损坏：非法的插件 id 长度")
    pid_bytes = src.read(pid_len)
    if len(pid_bytes) != pid_len:
        raise ContainerError("容器头不完整")
    try:
        plugin_id = pid_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContainerError("容器头损坏：插件 id 解码失败") from exc

    payload_start = src.tell()

    # 从文件末尾读 trailer：最后 4 字节是 meta_len
    file_size = src.seek(0, os.SEEK_END)
    if file_size < payload_start + _TRAILER_LEN_SIZE:
        raise ContainerError("文件缺少元数据尾部，可能未完成加密或已损坏")
    src.seek(-_TRAILER_LEN_SIZE, os.SEEK_END)
    (meta_len,) = _U32.unpack(src.read(_TRAILER_LEN_SIZE))
    trailer_total = _TRAILER_LEN_SIZE + meta_len
    if file_size - payload_start < trailer_total:
        raise ContainerError("元数据长度超出文件范围，文件已损坏")
    metadata = b""
    if meta_len:
        src.seek(-(trailer_total), os.SEEK_END)
        metadata = src.read(meta_len)
        if len(metadata) != meta_len:
            raise ContainerError("读取元数据失败")

    payload_len = file_size - payload_start - trailer_total
    # 归位到载荷起点，供插件顺序读取
    src.seek(payload_start)
    return ContainerInfo(plugin_id, metadata, payload_start, payload_len, file_size)


def open_payload_reader(src: BinaryIO, info: ContainerInfo) -> BoundedReader:
    """返回限定在密文载荷区间的读取器（要求 src 已定位到载荷起点）。"""
    return BoundedReader(src, info.payload_len)
