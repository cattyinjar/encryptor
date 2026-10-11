"""攻击方独立实现的算法复刻（不 import 软件本体，模拟纯外部攻击者）。"""

from __future__ import annotations

import hashlib


def xor_keystream_prefix(key: bytes, salt: bytes, n: int) -> bytes:
    """复刻 xor-stream 插件密钥流：SHA256(key||salt||counter8BE) 拼接。"""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + salt + i.to_bytes(8, "big")).digest()
        i += 1
    return out[:n]
