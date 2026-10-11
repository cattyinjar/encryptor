"""攻击实验室公共工具：加载插件、生成样本、解析容器。

本目录为安全审计代码（红队视角），不属于软件本体。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor import container, engine, plugin_manager  # noqa: E402
from encryptor.sdk import CryptoPlugin  # noqa: E402

LAB = Path(__file__).resolve().parent
SAMPLES = LAB / "samples"
KEYS = LAB / "keys"

PASSWORD_PLUGINS = ["aes-256-gcm", "xor-stream", "sm4-gcm", "sm3-stream"]
KEYFILE_PLUGINS = ["rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"]
ALL_PLUGINS = PASSWORD_PLUGINS + KEYFILE_PLUGINS

_registry = None


def registry() -> plugin_manager.PluginRegistry:
    global _registry
    if _registry is None:
        _registry = plugin_manager.scan_plugins()
        ok = {p.id for p in _registry.loaded}
        missing = set(ALL_PLUGINS) - ok
        assert not missing, f"插件加载失败: {missing}; 失败清单: {[ (f.source.name, f.reason) for f in _registry.failed]}"
    return _registry


def get(plugin_id: str) -> CryptoPlugin:
    p = registry().find(plugin_id)
    assert p is not None, f"插件 {plugin_id} 不可用"
    return p


def enc(src: Path, dst: Path, credential: str, plugin_id: str, passphrase=None) -> int:
    return engine.encrypt_file(get(plugin_id), src, dst, credential,
                               passphrase=passphrase)


def dec(src: Path, dst: Path, credential: str, plugin_id: str = None, passphrase=None):
    """解密；plugin_id 为 None 时按文件头自动路由（GUI 同款行为）。"""
    pid = plugin_id or engine.peek_plugin_id(src)
    return engine.decrypt_file(get(pid), src, dst, credential, passphrase=passphrase)


def parse(path: Path):
    """解析 .encx：返回 (plugin_id, header_len, payload, metadata)。"""
    data = path.read_bytes()
    assert data[:4] == b"ENCX"
    pid_len = int.from_bytes(data[5:7], "little")
    plugin_id = data[7 : 7 + pid_len].decode()
    header_len = 7 + pid_len
    meta_len = int.from_bytes(data[-4:], "little")
    payload = data[header_len:-4 - meta_len]
    metadata = data[-4 - meta_len : -4]
    return plugin_id, header_len, payload, metadata


def build_encx(plugin_id: str, payload: bytes, metadata: bytes) -> bytes:
    """攻击者工具：手工拼装 .encx 字节流。"""
    pid = plugin_id.encode()
    head = b"ENCX" + b"\x01" + len(pid).to_bytes(2, "little") + pid
    return head + payload + metadata + len(metadata).to_bytes(4, "little")
