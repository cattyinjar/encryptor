"""插件发现与加载。

插件目录约定（``<项目根>/plugins/``）::

    plugins/
        my_cipher.py                # 单文件插件：模块内定义类 Plugin
        my_cipher_v2/               # 目录插件：内含 plugin.py（或 __init__.py）
            plugin.py               #   模块内同样定义类 Plugin
            ...                     #   可附带任意私有模块/资源

两种形式都要求模块顶层暴露一个名为 ``Plugin`` 的类（见 encryptor/sdk.py）。

加载失败（语法错误、依赖缺失、接口不合法……）不会影响程序和其他插件，
失败原因会记录下来并展示在 GUI 的"插件"页，便于算法开发者排查。
"""

from __future__ import annotations

import importlib.util
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .sdk import CryptoPlugin

_VALID_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_REQUIRED_METHODS = ("encrypt_stream", "decrypt_stream")

# 每次重新扫描时递增，保证热重载时模块名不冲突
_load_seq = 0


@dataclass
class LoadedPlugin:
    plugin: CryptoPlugin
    source: Path          # 插件源码入口文件

    @property
    def id(self) -> str:
        return self.plugin.id

    @property
    def display_name(self) -> str:
        return f"{self.plugin.name} v{self.plugin.version}"


@dataclass
class FailedPlugin:
    source: Path
    reason: str


@dataclass
class PluginRegistry:
    """一次扫描的结果。"""

    loaded: List[LoadedPlugin] = field(default_factory=list)
    failed: List[FailedPlugin] = field(default_factory=list)

    def find(self, plugin_id: str) -> Optional[CryptoPlugin]:
        for item in self.loaded:
            if item.id == plugin_id:
                return item.plugin
        return None

    def get(self, plugin_id: str) -> Optional[LoadedPlugin]:
        for item in self.loaded:
            if item.id == plugin_id:
                return item
        return None


def default_plugins_dir() -> Path:
    """插件目录 = 项目根目录下的 plugins/。"""
    return Path(__file__).resolve().parent.parent / "plugins"


def _ensure_sdk_importable() -> None:
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)


def _module_entry(path: Path) -> Optional[Path]:
    """返回插件入口源码文件；不是插件则返回 None。"""
    if path.is_file() and path.suffix == ".py" and path.name != "__init__.py":
        return path
    if path.is_dir():
        for candidate in ("plugin.py", "__init__.py"):
            entry = path / candidate
            if entry.is_file():
                return entry
    return None


def _validate_plugin_class(cls, source: Path) -> CryptoPlugin:
    """校验 Plugin 类的静态元数据与接口，通过则返回实例。"""
    pid = getattr(cls, "id", "")
    name = getattr(cls, "name", "")
    version = getattr(cls, "version", "")
    if not pid or not name or not version:
        raise ValueError("Plugin 类缺少必填属性 id / name / version")
    if not _VALID_ID.match(pid):
        raise ValueError(
            f"插件 id '{pid}' 不合法（仅允许小写字母、数字、'-'、'_'、'.'，且以字母或数字开头）"
        )
    for method in _REQUIRED_METHODS:
        if not callable(getattr(cls, method, None)):
            raise ValueError(f"Plugin 类未实现方法 {method}()")
    instance = cls()
    if not isinstance(instance, CryptoPlugin):
        # 鸭子类型兜底：不继承基类也允许，但需要补齐布尔属性
        if not hasattr(instance, "requires_password"):
            instance.requires_password = True  # type: ignore[attr-defined]
    return instance


def scan_plugins(plugins_dir: Optional[Path] = None) -> PluginRegistry:
    """扫描并加载插件目录，返回注册表。线程安全。"""
    global _load_seq
    with threading.Lock():
        _load_seq += 1
        seq = _load_seq

    _ensure_sdk_importable()
    registry = PluginRegistry()
    directory = Path(plugins_dir) if plugins_dir else default_plugins_dir()
    if not directory.is_dir():
        registry.failed.append(FailedPlugin(directory, "插件目录不存在"))
        return registry

    seen_ids: Dict[str, Path] = {}
    for path in sorted(directory.iterdir()):
        if path.name.startswith((".", "_")):
            continue
        entry = _module_entry(path)
        if entry is None:
            continue
        try:
            module_name = f"_encx_plugin_{seq}_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, entry)
            if spec is None or spec.loader is None:
                raise ImportError(f"无法为 {entry} 创建导入器")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            cls = getattr(module, "Plugin", None)
            if cls is None:
                raise AttributeError("模块中没有定义名为 Plugin 的类")
            instance = _validate_plugin_class(cls, entry)

            if instance.id in seen_ids:
                raise ValueError(
                    f"插件 id '{instance.id}' 与 {seen_ids[instance.id]} 重复"
                )
            seen_ids[instance.id] = entry
            registry.loaded.append(LoadedPlugin(instance, entry))
        except Exception as exc:  # 单个插件失败不影响其他插件
            reason = f"{type(exc).__name__}: {exc}"
            registry.failed.append(FailedPlugin(entry or path, reason))
    return registry
