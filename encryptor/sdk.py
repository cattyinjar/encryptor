"""插件开发 SDK。

加密算法以"插件"的形式接入本软件。一个插件就是一个 Python 类，实现
``encrypt_stream`` / ``decrypt_stream`` 两个流式方法即可被框架加载使用。

插件通过::

    from encryptor.sdk import CryptoPlugin, WrongPasswordError, IntegrityError

引用本模块（框架保证项目根目录在 ``sys.path`` 中）。

框架按"鸭子类型"校验插件：即使不继承 ``CryptoPlugin``，只要具备
``id/name/version/encrypt_stream/decrypt_stream`` 也能加载；但继承基类
可以直接获得 ``derive_key`` 等工具函数。
"""

from __future__ import annotations

import hashlib
from typing import BinaryIO, Callable, Optional

# 插件在 on_progress 中收到的回调类型：传入本调用处理的字节数
ProgressFn = Callable[[int], None]


class PluginError(Exception):
    """插件相关错误的基类。插件可抛出它向用户展示自定义错误信息。"""


class WrongPasswordError(PluginError):
    """密码错误（解密时无法通过认证）。"""


class IntegrityError(PluginError):
    """密文数据损坏、被篡改或不完整。"""


class DependencyError(PluginError):
    """插件依赖的第三方库缺失（在模块导入阶段抛出）。"""


class CancelledError(PluginError):
    """用户取消了任务（框架内部使用，插件一般不需要主动抛出）。"""


class CryptoPlugin:
    """加密插件基类。

    生命周期：每次扫描/刷新时，框架导入插件模块并实例化该类一次，
    之后复用同一实例（GUI 非多线程并发调用，实例可保有状态，但建议
    不要在实例上保存跨任务的临时数据）。

    类属性（子类必须覆盖带注释"必填"的项）：

        id                必填。插件唯一标识，仅小写字母/数字/``-``/``_``。
                          会被写入加密文件头，一经发布请勿更改，否则旧文件无法解密。
        name              必填。显示名称。
        version           必填。版本号字符串，如 "1.0.0"。
        author            作者。
        description       一句话描述，显示在 GUI 中。
        requires_password 是否需要用户输入密码。False 时 GUI 会隐藏密码框。
        password_hint     密码输入框的提示文字。
    """

    id: str = ""
    name: str = ""
    version: str = ""
    author: str = ""
    description: str = ""
    requires_password: bool = True
    password_hint: str = "密码"

    # ---- 工具函数（子类可直接使用） ---------------------------------

    @staticmethod
    def derive_key(
        password: str,
        salt: bytes,
        length: int,
        iterations: int = 200_000,
        hash_name: str = "sha256",
    ) -> bytes:
        """由密码派生密钥（PBKDF2-HMAC，标准库实现）。

        :param password: 用户输入的密码（str，框架已保证非空）
        :param salt:     随机盐（至少 16 字节，务必随机生成并存入元数据）
        :param length:   派生密钥字节数
        :param iterations: 迭代次数，建议 >= 100_000
        """
        return hashlib.pbkdf2_hmac(hash_name, password.encode("utf-8"), salt, iterations, dklen=length)

    # ---- 插件必须实现的两个方法 --------------------------------------

    def encrypt_stream(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> bytes:
        """加密：从 ``src`` 循环读取明文直到 EOF，把密文写入 ``dst``。

        :returns: 元数据 blob（bytes）。框架会把它存进文件头/尾，解密时
                  原样传回 ``decrypt_stream``。请存放盐、nonce、认证标签
                  等解密必需的信息。返回 ``b""`` 表示无元数据。
        :param on_progress: 每处理一批数据调用一次 ``on_progress(n)``，
                            ``n`` 为本次处理的**明文**字节数。框架据此更新
                            进度条并在用户取消时抛出 CancelledError。
        :raises WrongPasswordError / IntegrityError: 加密阶段一般不会抛。
        """
        raise NotImplementedError

    def decrypt_stream(
        self,
        metadata: bytes,
        src: BinaryIO,
        dst: BinaryIO,
        password: Optional[str],
        on_progress: ProgressFn,
    ) -> None:
        """解密：``src`` 中只有密文载荷（框架已剥离容器头和元数据），
        从中循环读取直到 EOF，把明文写入 ``dst``。

        :param metadata: 加密时返回的元数据 blob 原文。
        :raises WrongPasswordError: 密码错误。
        :raises IntegrityError:     数据损坏、被篡改或不完整。
        """
        raise NotImplementedError
