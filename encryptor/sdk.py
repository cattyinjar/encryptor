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

from .securemem import zero_all as secure_zero

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

    # ---- 密钥文件模式（可选，默认关闭） -------------------------------
    # credential_mode = "password"：GUI 显示密码输入框（默认行为，凭据是密码字符串）；
    # credential_mode = "keyfile"  ：GUI 把凭据输入框替换为"密钥文件"选择框
    #                               （取消掩码、附加浏览按钮），凭据字符串是文件路径。
    # 无论哪种模式，凭据都通过 encrypt_stream / decrypt_stream 的 password 参数传入。
    credential_mode: str = "password"
    encrypt_credential_hint: str = "密钥文件"   # 加密侧（通常是公钥文件）的行标签
    decrypt_credential_hint: str = "密钥文件"   # 解密侧（通常是私钥文件）的行标签
    credential_filetypes = [("PEM 密钥文件", "*.pem"), ("所有文件", "*.*")]  # 文件对话框过滤
    supports_keygen: bool = False              # True 时 GUI 显示"生成密钥对"按钮
    # keyfile_needs_passphrase = True 时：GUI 在解密页的密钥文件行下方追加一个
    # "口令"输入框，框架调用 encrypt_stream / decrypt_stream 时会额外传入
    # passphrase 关键字参数（用户输入的口令，未输入为 None）。声明了本标志的
    # 插件，两个流式方法都必须接受该参数（加密侧通常忽略它，因为公钥无口令）。
    keyfile_needs_passphrase: bool = False

    # ---- 工具函数（子类可直接使用） ---------------------------------

    def describe_credential(self, credential, passphrase=None) -> str:
        """密钥文件插件可选实现：返回所选密钥文件的人类可读描述
        （如 ``"RSA-3072（约 128 位安全强度）"``）。

        GUI 在任务开始时调用并把结果写入日志，便于用户确认密钥强度。
        实现应当轻量、尽力而为：抛出异常或返回空串时 GUI 静默忽略。
        """
        return ""

    def generate_keypair(self, dest_dir, passphrase=None):
        """密钥文件插件可选实现：在 ``dest_dir`` 下生成一对密钥文件，
        返回 ``(公钥路径, 私钥路径)``。

        :param passphrase: 私钥保护口令。给出时私钥文件以标准加密格式写出
                           （PBKDF2 派生密钥 + AES 信封，PEM 头为
                           ``BEGIN ENCRYPTED PRIVATE KEY``）；为 None 时写出
                           明文私钥（``BEGIN PRIVATE KEY``）。公钥始终明文。

        GUI 在 ``supports_keygen = True`` 时显示"生成密钥对"按钮并调用本方法。
        默认不支持（抛 NotImplementedError）。
        """
        raise NotImplementedError(f"{self.name} 不支持自动生成密钥对")

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

        返回值为 ``bytes``——用完必须在 ``finally`` 中 ``secure_zero(key)``
        显式清零（本模块已 re-export 该函数）。同理，CEK、ECDH 共享秘密、
        从密钥文件读入的私钥字节等都属于必须清零的敏感缓冲区。
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
