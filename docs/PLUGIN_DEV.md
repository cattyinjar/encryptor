# 插件开发指南

本文面向想为本软件编写加密算法插件的开发者。不需要改动主程序任何一行代码——
把插件放进 `plugins/` 目录，点一下"重新扫描"，新算法就会出现在 GUI 下拉框里。

- 容器格式（`.encx` 文件如何组织头部/密文/元数据）见 [FORMAT.md](FORMAT.md)
- SDK 源码即权威参考：[encryptor/sdk.py](../encryptor/sdk.py)
- 现成范例：[plugins/xor_stream/plugin.py](../plugins/xor_stream/plugin.py)（教学模板）、
  [plugins/aes256_gcm/plugin.py](../plugins/aes256_gcm/plugin.py)（工业级实现）

## 1. 插件的两种形态

| 形态 | 布局 | 适用 |
|------|------|------|
| 单文件插件 | `plugins/my_cipher.py` | 简单算法、快速试验 |
| 目录插件 | `plugins/my_cipher/plugin.py`（或 `__init__.py`）+ 任意附带模块/资源 | 正式发布 |

要求：模块顶层必须有一个名为 **`Plugin`** 的类；目录/文件名不要以 `.` 或 `_` 开头
（会被扫描器跳过，`_` 前缀可用来临时停用一个插件）。

## 2. Plugin 类

```python
from encryptor.sdk import (
    CryptoPlugin, PluginError, WrongPasswordError, IntegrityError,
)

class Plugin(CryptoPlugin):
    # ---- 元数据（必填：id / name / version）----
    id = "my-cipher"            # 见下方"插件 id 规则"
    name = "我的算法"             # 下拉框显示名
    version = "1.0.0"
    author = "你的名字"
    description = "一句话算法说明，显示在界面上"

    # ---- 可选配置 ----
    requires_password = True    # False 时 GUI 自动隐藏密码框，password 参数传 None
    # password_hint = "口令"     # 预留

    # ---- 两个必须实现的方法 ----
    def encrypt_stream(self, src, dst, password, on_progress) -> bytes:
        ...

    def decrypt_stream(self, metadata, src, dst, password, on_progress) -> None:
        ...
```

> 框架按鸭子类型校验：不继承 `CryptoPlugin` 也能加载，但继承后可以直接使用
> `self.derive_key()` 工具函数。

### 插件 id 规则（重要）

- 仅允许 `小写字母 数字 - _ .`，以字母或数字开头，长度 ≤ 64；
- **id 会被写进每个加密文件的头部**。发布后一旦有人用你的插件加密了文件，
  再改 id 会导致这些文件无法解密——请把 id 当作永久标识；
- 与已有插件重复的 id 会被拒绝加载。

## 3. 两个流式方法的契约

框架已替你处理好 `.encx` 容器：头部、元数据存放、密文区间定位全部不用管。
你拿到的 `src` / `dst` 都是二进制文件对象：

### encrypt_stream(src, dst, password, on_progress) → bytes

- 循环 `src.read(块大小)` 读明文直到 EOF，把**密文**连续写入 `dst`；
- **每处理一批数据必须调用 `on_progress(n)`**，`n` 是本批明文字节数。
  它驱动进度条，也是取消机制的触发点（用户取消时它会抛 `CancelledError`，
  不用捕获，让它自然向外抛即可）；
- 返回值 = **元数据 blob**（任意 bytes，建议 ≤ 数 KB）。盐、nonce、认证标签、
  原文长度等解密所需信息都放这里，框架会把它存进文件、解密时原样还给你。

### decrypt_stream(metadata, src, dst, password, on_progress)

- `metadata`：加密时你返回的 blob；
- `src` 只能读到密文本身（框架已把头尾剥掉），读到 EOF 为止；
- 把明文连续写入 `dst`；
- 密码错误 → 抛 `WrongPasswordError`；数据被篡改/损坏/不完整 → 抛 `IntegrityError`。
  两者的消息会原样展示给用户。

### 其他约定

- **流式处理**：不要一次性读入整个文件（`src.read()` 不带参数只允许用于小文件
  测试），按块读写，大文件（GB 级）才不会爆内存；
- **`src.read(n)` 可能返回不足 n 字节**（EOF 前的正常现象），需要精确块对齐时
  请像示例插件那样实现 `_read_exact`；
- 每次加/解密任务都会调用你的两个方法各一次；GUI 中不会并发调用，但请不要
  在实例属性里存放跨任务状态。

## 4. 可用的工具与异常

| 名称 | 用途 |
|------|------|
| `CryptoPlugin.derive_key(password, salt, length, iterations)` | PBKDF2-HMAC-SHA256 密钥派生（标准库），盐务必 `os.urandom(16)` 随机生成并存入元数据 |
| `WrongPasswordError` | 解密时密码错误/认证失败 |
| `IntegrityError` | 数据损坏、被篡改、被截断 |
| `PluginError` | 基类；也可直接抛它显示自定义错误 |
| `CancelledError` | 框架内部使用；不要在插件里捕获它 |

依赖第三方库（如 `cryptography`）时，把 import 放模块顶部并给出友好提示：

```python
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    raise ImportError("本插件依赖 cryptography，请执行: pip install cryptography") from exc
```

依赖缺失只会让**这一个插件**标记为"加载失败"（原因显示在插件页），不影响程序和其他插件。

## 5. 调试工作流

1. 写好插件放入 `plugins/`；
2. 启动软件或点击 **插件页 → 重新扫描插件**；
3. 加载失败会在插件页和日志面板看到具体原因（异常类型 + 消息）；
4. 成功后直接在加密页选用你的算法，加密→解密做往返验证；
5. 也可以写脚本直接驱动引擎做自动化测试：

```python
import sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
from encryptor import plugin_manager, engine

reg = plugin_manager.scan_plugins()
mine = reg.find("my-cipher")
tmp = Path(tempfile.mkdtemp())
src = tmp / "a.bin"; src.write_bytes(b"hello" * 1000)

engine.encrypt_file(mine, src, tmp / "a.bin.encx", "pw")
engine.decrypt_file(mine, tmp / "a.bin.encx", tmp / "a.out", "pw")
assert (tmp / "a.out").read_bytes() == src.read_bytes()
print("往返 OK")
```

## 6. 发布插件

目录插件整个文件夹（或打成 zip 解压到 `plugins/`）拷贝到目标机器的
`plugins/` 目录，重新扫描即可使用。建议随插件附带 `README`，注明算法、
密钥派生方式与已知限制。
