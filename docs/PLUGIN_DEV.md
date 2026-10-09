# 插件开发指南

本文面向想为本软件编写加密算法插件的开发者。不需要改动主程序任何一行代码——
把插件放进 `plugins/` 目录，点一下"重新扫描"，新算法就会出现在 GUI 下拉框里。

- 容器格式（`.encx` 文件如何组织头部/密文/元数据）见 [FORMAT.md](FORMAT.md)
- SDK 源码即权威参考：[encryptor/sdk.py](../encryptor/sdk.py)
- 现成范例：[plugins/xor_stream/plugin.py](../plugins/xor_stream/plugin.py)（密码模式·教学模板）、
  [plugins/aes256_gcm/plugin.py](../plugins/aes256_gcm/plugin.py)（密码模式·工业级）、
  [plugins/rsa_hybrid/plugin.py](../plugins/rsa_hybrid/plugin.py) 与
  [plugins/ecdh_hybrid/plugin.py](../plugins/ecdh_hybrid/plugin.py)（密钥文件模式·混合加密）

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

## 6. 密钥文件模式插件（credential_mode = "keyfile")

插件可以不用密码，改用**密钥文件**作为凭据（框架内置的 RSA / ECC 插件即此模式）。
只需在类上声明几组可选属性，GUI 会自动把密码输入框替换成密钥文件选择框：

```python
class Plugin(CryptoPlugin):
    id = "my-pki-cipher"
    # ...（id/name/version 照旧）...

    credential_mode = "keyfile"            # 关键声明：凭据是密钥文件路径
    encrypt_credential_hint = "公钥文件"    # 加密侧行标签（也可以是别的叫法）
    decrypt_credential_hint = "私钥文件"    # 解密侧行标签
    credential_filetypes = [("PEM 密钥文件", "*.pem"), ("所有文件", "*.*")]
    supports_keygen = True                 # 提供密钥对生成时 GUI 显示"生成密钥对…"按钮
```

行为约定：

- 凭据路径仍通过 `encrypt_stream` / `decrypt_stream` 的 **`password` 参数**传入
  （`Optional[str]`，此时语义是文件路径），插件自行读取与校验；
- 密钥文件读取/解析失败抛 `PluginError`（信息会直接展示给用户），
  私钥不匹配抛 `WrongPasswordError`；
- `supports_keygen = True` 时实现 `generate_keypair(dest_dir, passphrase=None)`，
  在目标目录生成 `(公钥, 私钥)` 两个文件并返回路径；已存在同名文件应抛
  `PluginError`。GUI 在子窗口中让用户选择是否给私钥设口令：给出口令时建议用
  `serialization.BestAvailableEncryption(口令)` 写出标准加密私钥
  （`BEGIN ENCRYPTED PRIVATE KEY`，openssl 互通），None 时写明文私钥；
- 声明 `keyfile_needs_passphrase = True` 表示"私钥可能带口令"：GUI 会在解密页
  的密钥文件下方追加一个"口令"输入框，并给两个流式方法额外传入
  `passphrase` 关键字参数（未输入为 None）——因此**声明了该标志的插件，
  `encrypt_stream` / `decrypt_stream` 都必须接受 `passphrase=None` 参数**
  （加密侧通常忽略它，因为公钥无口令）。加载私钥时建议：未给口令但文件
  加密 → 抛 `PluginError` 提示用户；口令错误 → 抛 `WrongPasswordError`；
  文件未加密但用户多输了口令 → 忽略口令直接加载；
- 元数据 blob 由插件独占使用，放什么都不限制（RSA 插件存了被包裹的内容密钥，
  ECC 插件存了临时公钥 + 包裹结果 + GCM 参数）；
- 可选实现 `describe_credential(credential, passphrase=None) -> str`：返回
  所选密钥文件的描述（如密钥类型与强度），GUI 在任务开始时写入日志。适合
  在此向用户展示密钥强度；也可以在密钥加载处设强度下限并抛 `PluginError`
  拒绝弱钥（参考 rsa_hybrid / ecdh_hybrid 的 `_ensure_strength`）。

### 非对称加密的标准套路：混合加密

RSA/ECC 公钥算法单次只能处理几十到几百字节，不能直接加密大文件，所有实用
实现（TLS、PGP、age……）都是混合结构，建议照抄：

```
CEK = os.urandom(32)                      # 1. 每次加密随机生成内容密钥
文件内容 ← 逐块 AES-256-GCM(CEK)          # 2. 对称加密大文件
元数据 ← 公钥保护 CEK                     # 3. RSA-OAEP 直接加密 CEK，
                                          #    或 ECDH+HKDF 派生 KEK 后 AES-GCM 包裹
```

完整参考实现：[plugins/rsa_hybrid/plugin.py](../plugins/rsa_hybrid/plugin.py)、
[plugins/ecdh_hybrid/plugin.py](../plugins/ecdh_hybrid/plugin.py)。

### 敏感内存清理（必须遵守）

插件持有的所有密钥材料——派生密钥、CEK、ECDH 共享秘密、从密钥文件读入的
私钥字节、逐块密钥流——**必须在 `finally` 块中用 `secure_zero()` 清零**
（`encryptor.sdk` 已 re-export，支持一次传多个缓冲区）：

```python
from encryptor.sdk import CryptoPlugin, secure_zero

def encrypt_stream(self, src, dst, password, on_progress):
    key = self.derive_key(password, salt, 32)
    try:
        ...  # 使用 key
        return metadata
    finally:
        secure_zero(key)          # 返回/抛异常前同步清零，微秒级
```

约定：清零不依赖 GC、不抛异常（内部尽力而为）；能覆盖的是 Python 侧缓冲区，
`str` 口令与第三方库内部副本无法清零（详见 README"敏感内存的显式清理"）。
GUI 会在任务日志中报告清零统计，`tests/test_securemem.py` 会验证"函数返回前
已完成清理"的时序。

## 7. 发布插件

目录插件整个文件夹（或打成 zip 解压到 `plugins/`）拷贝到目标机器的
`plugins/` 目录，重新扫描即可使用。建议随插件附带 `README`，注明算法、
密钥派生方式与已知限制。
