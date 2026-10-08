# Encryptor — 单机文件加密解密工具（插件式架构）

一个完全离线运行的文件加密解密软件。任意类型文件（无论扩展名）都可以加密，
加密后统一添加本软件自有扩展名 **`.encx`**；解密后自动去掉该后缀还原原文件名。
加密算法以**插件**形式接入，可以随时添加新算法，无需改动主程序。

## 运行

要求 Python 3.10+（在 3.13 上测试通过）。

```bash
pip install cryptography     # 仅 AES-256-GCM 插件需要（强烈推荐安装）
python main.py               # 启动 GUI
```

不带 `cryptography` 也能运行：XOR 流加密插件为纯标准库实现，AES 插件会显示
"加载失败"并提示安装命令，不影响其他功能。

## 界面

| 页面 | 功能 |
|------|------|
| **加密** | 选择加密方式 → 选择待加密文件 → 选择保存位置 → 输入密码 → 开始加密。输出默认为 `原文件名.encx` |
| **解密** | 选择待解密文件（自动按文件头识别算法）→ 选择保存位置 → 输入密码 → 开始解密。输出默认为去掉 `.encx` 后的原文件名 |
| **插件** | 查看已加载/加载失败的插件清单（含失败原因），重新扫描插件、打开插件目录、查看开发指南 |

特性：进度显示、任务可取消、覆盖前确认、失败自动清理 `.part` 临时文件、
日志面板实时输出。任务在后台线程执行，不卡界面。

## 目录结构

```
encryptor/
├── main.py                 # 启动入口
├── encryptor/
│   ├── sdk.py              # 插件开发 SDK：CryptoPlugin 基类、异常、derive_key
│   ├── container.py        # .encx 容器格式读写
│   ├── plugin_manager.py   # 插件发现、加载、隔离坏插件
│   ├── engine.py           # 加密/解密执行：临时文件、进度、取消
│   └── app.py              # Tkinter GUI
├── plugins/                # ★ 插件目录（算法都在这里）
│   ├── aes256_gcm/         #   AES-256-GCM 分块认证加密（推荐）
│   └── xor_stream/         #   XOR 流加密（纯标准库，插件开发模板）
├── docs/
│   ├── PLUGIN_DEV.md       # ★ 插件开发指南
│   └── FORMAT.md           # .encx 容器格式说明
└── tests/
    ├── test_roundtrip.py   # 端到端测试（51 项）
    └── test_gui_smoke.py   # GUI 冒烟测试（11 项）
```

## 快速开发一个自己的加密插件

1. 在 `plugins/` 下新建 `my_cipher.py`（单文件）或 `my_cipher/plugin.py`（目录）；
2. 定义一个 `Plugin` 类，实现 `encrypt_stream` / `decrypt_stream`；
3. 启动软件（或点击"重新扫描插件"），新算法即出现在下拉框中。

```python
# plugins/my_cipher.py —— 最小可用插件
from encryptor.sdk import CryptoPlugin

class Plugin(CryptoPlugin):
    id = "my-cipher"          # 唯一且一经发布不可更改（会写进文件头）
    name = "我的算法"
    version = "0.1.0"
    description = "演示用最小插件"

    def encrypt_stream(self, src, dst, password, on_progress):
        data = src.read()
        dst.write(bytes(b ^ 0x5A for b in data))
        on_progress(len(data))
        return b""            # 元数据（盐/nonce 等），这里用不到

    def decrypt_stream(self, metadata, src, dst, password, on_progress):
        data = src.read()
        dst.write(bytes(b ^ 0x5A for b in data))
        on_progress(len(data))
```

完整 API、元数据用法、错误约定见 **[docs/PLUGIN_DEV.md](docs/PLUGIN_DEV.md)**。

## 安全说明

- 推荐使用 **AES-256-GCM** 插件：PBKDF2（200k 轮）派生密钥、逐块认证加密，
  可检测篡改与截断，错密码会在解密时报错而不是产出垃圾数据。
- `xor-stream` 仅作插件开发示例，无认证能力，请勿用于保护重要数据。

## 测试

```bash
python tests/test_roundtrip.py
python tests/test_gui_smoke.py
```

## 打包为独立 exe（可选）

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --add-data "plugins;plugins" --add-data "encryptor;encryptor" main.py
```

（如需把插件做成可插拔的外部目录，把 `plugins/` 放在 exe 旁并在
`plugin_manager.default_plugins_dir()` 中调整定位逻辑即可。）
