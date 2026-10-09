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
| **加密** | 选择加密方式 → 选择待加密文件 → 选择保存位置 → 输入密码（或密钥文件）→ 开始加密。输出默认为 `原文件名.encx` |
| **解密** | 选择待解密文件（自动按文件头识别算法）→ 选择保存位置 → 输入密码（或私钥文件）→ 开始解密。输出默认为去掉 `.encx` 后的原文件名 |
| **插件** | 查看已加载/加载失败的插件清单（含失败原因），重新扫描插件、打开插件目录、查看开发指南 |

特性：进度显示、任务可取消、覆盖前确认、失败自动清理 `.part` 临时文件、
日志面板实时输出。任务在后台线程执行，不卡界面。

## 内置的七种算法

| 插件 | 凭据 | 说明 |
|------|------|------|
| `aes-256-gcm` | 密码 | PBKDF2 派生密钥 + 逐块 AES-GCM 认证加密，日常使用推荐 |
| `xor-stream` | 密码 | 纯标准库流加密，插件开发教学模板，无认证能力 |
| `rsa-oaep-aes256gcm` | **密钥文件** | 混合加密：随机 AES 密钥加密文件，RSA-3072 公钥（OAEP）保护该密钥；加密用公钥、解密用私钥 |
| `ecdh-aes256gcm` | **密钥文件** | 混合加密（ECIES 风格）：临时密钥 ECDH 协商 + HKDF 派生密钥保护随机 AES 密钥 |
| `sm4-gcm` | 密码 | 国密对称认证加密：PBKDF2-HMAC-SM3 派生密钥 + 逐块 SM4-GCM |
| `sm3-stream` | 密码 | 国密教学示例：SM3 计数器密钥流 XOR（无认证能力） |
| `sm2-sm4-gcm` | **密钥文件** | 国密套件混合加密：SM2 公钥保护随机 SM4 内容密钥（附 SM3 校验），文件逐块 SM4-GCM |

公钥类插件会在任务日志中显示密钥强度（如 `RSA-3072（约 128 位安全强度）`），
并在加载时强制强度下限：RSA 低于 2048 位、ECC 曲线低于 256 位会被拒绝。

## 敏感内存的显式清理

所有插件的密钥材料在使用完毕后**立即、同步**地从内存清零（`encryptor/securemem.py`）：

- 派生密钥、内容密钥（CEK）、ECDH 共享秘密、私钥文件内容字节、逐块密钥流，
  全部在 `finally` 块中清零——错误密码、数据损坏、用户取消等异常路径同样执行；
- 清零在流式方法**返回之前**完成（不依赖垃圾回收），单次耗时约 2 微秒，
  满足"操作完成后亚毫秒内销毁"；任务结束时日志会报告清零统计；
- 机制：`bytearray` 原位覆写；不可变 `bytes` 经 ctypes 按 CPython 对象布局
  覆写（导入时金丝雀自检，布局不符自动降级）。

**Python 环境下诚实的能力边界**（无法覆盖的部分）：`str` 口令（不可变、可能
驻留）无法可靠清零，只能清零插件经手的字节副本；OpenSSL/gmssl 库内部的密钥
对象副本不受 Python 层控制；换页文件/休眠文件/崩溃转储等 OS 层面需配合全盘
加密。对内存取证级对手，请考虑使用原生实现（如 libsodium）的工具。

国密插件依赖 `cryptography`（SM3/SM4），SM2 另需 `gmssl`：

```bash
pip install cryptography gmssl
```

**SM2 密钥文件格式说明**：SM2 插件使用 Encryptor 自有封装格式（标准 SM2
推荐曲线参数，`-----BEGIN SM2 PUBLIC KEY-----` 等），与 openssl 的 SM2
ASN.1 文件不直接互通；RSA/ECC 插件的密钥文件则与 openssl 完全互通。

**密钥文件插件用法**：选中算法后点击"生成密钥对…"，在子窗口中选择保存目录、
并决定**是否为私钥设置口令**（推荐设置；勾选后输入两次口令）。生成的是标准
PEM 密钥：`xxx_public_key.pem` / `xxx_private_key.pem`，与 openssl 互通用；带
口令的私钥文件本身是加密的（PBKDF2+AES 信封），即使文件被拷走也无法直接使用。
把公钥发给要给你发文件的人，自己保留私钥和口令。加密方选公钥文件加密，你用
私钥文件解密（若设了口令，解密时还需在"口令"栏输入）。

公钥可以任意分发；私钥与口令务必妥善保管——**私钥或口令丢失则密文永久无法
解开**。

RSA/ECC 密钥也可以直接用 openssl 生成：

```bash
openssl genrsa -out rsa_private_key.pem 3072
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
openssl ecparam -name prime256v1 -genkey -noout -out ecc_private_key.pem
openssl ec -in ecc_private_key.pem -pubout -out ecc_public_key.pem
```

## 目录结构

```
encryptor/
├── main.py                 # 启动入口
├── encryptor/
│   ├── sdk.py              # 插件开发 SDK：CryptoPlugin 基类、异常、derive_key、secure_zero
│   ├── container.py        # .encx 容器格式读写
│   ├── plugin_manager.py   # 插件发现、加载、隔离坏插件
│   ├── engine.py           # 加密/解密执行：临时文件、进度、取消
│   ├── securemem.py        # 敏感内存显式清理（secure zeroization）
│   └── app.py              # Tkinter GUI
├── plugins/                # ★ 插件目录（算法都在这里）
│   ├── aes256_gcm/         #   密码模式：AES-256-GCM 分块认证加密（推荐）
│   ├── xor_stream/         #   密码模式：XOR 流加密（纯标准库，开发模板）
│   ├── rsa_hybrid/         #   密钥文件模式：RSA-OAEP + AES-GCM 混合加密
│   ├── ecdh_hybrid/        #   密钥文件模式：ECDH + HKDF + AES-GCM（ECIES 风格）
│   ├── sm4_gcm/            #   密码模式：国密 SM4-GCM
│   ├── sm3_stream/         #   密码模式：国密 SM3 密钥流（教学示例）
│   └── sm2_hybrid/         #   密钥文件模式：国密 SM2 混合加密
├── docs/
│   ├── PLUGIN_DEV.md       # ★ 插件开发指南
│   └── FORMAT.md           # .encx 容器格式说明
└── tests/
    ├── test_roundtrip.py   # 端到端测试（114 项）
    ├── test_gui_smoke.py   # GUI 冒烟测试（32 项）
    └── test_securemem.py   # 敏感内存清理专项测试（23 项）
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
