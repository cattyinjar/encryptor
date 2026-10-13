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

所有插件均基于**元数据 v2**：块级 AAD 绑定插件 id、元数据尾 MAC 认证全部
字段（含总长，杜绝"无声截断"）、KDF 参数自描述、默认迭代 600k（OWASP 2023）。

| 插件 | 凭据 | 说明 |
|------|------|------|
| `aes-256-gcm` | 密码 | PBKDF2 派生双密钥 + 逐块 AES-GCM + 元数据 MAC，日常使用推荐 |
| `xor-stream` | 密码 | 教学示例：SHA-256 密钥流 + HMAC 完整性 + 口令预验证 |
| `rsa-oaep-aes256gcm` | **密钥文件** | 混合加密：随机 AES 密钥加密文件，RSA-3072 公钥（OAEP）保护该密钥 |
| `ecdh-aes256gcm` | **密钥文件** | 混合加密（ECIES 风格）：临时密钥 ECDH + HKDF 保护随机 AES 密钥 |
| `sm4-gcm` | 密码 | 国密对称认证加密：PBKDF2-HMAC-SM3 + 逐块 SM4-GCM |
| `sm3-stream` | 密码 | 国密教学示例：SM3 密钥流 + HMAC-SM3 完整性 |
| `sm2-sm4-gcm` | **密钥文件** | 国密套件：SM2 公钥（自实现，CSPRNG + C1 曲线校验 + C3 校验）保护 SM4 内容密钥 |

全部插件依赖仅 `cryptography`（国密插件亦然——SM2 v2 起自实现曲线运算，
不再依赖 gmssl；gmssl 仅在测试中用于交叉验证）。

公钥类插件会在任务日志中显示密钥强度（如 `RSA-3072（约 128 位安全强度）`），
并在加载时强制强度下限：RSA 低于 2048 位、ECC 曲线低于 256 位会被拒绝。

## 敏感内存清理与进程隔离（多层防御）

**第一层：任务子进程（结构性）**。GUI 的全部密钥操作——加密/解密、密钥对
生成、密钥强度描述——都在**短命子进程**中执行（`encryptor/jobrunner.py`），
任务结束子进程退出，其地址空间（含第三方库内部的密钥副本）随之消亡。
实测验证（`tests/test_subprocess_isolation.py`）：经该路径完成解密后，
编排进程的全内存镜像中 ECC 私钥的**全部内存表示 0 命中**（修复前 2/3 概率
残留完整 PKCS#8 DER）；代价是每任务约 0.1–0.3s 的子进程启动开销。

**第二层：插件内显式清零**（`encryptor/securemem.py`）。密钥材料在流式方法
返回**之前**于 `finally` 中同步清零（微秒级，异常/取消路径不跳过），任务
日志报告清零统计——防的是子进程存活期间的内存 dump。

**诚实的能力边界**：`str` 口令在任务期间必然存在于父进程（发送给子进程的
参数），子进程存活期间也可被 dump——进程模型保证的是"任务结束即不可达"，
不是"从未存在"；页面文件/休眠文件/文件缓存属 OS 层，请配合全盘加密。
对内存取证级对手，请考虑原生实现（libsodium 类）工具。

红队审计（`attack_lab/`）后的主要加固见 `docs/REMEDIATION_PLAN.md`：
SM2 随机数/C1/C3 修复、全部插件元数据 v2（trailer MAC 杜绝无声截断）、
KDF 600k 自描述、口令策略（加密侧 ≥8 位 + 弱口令表）、流插件完整性。

国密插件依赖 `cryptography`（SM3/SM4；SM2 为自实现）：

```bash
pip install cryptography
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
│   ├── sdk.py              # 插件开发 SDK：CryptoPlugin 基类、异常、derive_key、secure_zero、secure_random_int
│   ├── aead.py             # ★ 分块认证加密共享层（v2 元数据：AAD/MAC/自描述 KDF）
│   ├── container.py        # .encx 容器格式读写
│   ├── plugin_manager.py   # 插件发现、加载、隔离坏插件
│   ├── engine.py           # 加密/解密执行：临时文件、进度、取消
│   ├── jobrunner.py        # 任务子进程执行器（密钥材料不进 GUI 进程）
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
    ├── test_roundtrip.py             # 端到端测试（128 项，含 F1/F2/F3/F5 回归向量）
    ├── test_gui_smoke.py             # GUI 冒烟测试（35 项）
    ├── test_securemem.py             # 敏感内存清理专项（23 项）
    └── test_subprocess_isolation.py  # 子进程隔离取证验证（9 项）
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
