# 打包指南（Windows 安装包）

产出标准 Windows 单机软件：PyInstaller（免依赖的 onedir 程序目录）+
Inno Setup（安装包、快捷方式、注册表注册）。`attack_lab/`、`tests/`
不会进入安装包（它们不被主程序引用，spec 中亦显式排除）。

## 一次性准备

```bash
pip install pyinstaller          # 本仓库已含 Inno Setup 6.x（ISCC）
```

Inno Setup 若未安装：`winget install JRSoftware.InnoSetup`，ISCC 默认在
`%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe`（用户级）或
`C:\Program Files (x86)\Inno Setup 6\ISCC.exe`（系统级）。

## 构建步骤（在仓库根目录）

```bash
# 1) 构建 exe（onedir），并把插件/文档/README 放到 exe 同目录
rm -rf build dist
python -m PyInstaller packaging/Encryptor.spec --noconfirm
cp -r plugins dist/Encryptor/plugins
cp -r docs    dist/Encryptor/docs
cp README.md  dist/Encryptor/

# 2) 冻结自检（退出码 0 = 通过；验证插件发现与子进程任务两大雷区）
(cd dist/Encryptor && ./Encryptor.exe --selftest)

# 3) 编译安装包 → packaging/installer/Encryptor-Setup-<版本>.exe
"/c/Users/DFN/AppData/Local/Programs/Inno Setup 6/ISCC.exe" packaging/encryptor.iss
```

发版前记得更新三处版本号：`encryptor/__init__.py`（`__version__`）、
`packaging/encryptor.iss`（`MyAppVersion`）、`packaging/version_info.txt`。

## 安装包行为

- **默认按机器安装**（管理员，`C:\Program Files\Encryptor`），也支持
  `/CURRENTUSER` 按用户安装；
- **注册表注册**：
  - 卸载项（"应用/设置 → 已安装的应用"可见，含版本/发布者/卸载命令）——
    Inno 自动写入（按机器 = HKLM，按用户 = HKCU）；
  - `HKLM\Software\Encryptor`：`InstallDir`、`Version`（仅按机器安装时）；
  - `.encx` 文件关联（可选任务，默认勾选）：双击加密文件 → 启动软件并
    定位到解密页、自动预填该文件与算法；
- 开始菜单快捷方式 + 可选桌面快捷方式；卸载时清理全部注册表项与文件。

## 注意事项（踩过的坑）

1. **`multiprocessing.freeze_support()`**：main.py 入口第一件事就是调用它，
   否则冻结模式下 jobrunner 的子进程任务会重复执行主程序而挂起；
2. **hiddenimports**：插件经 importlib 动态加载，PyInstaller 静态分析
   看不到 `cryptography`、`encryptor.aead` 等依赖，spec 中已列出；
3. **`CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1`**：plugin_manager 模块顶层设置
   （冻结环境捆绑的 OpenSSL 3 找不到 legacy provider 会直接崩；本软件
   不用任何 legacy 算法）；
4. **Git Bash 静默安装**：`/VERYSILENT` 等开关会被 MSYS 路径转换改写，
   需 `MSYS2_ARG_CONV_EXCL="*"` 前缀或改用 cmd 执行；
5. 构建前清理 `dist/Encryptor/selftest.log`（若曾运行过自检），避免
   打进安装包。

## 静默安装/卸载（自动化测试用）

```bash
MSYS2_ARG_CONV_EXCL="*" Encryptor-Setup-1.1.0.exe /VERYSILENT /CURRENTUSER \
    /SUPPRESSMSGBOXES /DIR="C:\somewhere" /NOICONS
MSYS2_ARG_CONV_EXCL="*" "C:\somewhere\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES
```
