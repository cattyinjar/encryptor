"""Encryptor 启动入口。

用法::

    python main.py                 # 启动 GUI
    python main.py 文件.encx       # 启动并定位到解密页（.encx 双击关联）
    Encryptor.exe --selftest       # 打包后自检（退出码 0 = 通过）
"""

import multiprocessing
import sys
from pathlib import Path

# 双击运行或从其他目录启动时，保证 encryptor 包可导入
_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def main() -> None:
    from encryptor.app import run_app

    open_file = None
    for arg in sys.argv[1:]:
        if not arg.startswith("-"):
            open_file = arg
            break
    run_app(open_file=open_file)


if __name__ == "__main__":
    # PyInstaller 冻结模式下 multiprocessing 子进程（jobrunner）依赖它：
    # 必须在任何业务逻辑之前调用，否则 spawn 的子进程会重复执行主程序
    multiprocessing.freeze_support()
    if "--selftest" in sys.argv[1:]:
        from encryptor.selftest import run_selftest

        sys.exit(run_selftest())
    main()
