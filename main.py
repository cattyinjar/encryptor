"""Encryptor 启动入口。

用法::

    python main.py        # 启动 GUI
"""

import sys
from pathlib import Path

# 双击运行或从其他目录启动时，保证 encryptor 包可导入
_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from encryptor.app import main

if __name__ == "__main__":
    main()
