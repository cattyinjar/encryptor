"""Encryptor — 单机文件加密解密工具（插件式架构）。

包结构：
    sdk             插件开发 SDK（插件继承/引用的基类与异常）
    container       .encx 加密容器格式的读写
    plugin_manager  插件发现、加载、校验
    engine          加密/解密任务执行（临时文件、进度、取消）
    app             Tkinter GUI
"""

__version__ = "1.0.0"

APP_NAME = "Encryptor"
# 本软件自有的加密文件扩展名
ENC_EXTENSION = ".encx"
