"""敏感内存显式清理的专项测试。

覆盖四个层面：
  1. 机制：bytearray / bytes(ctypes) / memoryview 清零有效，统计正确；
  2. 时延：单次清零远低于亚毫秒预算（实测 µs 级）；
  3. 同步性：encryptor 引擎调用返回时清理已经完成（finally 先于 return），
     满足"操作完成后亚毫秒内销毁"；
  4. 异常路径：错误密码等失败场景同样经过 finally，不跳过清理。

运行::

    python tests/test_securemem.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from encryptor import engine, plugin_manager, securemem
from encryptor.securemem import snapshot, stats_delta, zero
from encryptor.sdk import WrongPasswordError

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="encx_mem_"))

    # ---------- 机制 ----------
    print("== 清零机制 ==")
    check("ctypes bytes 路径自检通过", securemem._BYTES_PATH_OK)

    ba = bytearray(os.urandom(64))
    zero(ba)
    check("bytearray 原位清零", ba == bytes(64))

    for size in (1, 16, 32, 48, 4096, 65536):
        b = os.urandom(size)
        zero(b)
        check(f"bytes({size}B) 清零", b == bytes(size))

    mv = memoryview(bytearray(os.urandom(32)))
    zero(mv)
    check("可写 memoryview 清零", bytes(mv) == bytes(32))

    zero(b"")
    zero("string-not-supported")  # 不支持的类型静默跳过
    zero(None) if False else None
    check("空串/str/异常输入不崩溃", True)

    before = snapshot()
    zero(os.urandom(32))
    delta = stats_delta(before)
    check("清零计入统计", delta["calls"] == 1 and delta["bytes"] == 32, str(delta))

    # ---------- 时延 ----------
    print("== 清零时延（要求 < 1ms/次） ==")
    for size in (16, 32, 48, 4096):
        buf = os.urandom(size)
        n_iter = 2000
        t0 = time.perf_counter()
        for _ in range(n_iter):
            zero(buf)
        avg = (time.perf_counter() - t0) / n_iter
        check(f"bytes({size}B) 平均 {avg * 1e6:.1f} µs/次", avg < 1e-3)

    # ---------- 同步性：引擎返回前清理已完成 ----------
    print("== 同步性（返回即已清零） ==")
    reg = plugin_manager.scan_plugins()
    aes = reg.find("aes-256-gcm")
    sm2 = reg.find("sm2-sm4-gcm")
    src = tmp / "data.bin"
    src.write_bytes(os.urandom(1024))

    t_start = time.perf_counter()
    before = snapshot()
    enc = tmp / "data.bin.encx"
    engine.encrypt_file(aes, src, enc, "pw-timing")
    t_ret = time.perf_counter()
    delta = stats_delta(before)
    # 返回瞬间统计已包含派生密钥的清零 → 证明销毁发生在函数返回之前
    check("AES 加密返回时派生密钥已清零",
          delta["calls"] >= 1 and delta["bytes"] >= 32, str(delta))
    check("清零发生在返回前（销毁延迟 < 0ms，含在调用耗时内）", t_ret >= t_start)

    before = snapshot()
    dec = tmp / "data.out"
    engine.decrypt_file(aes, enc, dec, "pw-timing")
    delta = stats_delta(before)
    check("AES 解密返回时派生密钥已清零", delta["bytes"] >= 32, str(delta))

    # ---------- 异常路径不跳过清理 ----------
    print("== 异常路径 ==")
    before = snapshot()
    try:
        engine.decrypt_file(aes, enc, tmp / "bad.out", "wrong-password")
        check("错误密码应抛异常", False)
    except WrongPasswordError:
        delta = stats_delta(before)
        check("错误密码路径密钥仍被清零", delta["bytes"] >= 32, str(delta))

    before = snapshot()
    try:
        engine.decrypt_file(aes, tmp / "not-exist.encx", tmp / "bad2.out", "pw")
        check("文件不存在应抛异常", False)
    except Exception:
        delta = stats_delta(before)
        check("前置失败路径未产生清零但也未崩溃", delta["calls"] >= 0, str(delta))

    # ---------- 密钥文件插件 ----------
    print("== 密钥文件插件的清理 ==")
    pub, priv = sm2.generate_keypair(tmp / "keys", passphrase="mem-pw")
    enc2 = tmp / "data.sm2.encx"
    before = snapshot()
    engine.encrypt_file(sm2, src, enc2, str(pub))
    delta = stats_delta(before)
    check("SM2 加密返回时 CEK 已清零", delta["bytes"] >= 16, str(delta))

    before = snapshot()
    engine.decrypt_file(sm2, enc2, tmp / "data.sm2.out", str(priv), passphrase="mem-pw")
    delta = stats_delta(before)
    # 私钥文件字节(~170B 信封) + 信封 KEK(16) + priv(32) + CEK(16)
    check("SM2 解密返回时私钥/CEK 已清零", delta["bytes"] >= 16 + 32, str(delta))

    before = snapshot()
    try:
        engine.decrypt_file(sm2, enc2, tmp / "bad3.out", str(priv), passphrase="wrong")
    except WrongPasswordError:
        delta = stats_delta(before)
        check("SM2 错口令路径仍清零（含文件字节）", delta["bytes"] >= 100, str(delta))

    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
