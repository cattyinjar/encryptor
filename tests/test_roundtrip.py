"""端到端测试：插件加载、加密解密往返、完整性/密码校验、命名规则、容器格式。

运行::

    python tests/test_roundtrip.py
"""

import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from encryptor import engine, plugin_manager
from encryptor.container import ContainerError
from encryptor.sdk import IntegrityError, WrongPasswordError

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


def md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_samples(tmp: Path):
    samples = {
        "empty.bin": b"",
        "one_byte.txt": b"x",
        "text.txt": "你好，Encryptor！hello world.\n" * 500,
        "big_random.bin": os.urandom(1024 * 1024 * 2 + 12345),  # 跨多个 AES 块
    }
    paths = {}
    for name, data in samples.items():
        p = tmp / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        paths[name] = p
    return paths


def expect_raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return True
    except Exception as exc:
        return False
    return False


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="encx_test_"))
    try:
        # ---------- 插件加载 ----------
        print("== 插件加载 ==")
        reg = plugin_manager.scan_plugins()
        loaded_ids = [i.id for i in reg.loaded]
        check("aes-256-gcm 加载成功", "aes-256-gcm" in loaded_ids, str(loaded_ids))
        check("xor-stream 加载成功", "xor-stream" in loaded_ids, str(loaded_ids))
        check("无加载失败项", not reg.failed, str([f.reason for f in reg.failed]))

        aes = reg.find("aes-256-gcm")
        xor = reg.find("xor-stream")

        samples = make_samples(tmp)

        # ---------- 往返测试 ----------
        for plugin in (aes, xor):
            print(f"== 往返测试: {plugin.id} ==")
            for name, src in samples.items():
                enc = tmp / f"{src.name}.encx"
                dec = tmp / f"{src.name}.dec.out"
                n1 = engine.encrypt_file(plugin, src, enc, "pw-测试123")
                check(f"{name} 加密后扩展名为 .encx", enc.name.endswith(".encx"))
                check(f"{name} 密文不等于明文", md5(enc) != md5(src))
                n2 = engine.decrypt_file(plugin, enc, dec, "pw-测试123")
                check(f"{name} 解密内容一致", md5(dec) == md5(src),
                      f"{md5(dec)} != {md5(src)}")
                check(f"{name} 字节数一致", n1 == n2 == src.stat().st_size)

        # ---------- 探测与命名 ----------
        print("== 探测与命名 ==")
        enc = tmp / "text.txt.encx"
        enc.unlink(missing_ok=True)
        engine.encrypt_file(aes, samples["text.txt"], enc, "pw-测试123")  # 重新用 AES 加密
        check("peek_plugin_id 识别 aes", engine.peek_plugin_id(enc) == "aes-256-gcm")
        check("加密命名", engine.encrypted_name(Path("photo.jpg")) == "photo.jpg.encx")
        check("解密命名-去后缀", engine.decrypted_name(Path("photo.jpg.encx")) == "photo.jpg")
        check("解密命名-大写后缀", engine.decrypted_name(Path("photo.JPG.ENCX")) == "photo.JPG")
        check("解密命名-无后缀", engine.decrypted_name(Path("photo.jpg")) == "photo_decrypted.jpg")
        check("解密命名-仅后缀", engine.decrypted_name(Path("data.encx")) == "data")

        # ---------- 错误密码 / 数据损坏 ----------
        print("== 错误密码与完整性 ==")
        dec_bad = tmp / "bad.out"
        check("AES 错误密码被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file, aes, enc, dec_bad, "wrong"))

        enc_xor = tmp / "text.txt.x.encx"
        engine.encrypt_file(xor, samples["text.txt"], enc_xor, "pw-测试123")
        dec_xor_bad = tmp / "bad_xor.out"
        engine.decrypt_file(xor, enc_xor, dec_xor_bad, "wrong")  # XOR 无认证，不抛错
        check("XOR 错密码结果不等于原文",
              dec_xor_bad.read_bytes() != samples["text.txt"].read_bytes())
        dec_xor_bad.unlink()
        dec_bad.unlink(missing_ok=True)

        # 篡改密文中间一个字节
        tampered = tmp / "tampered.encx"
        raw = bytearray(enc.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        tampered.write_bytes(raw)
        check("AES 篡改被检测",
              expect_raises((WrongPasswordError, IntegrityError),
                            engine.decrypt_file, aes, tampered, tmp / "t1.out", "pw-测试123"))

        # 截断文件
        truncated = tmp / "trunc.encx"
        truncated.write_bytes(raw[: len(raw) - 100])
        check("AES 截断被检测",
              expect_raises((WrongPasswordError, IntegrityError, ContainerError),
                            engine.decrypt_file, aes, truncated, tmp / "t2.out", "pw-测试123"))

        # 非 encx 文件
        check("非加密文件被拒绝",
              expect_raises(ContainerError, engine.decrypt_file,
                            aes, samples["text.txt"], tmp / "t3.out", "pw"))

        # 插件不匹配
        check("插件不匹配被拒绝",
              expect_raises(ContainerError, engine.decrypt_file,
                            xor, enc, tmp / "t4.out", "pw-测试123"))

        # 失败后不残留 .part 文件与输出
        leftovers = [p.name for p in tmp.glob("*.part")] + [
            p.name for p in tmp.iterdir() if p.name in ("t1.out", "t2.out", "t3.out", "t4.out")
        ]
        check("失败任务无残留输出", not leftovers, str(leftovers))

        # ---------- 单文件插件形式 ----------
        print("== 单文件插件形式 ==")
        single = plugin_manager.default_plugins_dir() / "demo_single.py"
        single.write_text(
            "from encryptor.sdk import CryptoPlugin\n"
            "class Plugin(CryptoPlugin):\n"
            "    id = 'demo-single'\n"
            "    name = '演示单文件插件'\n"
            "    version = '0.1'\n"
            "    requires_password = False\n"
            "    def encrypt_stream(self, src, dst, password, on_progress):\n"
            "        data = src.read(); dst.write(bytes(b ^ 0x5A for b in data)); "
            "on_progress(len(data)); return b''\n"
            "    def decrypt_stream(self, metadata, src, dst, password, on_progress):\n"
            "        data = src.read(); dst.write(bytes(b ^ 0x5A for b in data)); "
            "on_progress(len(data))\n",
            encoding="utf-8",
        )
        try:
            reg2 = plugin_manager.scan_plugins()
            demo = reg2.find("demo-single")
            check("单文件插件被发现并加载", demo is not None,
                  str([f.reason for f in reg2.failed]))
            if demo:
                src = samples["one_byte.txt"]
                e2 = tmp / "single.encx"
                d2 = tmp / "single.out"
                engine.encrypt_file(demo, src, e2, None)
                engine.decrypt_file(demo, e2, d2, None)
                check("无密码插件往返成功", d2.read_bytes() == src.read_bytes())
        finally:
            single.unlink(missing_ok=True)

        # ---------- 坏插件隔离 ----------
        print("== 坏插件隔离 ==")
        bad = plugin_manager.default_plugins_dir() / "broken_demo.py"
        bad.write_text("raise RuntimeError('boom-导入失败')", encoding="utf-8")
        try:
            reg3 = plugin_manager.scan_plugins()
            check("坏插件被隔离且不影响其他插件",
                  "aes-256-gcm" in [i.id for i in reg3.loaded]
                  and len(reg3.failed) == 1 and "boom" in reg3.failed[0].reason)
        finally:
            bad.unlink(missing_ok=True)

        print(f"\n结果: {PASS} 通过, {FAIL} 失败")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
