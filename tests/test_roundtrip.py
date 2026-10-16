"""端到端测试：插件加载、加密解密往返、完整性/密码校验、命名规则、容器格式。

运行::

    python tests/test_roundtrip.py
"""

import hashlib
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from encryptor import engine, plugin_manager
from encryptor.container import ContainerError
from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

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


def truncate_rewrite_total(src: Path, out: Path, total_off_in_meta: int, chunk_plain: int = 1024 * 1024):
    """审计 F2 攻击向量：删除最后一个整块密文 + 改写元数据总长字段。"""
    import struct as _st
    raw = bytearray(src.read_bytes())
    (mlen,) = _st.unpack("<I", bytes(raw[-4:]))
    meta_off = len(raw) - 4 - mlen
    (pid_len,) = _st.unpack("<H", bytes(raw[5:7]))
    head = 7 + pid_len
    chunk = chunk_plain + 16
    n_chunks = (meta_off - head) // chunk
    assert n_chunks >= 2, "样本需跨块"
    start = head + (n_chunks - 1) * chunk
    del raw[start : start + chunk]
    meta_off = len(raw) - 4 - mlen
    toff = meta_off + total_off_in_meta
    old = int.from_bytes(raw[toff : toff + 8], "big")
    raw[toff : toff + 8] = (old - chunk_plain).to_bytes(8, "big")
    out.write_bytes(raw)


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
        # v2 起流插件带口令预验证：错口令立即报错（不再静默输出乱码）
        check("XOR 错密码被立即拒绝（v2 预验证器）",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            xor, enc_xor, dec_xor_bad, "wrong-pw"))
        enc_sm3 = tmp / "text.txt.sm3err.encx"
        engine.encrypt_file(reg.find("sm3-stream"), samples["text.txt"], enc_sm3, "pw-测试123")
        check("SM3 错密码被立即拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            reg.find("sm3-stream"), enc_sm3, tmp / "bad3.out", "wrong-pw"))
        dec_xor_bad.unlink(missing_ok=True)
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

        # ---------- 密钥文件插件（RSA / ECC 混合加密） ----------
        print("== 密钥文件插件：RSA / ECC ==")
        rsa_p = reg.find("rsa-oaep-aes256gcm")
        ecc_p = reg.find("ecdh-aes256gcm")
        check("RSA 插件加载成功", rsa_p is not None, str(loaded_ids))
        check("ECC 插件加载成功", ecc_p is not None, str(loaded_ids))

        keys_dir = tmp / "keys"
        rsa_pub, rsa_priv = rsa_p.generate_keypair(keys_dir)
        ecc_pub, ecc_priv = ecc_p.generate_keypair(keys_dir)
        check("RSA 密钥对生成", rsa_pub.is_file() and rsa_priv.is_file())
        check("ECC 密钥对生成", ecc_pub.is_file() and ecc_priv.is_file())
        check("RSA 公钥为标准 PEM", b"BEGIN PUBLIC KEY" in rsa_pub.read_bytes())
        check("ECC 私钥为标准 PEM", b"PRIVATE KEY" in ecc_priv.read_bytes())
        check("重复生成同目录密钥被拒绝",
              expect_raises(PluginError, rsa_p.generate_keypair, keys_dir))

        for plugin, pub, priv in (
            (rsa_p, rsa_pub, rsa_priv),
            (ecc_p, ecc_pub, ecc_priv),
        ):
            for name, src in samples.items():
                enc_k = tmp / f"{name}.{plugin.id}.encx"
                dec_k = tmp / f"{name}.{plugin.id}.out"
                engine.encrypt_file(plugin, src, enc_k, str(pub))
                engine.decrypt_file(plugin, enc_k, dec_k, str(priv))
                check(f"{plugin.id} {name} 密钥文件往返一致", md5(dec_k) == md5(src))
            head = engine.peek_plugin_id(tmp / f"text.txt.{plugin.id}.encx")
            check(f"{plugin.id} 文件头记录算法 id", head == plugin.id, str(head))

        enc_rsa = tmp / f"text.txt.{rsa_p.id}.encx"
        enc_ecc = tmp / f"text.txt.{ecc_p.id}.encx"

        # 错误私钥（另一对密钥）
        keys2 = tmp / "keys2"
        _, rsa_priv2 = rsa_p.generate_keypair(keys2)
        _, ecc_priv2 = ecc_p.generate_keypair(keys2)
        check("RSA 错误私钥被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            rsa_p, enc_rsa, tmp / "wrong1.out", str(rsa_priv2)))
        check("ECC 错误私钥被拒绝",
              expect_raises((WrongPasswordError, IntegrityError), engine.decrypt_file,
                            ecc_p, enc_ecc, tmp / "wrong2.out", str(ecc_priv2)))

        # 跨算法 / 跨密钥类型混用
        check("ECC 密文不能由 RSA 插件解（容器层拦截）",
              expect_raises(ContainerError, engine.decrypt_file,
                            rsa_p, enc_ecc, tmp / "x1.out", str(rsa_priv)))
        check("RSA 解密配 ECC 私钥被拒绝",
              expect_raises(PluginError, engine.decrypt_file,
                            rsa_p, enc_rsa, tmp / "x2.out", str(ecc_priv)))

        # 密钥文件缺失
        check("加密时密钥文件缺失被拒绝",
              expect_raises(PluginError, engine.encrypt_file,
                            rsa_p, samples["text.txt"], tmp / "x3.encx", str(tmp / "nope.pem")))

        # 篡改元数据尾部
        tampered_k = tmp / "tampered_k.encx"
        raw_k = bytearray(enc_ecc.read_bytes())
        raw_k[len(raw_k) - 30] ^= 0xFF  # 落在元数据区域
        tampered_k.write_bytes(raw_k)
        check("ECC 元数据篡改被检测",
              expect_raises((WrongPasswordError, IntegrityError, ContainerError),
                            engine.decrypt_file, ecc_p, tampered_k, tmp / "x4.out", str(ecc_priv)))

        leftovers2 = [p.name for p in tmp.glob("*.part")] + [
            p.name for p in tmp.iterdir()
            if p.name.startswith(("x1", "x2", "x3", "x4", "wrong1", "wrong2"))
        ]
        check("密钥插件失败任务无残留输出", not leftovers2, str(leftovers2))

        # ---------- v2 元数据安全（审计 F2/F4/F5 修复验证） ----------
        print("== v2 元数据安全 ==")
        big = samples["big_random.bin"]
        f2_cases = []
        for pid in ("aes-256-gcm", "sm4-gcm"):
            e = tmp / f"big_random.bin.{pid}.encx"
            engine.encrypt_file(reg.find(pid), big, e, "pw-测试123")
            f2_cases.append((pid, e, 2 + 4 + 16 + 8, "pw-测试123"))
        e_rsa = tmp / "big_random.bin.rsa-f2.encx"
        engine.encrypt_file(rsa_p, big, e_rsa, str(rsa_pub))
        f2_cases.append(("rsa-oaep-aes256gcm", e_rsa, 1 + 2 + 384 + 8, str(rsa_priv)))
        e_ecc = tmp / "big_random.bin.ecc-f2.encx"
        engine.encrypt_file(ecc_p, big, e_ecc, str(ecc_pub))
        f2_cases.append(("ecdh-aes256gcm", e_ecc, 1 + 2 + 33 + 12 + 48 + 8, str(ecc_priv)))
        s2_pub, s2_priv = reg.find("sm2-sm4-gcm").generate_keypair(tmp / "keys_f2")
        e_sm2 = tmp / "big_random.bin.sm2-f2.encx"
        engine.encrypt_file(reg.find("sm2-sm4-gcm"), big, e_sm2, str(s2_pub))
        f2_cases.append(("sm2-sm4-gcm", e_sm2, 1 + 112 + 8, str(s2_priv)))

        for pid, enc_path, off, cred in f2_cases:
            out = tmp / "f2.encx"
            truncate_rewrite_total(enc_path, out, off)
            check(f"F2 截断+改总长被拒 [{pid}]",
                  expect_raises((WrongPasswordError, IntegrityError), engine.decrypt_file,
                                reg.find(pid), out, tmp / "f2.out", cred))

        # 流插件：截断（无 total 字段，MAC 直接覆盖密文）
        for pid in ("xor-stream", "sm3-stream"):
            e = tmp / f"big_random.bin.{pid}.encx"
            engine.encrypt_file(reg.find(pid), big, e, "pw-测试123")
            raw = bytearray(e.read_bytes())
            del raw[len(raw) - 100:]
            (tmp / "f2s.encx").write_bytes(raw)
            check(f"F2 密文截断被拒 [{pid}]",
                  expect_raises((WrongPasswordError, IntegrityError), engine.decrypt_file,
                                reg.find(pid), tmp / "f2s.encx", tmp / "f2s.out", "pw-测试123"))

        # F5：流插件比特翻转 / 头部 id 交换
        flip = tmp / "flip.encx"
        raw = bytearray((tmp / "text.txt.x.encx").read_bytes())
        raw[30] ^= 0x01
        flip.write_bytes(raw)
        check("XOR 比特翻转被拒（v2 MAC）",
              expect_raises(IntegrityError, engine.decrypt_file,
                            xor, flip, tmp / "flip.out", "pw-测试123"))
        swap = tmp / "swap.encx"
        raw = bytearray((tmp / "text.txt.x.encx").read_bytes())
        raw[7 : 7 + 10] = b"sm3-stream"
        swap.write_bytes(raw)
        check("头部插件 id 交换被拒",
              expect_raises((IntegrityError, WrongPasswordError, ContainerError),
                            engine.decrypt_file, reg.find("sm3-stream"), swap,
                            tmp / "swap.out", "pw-测试123"))

        # F4/N1：KDF 参数自描述（600k 写入元数据，版本 v3）
        from encryptor import container as _ct
        with open(tmp / "big_random.bin.aes-256-gcm.encx", "rb") as f:
            info = _ct.read_container(f)
        meta = info.metadata
        check("元数据版本 v3", meta[0] == 3, str(meta[:2]))
        check("KDF 标识与迭代数自描述（600k）",
              meta[1] == 1 and int.from_bytes(meta[2:6], "big") == 600_000,
              f"kdf={meta[1]} iters={int.from_bytes(meta[2:6], 'big')}")

        # N1：伪造大迭代数必须被廉价预验快速拒绝（不烧全量 KDF 的 CPU）
        import struct as _st4

        def forge_iterations(src: Path, out: Path, iters: int) -> None:
            raw = bytearray(src.read_bytes())
            (m4,) = _st4.unpack("<I", bytes(raw[-4:]))
            moff = len(raw) - 4 - m4
            raw[moff + 2 : moff + 6] = iters.to_bytes(4, "big")
            out.write_bytes(raw)

        n1_file = tmp / "n1_maxiter.encx"
        forge_iterations(tmp / "big_random.bin.aes-256-gcm.encx", n1_file, 20_000_000)
        t0 = time.time()
        rejected = expect_raises((WrongPasswordError, IntegrityError),
                                 engine.decrypt_file, aes, n1_file,
                                 tmp / "n1.out", "pw-测试123")
        dt = time.time() - t0
        check("N1 伪造 2000 万轮迭代被拒", rejected)
        check(f"N1 拒绝耗时 {dt:.2f}s（预验生效，<2s）", dt < 2.0, f"{dt:.2f}s")
        n1_over = tmp / "n1_over.encx"
        forge_iterations(tmp / "big_random.bin.aes-256-gcm.encx", n1_over, 99_999_999)
        check("N1 超上限迭代数被结构性拒绝",
              expect_raises(IntegrityError, engine.decrypt_file, aes, n1_over,
                            tmp / "n1b.out", "pw-测试123"))

        # N4：engine 层口令策略（加密侧，任何调用路径）
        check("N4 engine 拒绝过短口令",
              expect_raises(Exception, engine.encrypt_file, aes,
                            samples["text.txt"], tmp / "n4.encx", "short"))
        ok_enc = tmp / "n4_ok.encx"
        engine.encrypt_file(aes, samples["text.txt"], ok_enc, "pw-足够长度-12345")
        check("N4 engine 接受合规口令", ok_enc.is_file())
        # keyfile 模式（password=路径）与无密码插件不适用长度策略
        try:
            engine._check_encrypt_policy(rsa_p, "x")       # keyfile：不检查
            engine._check_encrypt_policy(aes, None)        # 无口令：不检查
            keyfile_ok = True
        except Exception as exc:
            keyfile_ok = False
        check("N4 策略仅作用于密码模式插件", keyfile_ok)
        try:
            engine._check_encrypt_policy(aes, "short")
            policy_hit = False
        except Exception:
            policy_hit = True
        check("N4 策略对密码模式短口令生效", policy_hit)

        # ---------- 带口令的私钥 ----------
        print("== 带口令的私钥 ==")
        pub_e, priv_e = rsa_p.generate_keypair(tmp / "keys_enc", passphrase="top-secret-PW")
        check("口令私钥为标准加密 PEM", b"BEGIN ENCRYPTED PRIVATE KEY" in priv_e.read_bytes())
        check("口令私钥对的公钥仍为明文 PEM", b"BEGIN PUBLIC KEY" in pub_e.read_bytes())
        enc_pw = tmp / "text.txt.rsa-pw.encx"
        dec_pw = tmp / "text.txt.rsa-pw.out"
        engine.encrypt_file(rsa_p, samples["text.txt"], enc_pw, str(pub_e))  # 公钥无需口令
        engine.decrypt_file(rsa_p, enc_pw, dec_pw, str(priv_e), passphrase="top-secret-PW")
        check("RSA 口令私钥往返一致", dec_pw.read_bytes() == samples["text.txt"].read_bytes())
        check("错误口令被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            rsa_p, enc_pw, tmp / "w3.out", str(priv_e), passphrase="wrong"))
        check("未给口令时给出明确提示",
              expect_raises(PluginError, engine.decrypt_file,
                            rsa_p, enc_pw, tmp / "w4.out", str(priv_e)))
        dec_ok = tmp / "text.txt.plain-with-pw.out"
        engine.decrypt_file(rsa_p, enc_rsa, dec_ok, str(rsa_priv), passphrase="多输的口令")
        check("明文私钥误配口令仍可解密", dec_ok.read_bytes() == samples["text.txt"].read_bytes())

        e_pub, e_priv = ecc_p.generate_keypair(tmp / "keys_enc2", passphrase="ecc-pw")
        e_enc = tmp / "text.txt.ecc-pw.encx"
        e_dec = tmp / "text.txt.ecc-pw.out"
        engine.encrypt_file(ecc_p, samples["text.txt"], e_enc, str(e_pub))
        engine.decrypt_file(ecc_p, e_enc, e_dec, str(e_priv), passphrase="ecc-pw")
        check("ECC 口令私钥往返一致", e_dec.read_bytes() == samples["text.txt"].read_bytes())
        check("ECC 错误口令被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            ecc_p, e_enc, tmp / "w5.out", str(e_priv), passphrase="no"))
        leftovers3 = [p.name for p in tmp.iterdir() if p.name.startswith(("w3", "w4", "w5"))]
        check("口令失败任务无残留输出", not leftovers3, str(leftovers3))

        # ---------- 国密插件（SM2 / SM3 / SM4） ----------
        print("== 国密插件：SM2 / SM3 / SM4 ==")
        sm3p = reg.find("sm3-stream")
        sm4p = reg.find("sm4-gcm")
        sm2p = reg.find("sm2-sm4-gcm")
        check("SM3 插件加载成功", sm3p is not None, str(loaded_ids))
        check("SM4 插件加载成功", sm4p is not None, str(loaded_ids))
        check("SM2 插件加载成功", sm2p is not None, str(loaded_ids))

        for plugin in (sm3p, sm4p):
            for name, src in samples.items():
                enc_k = tmp / f"{name}.{plugin.id}.encx"
                dec_k = tmp / f"{name}.{plugin.id}.out"
                engine.encrypt_file(plugin, src, enc_k, "国密-pw-123")
                engine.decrypt_file(plugin, enc_k, dec_k, "国密-pw-123")
                check(f"{plugin.id} {name} 往返一致", md5(dec_k) == md5(src))
        check("SM4 错密码被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            sm4p, tmp / f"text.txt.{sm4p.id}.encx", tmp / "w6.out", "wrong"))

        s_pub, s_priv = sm2p.generate_keypair(tmp / "keys_sm2", passphrase="sm2-pw")
        check("SM2 公钥文件标记正确", b"BEGIN SM2 PUBLIC KEY" in s_pub.read_bytes())
        check("SM2 口令私钥为加密信封", b"ENCRYPTED SM2 PRIVATE KEY" in s_priv.read_bytes())
        s_pub2, s_priv2 = sm2p.generate_keypair(tmp / "keys_sm2_plain")
        check("SM2 明文私钥标记正确", b"BEGIN SM2 PRIVATE KEY" in s_priv2.read_bytes())
        for name, src in samples.items():
            enc_k = tmp / f"{name}.sm2.encx"
            dec_k = tmp / f"{name}.sm2.out"
            engine.encrypt_file(sm2p, src, enc_k, str(s_pub))
            engine.decrypt_file(sm2p, enc_k, dec_k, str(s_priv), passphrase="sm2-pw")
            check(f"sm2 {name} 往返一致", md5(dec_k) == md5(src))
        enc_sm2 = tmp / "text.txt.sm2.encx"
        check("SM2 空文件错误私钥被拒绝（CEK 校验生效）",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            sm2p, tmp / "empty.bin.sm2.encx", tmp / "w7.out", str(s_priv2)))
        check("SM2 错误私钥被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            sm2p, enc_sm2, tmp / "w8.out", str(s_priv2), passphrase=None))
        check("SM2 缺口令被提示",
              expect_raises(PluginError, engine.decrypt_file,
                            sm2p, enc_sm2, tmp / "w9.out", str(s_priv)))
        check("SM2 错误口令被拒绝",
              expect_raises(WrongPasswordError, engine.decrypt_file,
                            sm2p, enc_sm2, tmp / "w10.out", str(s_priv), passphrase="wrong"))
        check("SM2 密文不能由 SM4 插件解（容器层拦截）",
              expect_raises(ContainerError, engine.decrypt_file,
                            sm4p, enc_sm2, tmp / "w11.out", "x"))
        leftovers4 = [p.name for p in tmp.iterdir()
                      if p.name.startswith(("w6", "w7", "w8", "w9", "w10", "w11"))]
        check("国密失败任务无残留输出", not leftovers4, str(leftovers4))

        # F1 回归证明：敏感随机数路径完全不依赖 random 模块（MT19937）
        import random as _random
        import contextlib

        @contextlib.contextmanager
        def _random_must_not_be_called():
            def _boom(*a, **k):
                raise AssertionError("敏感路径调用了 random 模块!")
            orig = _random.choice, _random.getrandbits, _random.random
            _random.choice = _random.getrandbits = _random.random = _boom
            try:
                yield
            finally:
                _random.choice, _random.getrandbits, _random.random = orig

        mt_pub = tmp / "mt_sm2"
        with _random_must_not_be_called():
            m_pub, m_priv = sm2p.generate_keypair(mt_pub)
            m_enc = tmp / "mt.encx"
            engine.encrypt_file(sm2p, samples["one_byte.txt"], m_enc, str(m_pub))
            m_out = tmp / "mt.out"
            engine.decrypt_file(sm2p, m_enc, m_out, str(m_priv))
        check("SM2 密钥生成/加解密全程不触碰 random(MT19937)",
              m_out.read_bytes() == samples["one_byte.txt"].read_bytes())

        # F3 回归：伪造 C1（不在曲线上）必须被拒
        forged = tmp / "forged_c1.encx"
        raw = bytearray(enc_sm2.read_bytes())
        import struct as _st3
        (mlen3,) = _st3.unpack("<I", bytes(raw[-4:]))
        meta_off3 = len(raw) - 4 - mlen3
        for i in range(64):
            raw[meta_off3 + 1 + i] = (i * 7 + 13) & 0xFF   # C1 换成非曲线点
        forged.write_bytes(raw)
        check("伪造 C1（不在曲线上）被拒",
              expect_raises(IntegrityError, engine.decrypt_file,
                            sm2p, forged, tmp / "forged.out", str(s_priv2)))

        # ---------- 密钥强度下限 ----------
        print("== 密钥强度下限 ==")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec as c_ec
        from cryptography.hazmat.primitives.asymmetric import rsa as c_rsa

        weak_rsa = tmp / "weak_rsa1024.pub.pem"
        weak_rsa.write_bytes(
            c_rsa.generate_private_key(public_exponent=65537, key_size=1024)
            .public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        check("RSA-1024 公钥被拒绝",
              expect_raises(PluginError, engine.encrypt_file,
                            rsa_p, samples["text.txt"], tmp / "weak.encx", str(weak_rsa)))
        weak_ec = tmp / "weak_p192.pub.pem"
        weak_ec.write_bytes(
            c_ec.generate_private_key(c_ec.SECP192R1())
            .public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        check("P-192 公钥被拒绝",
              expect_raises(PluginError, engine.encrypt_file,
                            ecc_p, samples["text.txt"], tmp / "weak2.encx", str(weak_ec)))
        check("强度描述-RSA", "3072" in rsa_p.describe_credential(str(rsa_priv)),
              rsa_p.describe_credential(str(rsa_priv)))
        check("强度描述-ECC", "256" in ecc_p.describe_credential(str(ecc_priv)),
              ecc_p.describe_credential(str(ecc_priv)))
        check("强度描述-SM2", "SM2" in sm2p.describe_credential(str(s_pub)))

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
