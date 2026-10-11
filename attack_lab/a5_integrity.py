"""攻击5：完整性绕过。

向量：
  A) 截断 + 改写尾部长度字段（元数据未认证）→ 多块文件可被无声截断
  B) 密文块重排/拼接 → 应被 GCM 计数器 nonce 拒绝（验证）
  C) xor/sm3 流密码定向比特翻转 → 无检测（无认证标签的必然结果）
  D) 头部插件 id 交换（xor-stream ↔ sm3-stream）→ 静默解出乱码
  E) 元数据盐篡改（GCM 插件）→ 应失败（验证）
  F) 空文件边界（全部 7 插件）
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

from lab import KEYS, SAMPLES, build_encx, dec, enc, get, parse

PASSWORD = "S3cret-P@ss2026!"
CHUNK = 1024 * 1024 + 16      # 1 MiB 密文 + 16B GCM 标签
ART = Path(__file__).resolve().parent / "artifacts_int"


def try_decrypt(path: Path, out: Path, cred: str, passphrase=None) -> str:
    try:
        n = dec(path, out, cred, passphrase=passphrase)
        return f"成功({n}B)"
    except WrongPasswordError:
        return "WrongPasswordError"
    except IntegrityError as e:
        return f"IntegrityError({str(e)[:24]}...)"
    except PluginError as e:
        return f"PluginError({str(e)[:24]}...)"
    except Exception as e:
        return f"{type(e).__name__}({str(e)[:24]}...)"


def truncation_attack(src: Path, cred: str, passphrase=None) -> None:
    """去掉最后一块密文 + 把元数据中的 8 字节总长改成截断后的值。"""
    pid, hlen, payload, meta = parse(src)
    blocks = [payload[i : i + CHUNK] for i in range(0, len(payload), CHUNK)]
    assert len(blocks) >= 2, "需要多块文件"
    cut_payload = b"".join(blocks[:-1])
    plain_len = sum(len(b) - 16 for b in blocks[:-1])
    if pid in ("aes-256-gcm", "sm4-gcm"):
        new_meta = meta[:24] + plain_len.to_bytes(8, "big")
    else:  # rsa/ecdh/sm2：元数据布局不同，总长字段在最后 8 字节
        new_meta = meta[:-8] + plain_len.to_bytes(8, "big")
    out_file = ART / f"trunc.{pid}.encx"
    out_file.write_bytes(build_encx(pid, cut_payload, new_meta))
    print(f"  {pid}: 原明文 {int.from_bytes(meta[-8:], 'big'):,}B → 篡改为 {plain_len:,}B")
    print(f"    受害者解密被截断文件 → {try_decrypt(out_file, ART / 'trunc.out', cred, passphrase)}")
    got = (ART / "trunc.out")
    if got.exists():
        data = got.read_bytes()
        orig = (SAMPLES / "big3m.bin").read_bytes()
        print(f"    输出前段与原明文一致 = {data == orig[:len(data)]}  （无声丢失 {len(orig) - len(data):,}B）")
        got.unlink()


def reorder_attack(src: Path, cred: str) -> None:
    pid, hlen, payload, meta = parse(src)
    blocks = [payload[i : i + CHUNK] for i in range(0, len(payload), CHUNK)]
    blocks[0], blocks[1] = blocks[1], blocks[0]
    out_file = ART / f"reorder.{pid}.encx"
    out_file.write_bytes(build_encx(pid, b"".join(blocks), meta))
    print(f"  {pid}: 块0/块1 互换 → {try_decrypt(out_file, ART / 'reorder.out', cred)}")


def bitflip_attack() -> None:
    """xor-stream：把明文里的 '03:00' 改成 '09:30'（攻击者已知明文位置）。"""
    plain = (SAMPLES / "secret.txt").read_bytes()
    payload_of = SAMPLES / "secret.xor-stream.encx"
    _, _, payload, meta = parse(payload_of)
    off = plain.index(b"03:00")
    # '0'=0x30 '3'=0x33 '9'=0x39 → 只需翻转 1 比特: 0x33^0x0A 不对——直接算目标差分
    diff = bytes(a ^ b for a, b in zip(b"03:00", b"09:30"))
    forged = bytearray(payload)
    for i, d in enumerate(diff):
        forged[off + i] ^= d
    out_file = ART / "flip.xor-stream.encx"
    out_file.write_bytes(build_encx("xor-stream", bytes(forged), meta))
    print(f"  xor-stream: 篡改 {diff.hex()} @off{off} → {try_decrypt(out_file, ART / 'flip.out', PASSWORD)}")
    got = (ART / "flip.out").read_bytes()
    print(f"    解出明文包含 '09:30' = {b'09:30' in got}  原文其余部分不变 = "
          f"{got.replace(b'09:30', b'03:00') == plain}")
    (ART / "flip.out").unlink()


def header_swap_attack() -> None:
    data = (SAMPLES / "secret.xor-stream.encx").read_bytes()
    forged = data.replace(b"ENCX\x01\x0a\x00xor-stream", b"ENCX\x01\x0a\x00sm3-stream")
    assert forged != data
    f = ART / "swap.encx"
    f.write_bytes(forged)
    print(f"  头部 id 改为 sm3-stream 后用受害者口令解密 → {try_decrypt(f, ART / 'swap.out', PASSWORD)}")
    out = ART / "swap.out"
    if out.exists():
        data = out.read_bytes()
        print(f"    输出是乱码(≠原文) = {data != (SAMPLES / 'secret.txt').read_bytes()}"
              f"  软件未报任何错误 = True")
        out.unlink()


def salt_tamper_attack() -> None:
    _, _, payload, meta = parse(SAMPLES / "secret.aes-256-gcm.encx")
    meta2 = bytearray(meta); meta2[0] ^= 1
    f = ART / "salt.encx"
    f.write_bytes(build_encx("aes-256-gcm", payload, bytes(meta2)))
    print(f"  aes-256-gcm: 篡改盐 1 字节 → {try_decrypt(f, ART / 'salt.out', PASSWORD)}")


def empty_file_edge() -> None:
    empty = ART / "empty.bin"
    empty.write_bytes(b"")
    for pid in ("aes-256-gcm", "xor-stream", "sm4-gcm", "sm3-stream"):
        f = ART / f"empty.{pid}.encx"
        enc(empty, f, PASSWORD, pid)
        st = try_decrypt(f, ART / "empty.out", PASSWORD)
        ok = (ART / "empty.out").exists() and (ART / "empty.out").stat().st_size == 0
        (ART / "empty.out").unlink(missing_ok=True)
        print(f"  {pid}: 空文件 加密→解密 {st} 输出为空 = {ok}")
    for pid in ("rsa-oaep-aes256gcm", "ecdh-aes256gcm", "sm2-sm4-gcm"):
        pub = KEYS / pid / ("rsa_public_key.pem" if "rsa" in pid
                            else "ecc_public_key.pem" if "ecdh" in pid else "sm2_public_key.pem")
        priv = str(pub).replace("public", "private")
        f = ART / f"empty.{pid}.encx"
        enc(empty, f, str(pub), pid)
        st = try_decrypt(f, ART / "empty.out", priv)
        ok = (ART / "empty.out").exists() and (ART / "empty.out").stat().st_size == 0
        (ART / "empty.out").unlink(missing_ok=True)
        print(f"  {pid}: 空文件 加密→解密 {st} 输出为空 = {ok}")


def main() -> None:
    ART.mkdir(exist_ok=True)
    print("=" * 78)
    print("A) 无声截断攻击（元数据总长未认证）：aes-256-gcm / sm4-gcm / rsa / sm2")
    truncation_attack(SAMPLES / "big3m.aes-256-gcm.encx", PASSWORD)
    truncation_attack(SAMPLES / "big3m.sm4-gcm.encx", PASSWORD)
    truncation_attack(SAMPLES / "big3m.rsa-oaep-aes256gcm.encx",
                      str(KEYS / "rsa-oaep-aes256gcm" / "rsa_private_key.pem"))
    truncation_attack(SAMPLES / "big3m.sm2-sm4-gcm.encx",
                      str(KEYS / "sm2-sm4-gcm" / "sm2_private_key.pem"))

    print()
    print("=" * 78)
    print("B) 密文块重排（应被 GCM 拒绝）")
    reorder_attack(SAMPLES / "big3m.aes-256-gcm.encx", PASSWORD)
    reorder_attack(SAMPLES / "big3m.ecdh-aes256gcm.encx",
                   str(KEYS / "ecdh-aes256gcm" / "ecc_private_key.pem"))

    print()
    print("=" * 78)
    print("C) 流密码定向比特翻转")
    bitflip_attack()

    print()
    print("=" * 78)
    print("D) 头部插件 id 交换")
    header_swap_attack()

    print()
    print("=" * 78)
    print("E) 元数据盐篡改（GCM 应拒绝）")
    salt_tamper_attack()

    print()
    print("=" * 78)
    print("F) 空文件边界")
    empty_file_edge()


if __name__ == "__main__":
    main()
