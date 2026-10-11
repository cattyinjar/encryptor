"""内存镜像攻击 · 残留定位：保留镜像，打印命中点上下文，推断残留来源。"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from gmssl import sm2 as gm_sm2

from a7_memdump import WORK, dump_process, scan_dump
from lab import parse

HERE = Path(__file__).resolve().parent


def context(dmp: Path, off: int, before: int = 96, after: int = 96) -> bytes:
    with open(dmp, "rb") as f:
        f.seek(max(0, off - before))
        return f.read(before + after)


def show(tag: str, dmp: Path, off: int):
    c = context(dmp, off)
    hexs = c.hex(" ")
    print(f"  [{tag}] 命中偏移 +0x{off:X}，上下文（前 96B | 后 96B）:")
    for i in range(0, len(c), 32):
        chunk = c[i : i + 32]
        print(f"    {chunk.hex(' ')}  |{''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)}|")
    # 启发式判断
    pre = c[:96]
    if b"-----BEGIN" in c or b"BEGIN EC" in c:
        print("    → 上下文含 PEM 头：残留位于 PEM/Base64 文本附近")
    if pre[-4:-2] in (b"\x30\x67", b"\x30\x77", b"\x30\x81", b"\x04\x20", b"\x02\x01"):
        print("    → 上下文含 DER TLV 长度字节：残留疑似位于 DER 编码结构内")
    if all(32 <= b < 127 for b in c[96 - 62 : 96]):
        print("    → 命中点左侧是长串可打印 ASCII：疑似 hex 字符串/文本缓冲")


def main() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()
    (WORK / "keys").mkdir()
    from lab import get
    for pid in ("ecdh-aes256gcm", "sm2-sm4-gcm"):
        get(pid).generate_keypair(WORK / "keys")

    # ---- ecdh 场景 ----
    mdir = WORK / "ecdh"
    mdir.mkdir()
    proc = subprocess.Popen([sys.executable, str(HERE / "a7_victim.py"), "ecdh", str(mdir)],
                            cwd=str(HERE))
    while not (mdir / "READY").exists():
        time.sleep(0.3)
    dump_process(proc.pid, mdir / "victim.dmp")
    (mdir / "EXIT").write_text("1"); proc.wait(timeout=30)

    ecc_priv = serialization.load_pem_private_key(
        (WORK / "keys" / "ecc_private_key.pem").read_bytes(), password=None)
    v = ecc_priv.private_numbers().private_value
    needles = {
        "ECC私钥标量·raw": v.to_bytes(32, "big"),
        "ECC私钥标量·hex": f"{v:064x}".encode(),
        "对照明文": b"MEMORY-DUMP-ATTACK-CONTROL-PLAINTEXT",
    }
    hits = scan_dump(mdir / "victim.dmp", needles)
    print("== ecdh 场景残留定位 ==")
    for name, offs in hits.items():
        for off in offs[:3]:
            show(name, mdir / "victim.dmp", off)

    # ---- sm2 场景 ----
    mdir2 = WORK / "sm2"
    mdir2.mkdir()
    proc = subprocess.Popen([sys.executable, str(HERE / "a7_victim.py"), "sm2", str(mdir2)],
                            cwd=str(HERE))
    while not (mdir2 / "READY").exists():
        time.sleep(0.3)
    dump_process(proc.pid, mdir2 / "victim.dmp")
    (mdir2 / "EXIT").write_text("1"); proc.wait(timeout=30)

    sm2_hex = base64.b64decode("".join(
        (WORK / "keys" / "sm2_private_key.pem").read_text()
        .split("-----BEGIN SM2 PRIVATE KEY-----")[1]
        .split("-----END SM2 PRIVATE KEY-----")[0].split())).hex()
    _, _, _, meta = parse(mdir2 / "sm2.encx")
    ct_len = int.from_bytes(meta[:2], "big")
    cek = gm_sm2.CryptSM2(public_key="", private_key=sm2_hex, mode=1, asn1=False).decrypt(
        meta[2 : 2 + ct_len])
    needles2 = {
        "SM2私钥·raw": bytes.fromhex(sm2_hex),
        "SM2私钥·hex": sm2_hex.encode(),
        "SM2场景CEK·raw": cek,
        "SM2场景CEK·hex": cek.hex().encode(),
        "对照明文": b"MEMORY-DUMP-ATTACK-CONTROL-PLAINTEXT",
    }
    hits2 = scan_dump(mdir2 / "victim.dmp", needles2)
    print()
    print("== sm2 场景残留定位 ==")
    for name, offs in hits2.items():
        for off in offs[:3]:
            show(name, mdir2 / "victim.dmp", off)

    print()
    print("镜像保留在:", WORK / "ecdh" / "victim.dmp", "与", WORK / "sm2" / "victim.dmp")


if __name__ == "__main__":
    main()
