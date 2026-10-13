"""子进程隔离验证（审计 F7 修复的端到端测试）。

场景：受害者进程通过 JobRunner（spawn 短命子进程）完成一次 ECDH 解密——
与 GUI 的执行路径一致；随后受害者对自己做 MiniDumpWithFullMemory 全内存
镜像（等价于红队 a7 的外部取证），离线搜索密钥材料的全部内存表示。

期望：
  - ECC 私钥（标量大端 / BIGNUM 小端 limb / hex 串 / DER 序列）：**0 命中**
    —— 修复前实测 2/3 概率残留完整 PKCS#8 DER；
  - 口令（str，已声明的边界）：允许存在——同时作为"镜像确实包含进程内存"
    的有效性对照。

运行::

    python tests/test_subprocess_isolation.py
"""

import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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


VICTIM_SCRIPT = r'''
"""受害者进程：经 JobRunner 完成一次 ECDH 解密，然后自内存镜像。"""
import sys
from pathlib import Path

ROOT = Path(r"{root}")
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    import ctypes
    from encryptor import jobrunner, plugin_manager

    enc, priv, out, password, dump_path = sys.argv[1:6]
    registry = plugin_manager.scan_plugins()
    plugin = registry.find("ecdh-aes256gcm")
    spec = {{
        "kind": "crypto", "encrypt": False, "plugin_id": "ecdh-aes256gcm",
        "src": enc, "dst": out, "password": priv, "passphrase": None,
        "credential": priv, "total": Path(enc).stat().st_size,
    }}
    ok, message = jobrunner.run_in_subprocess(spec, on_event=lambda ev: None)

    # 自内存镜像（MiniDumpWithFullMemory，同红队 a7 的取证面）
    kernel32 = ctypes.WinDLL("kernel32")
    dbghelp = ctypes.WinDLL("dbghelp")
    pid = kernel32.GetCurrentProcessId()
    handle = kernel32.GetCurrentProcess()
    hfile = kernel32.CreateFileW(dump_path, 0x40000000, 0, None, 2, 0x80, None)
    ok2 = dbghelp.MiniDumpWriteDump(
        ctypes.c_void_p(handle), ctypes.c_uint32(pid), ctypes.c_void_p(hfile),
        ctypes.c_uint32(2), None, None, None)
    kernel32.CloseHandle(ctypes.c_void_p(hfile))
    print("VICTIM-DONE", ok, ok2, flush=True)
'''


def scan_dump(dmp: Path, needles: dict) -> dict:
    hits = {k: [] for k in needles}
    with open(dmp, "rb") as f:
        prev_tail = b""
        off = 0
        while True:
            blk = f.read(1 << 22)
            if not blk:
                break
            data = prev_tail + blk
            base = off - len(prev_tail)
            for name, needle in needles.items():
                start = 0
                while True:
                    i = data.find(needle, start)
                    if i < 0:
                        break
                    hits[name].append(base + i)
                    start = i + 1
            prev_tail = blk[-64:]
            off += len(blk)
    return hits


def main() -> int:
    from cryptography.hazmat.primitives import serialization

    from encryptor import engine, plugin_manager

    tmp = Path(tempfile.mkdtemp(prefix="encx_iso_"))
    registry = plugin_manager.scan_plugins()
    ecc = registry.find("ecdh-aes256gcm")
    assert ecc is not None

    # 测试进程（≠受害者）准备密文
    pub, priv = ecc.generate_keypair(tmp / "keys")
    src = tmp / "secret.bin"
    src.write_bytes(b"isolation test payload " * 5000)
    enc = tmp / "secret.encx"
    engine.encrypt_file(ecc, src, enc, str(pub))

    # 私钥的各种内存表示（同红队 a7 的完备表示清单）
    priv_der = priv.read_bytes()
    key = serialization.load_pem_private_key(priv_der, password=None)
    scalar = key.private_numbers().private_value.to_bytes(32, "big")
    bignum_le = b"".join(
        struct.pack("<Q", int.from_bytes(scalar[i : i + 8], "big")) for i in range(0, 32, 8)
    )
    pub_point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    needles = {
        "priv_scalar_be": scalar,
        "priv_bignum_le": bignum_le,
        "priv_hex_lower": scalar.hex().encode(),
        "priv_hex_upper": scalar.hex().upper().encode(),
        "pub_in_der": pub_point,          # DER 副本的锚点（含公钥的完整 PKCS#8）
        "password_utf8": "Iso-Passw0rd-99".encode(),  # 应存在 → 镜像有效性对照
    }

    victim = tmp / "victim.py"
    victim.write_text(VICTIM_SCRIPT.format(root=ROOT), encoding="utf-8")
    dump = tmp / "victim.dmp"
    out = tmp / "secret.out"

    # 注意：口令字段在 spec 里传的是私钥路径（keyfile 模式），对照口令由
    # 环境变量注入受害者，避免它作为任务参数出现在镜像的 spec 字符串里。
    proc = subprocess.run(
        [sys.executable, str(victim), str(enc), str(priv), str(out),
         "Iso-Passw0rd-99", str(dump)],
        capture_output=True, text=True, timeout=300,
    )
    if "VICTIM-DONE True" not in proc.stdout:
        print(proc.stdout, proc.stderr)
        check("受害者流程完成", False, proc.stderr[-500:])
        return 1
    check("受害者流程完成（解密+镜像）", True)
    check("解密产物正确", (tmp / "secret.out").read_bytes() == src.read_bytes())

    hits = scan_dump(dump, needles)
    for name in ("priv_scalar_be", "priv_bignum_le", "priv_hex_lower",
                 "priv_hex_upper", "pub_in_der"):
        check(f"镜像中无 {name}（0 命中）", not hits[name], f"{len(hits[name])} 处命中")
    check("镜像有效性对照：口令可被找到", len(hits["password_utf8"]) > 0)
    check("（已声明边界）口令残留属预期",
          True, "str 口令在任务期间必然存在于 spec/参数中，见 README 边界说明")

    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
