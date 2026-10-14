"""新攻击面扫描：v2 元数据模糊 / 跨插件移植 / 版本降级 / 弱口令爆破计时。"""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

from lab import KEYS, SAMPLES, build_encx, dec, parse

PASSWORD = "S3cret-P@ss2026!"
ART = Path(__file__).resolve().parent / "artifacts_new"


def try_dec(path: Path, out: Path, cred: str, pid: str = None) -> str:
    try:
        n = dec(path, out, cred, plugin_id=pid)
        return f"成功({n}B)"
    except WrongPasswordError:
        return "WrongPasswordError"
    except IntegrityError as e:
        return f"IntegrityError({str(e)[:24]})"
    except PluginError as e:
        return f"PluginError({str(e)[:24]})"
    except Exception as e:
        return f"{type(e).__name__}({str(e)[:24]})"


def main() -> None:
    ART.mkdir(exist_ok=True)

    print("=" * 78)
    print("A) v2 元数据模糊（aes：错误版本/截断/非法kdf/迭代越界）")
    _, _, payload, meta = parse(SAMPLES / "secret.aes-256-gcm.encx")
    cases = {
        "ver=1(降级)": bytes([1]) + meta[1:],
        "ver=3(未来)": bytes([3]) + meta[1:],
        "截断1B": meta[:-1],
        "kdf_id=99": meta[:1] + bytes([99]) + meta[2:],
        "iterations=0": meta[:2] + (0).to_bytes(4, "big") + meta[6:],
        "iterations=1e9(越上界)": meta[:2] + (10**9).to_bytes(4, "big") + meta[6:],
    }
    for name, m in cases.items():
        f = ART / "f.encx"
        f.write_bytes(build_encx("aes-256-gcm", payload, m))
        print(f"  {name:<22} → {try_dec(f, ART / 'f.out', PASSWORD, 'aes-256-gcm')}")

    print()
    print("=" * 78)
    print("B) 跨插件移植：A 的元数据 + B 的密文体")
    combos = [
        ("aes→sm4", "aes-256-gcm", "sm4-gcm", PASSWORD, "sm4-gcm"),
        ("rsa→ecdh", "rsa-oaep-aes256gcm", "ecdh-aes256gcm",
         str(KEYS / "ecdh-aes256gcm" / "ecc_private_key.pem"), "ecdh-aes256gcm"),
        ("sm2→rsa", "sm2-sm4-gcm", "rsa-oaep-aes256gcm",
         str(KEYS / "rsa-oaep-aes256gcm" / "rsa_private_key.pem"), "rsa-oaep-aes256gcm"),
    ]
    for name, meta_src, body_src, cred, header_pid in combos:
        _, _, body, _ = parse(SAMPLES / f"secret.{body_src}.encx")
        _, _, _, m = parse(SAMPLES / f"secret.{meta_src}.encx")
        f = ART / "x.encx"
        f.write_bytes(build_encx(header_pid, body, m))
        print(f"  {name:<10} → {try_dec(f, ART / 'x.out', cred, header_pid)}")

    print()
    print("=" * 78)
    print("C) 同插件跨文件移植：文件1的元数据 + 文件2的密文体（同口令）")
    _, _, body2, _ = parse(SAMPLES / "secret.aes-256-gcm.encx.2")
    _, _, _, m1 = parse(SAMPLES / "secret.aes-256-gcm.encx")
    f = ART / "y.encx"
    f.write_bytes(build_encx("aes-256-gcm", body2, m1))
    print(f"  meta1+body2            → {try_dec(f, ART / 'y.out', PASSWORD, 'aes-256-gcm')}")

    print()
    print("=" * 78)
    print("D) 弱口令密文离线爆破计时（600k 轮，12 词字典，口令排第 5）")
    wl = ["password", "12345678", "admin", "qwerty", "letmein",
          "123456", "iloveyou", "111111", "abc123", "hunter2",
          "P@ssw0rd", "123456"]
    _, _, payload, meta = parse(SAMPLES / "weak.aes.encx")
    salt = meta[6:22]
    nonce = meta[22:30] + b"\x00\x00\x00\x00"
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = payload[:1024 * 1024 + 16]
    t0 = time.perf_counter()
    found = None
    for pw in dict.fromkeys(wl):
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000, dklen=64)
        try:
            AESGCM(dk[:32]).decrypt(nonce, blob, b"aes-256-gcm")
            found = pw
            break
        except Exception:
            continue
    print(f"  破解结果: {found!r}  耗时 {time.perf_counter() - t0:.1f}s（3.5 H/s CPU）")


if __name__ == "__main__":
    main()
