"""修复验证重放：F3 无效曲线（v2 格式适配）。

向量：
  A) 对真实密文的 wrapped C1 篡改为曲线外的点 → 应被 C1 校验拒绝
     （校验发生在 MAC 检查之前，出现专用错误信息即证明校验真实存在）
  B) C1 篡改为 G（合法点但错误）→ 干净的 WrongPasswordError（不再是内部崩溃）
  C) 对照：未篡改文件正常解密
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from encryptor.sdk import IntegrityError, PluginError, WrongPasswordError

from lab import KEYS, SAMPLES, build_encx, dec, enc, get, parse

ART = Path(__file__).resolve().parent / "artifacts_replay"
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A3 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B3 = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93


def try_decrypt(path: Path, out: Path, cred: str) -> str:
    try:
        n = dec(path, out, cred)
        return f"成功({n}B)"
    except WrongPasswordError as e:
        return f"WrongPasswordError({str(e)[:26]})"
    except IntegrityError as e:
        return f"IntegrityError({str(e)[:26]})"
    except PluginError as e:
        return f"PluginError({str(e)[:26]})"
    except Exception as e:
        return f"{type(e).__name__}({str(e)[:26]})"


def main() -> None:
    import shutil
    if ART.exists():
        shutil.rmtree(ART)
    ART.mkdir()

    priv = str(KEYS / "sm2-sm4-gcm" / "sm2_private_key.pem")
    pub = str(KEYS / "sm2-sm4-gcm" / "sm2_public_key.pem")
    plugin = get("sm2-sm4-gcm")

    empty = ART / "empty.bin"
    empty.write_bytes(b"")
    base = ART / "base.encx"
    enc(empty, base, pub, "sm2-sm4-gcm")
    pid, _, payload, meta = parse(base)
    print(f"真实空载荷密文: {base.name} metadata {len(meta)}B ver={meta[0]}")

    # A) 曲线外点 (x=1, y=1)
    bad = bytearray(meta)
    off = 1  # ver 之后是 C1
    bad[off : off + 64] = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    f = ART / "offcurve.encx"
    f.write_bytes(build_encx("sm2-sm4-gcm", payload, bytes(bad)))
    print(f"A) C1=(1,1) 曲线外    → {try_decrypt(f, ART / 'o1', priv)}")

    # A2) 随机 64B 垃圾 C1
    import os
    bad = bytearray(meta)
    bad[off : off + 64] = os.urandom(64)
    f.write_bytes(build_encx("sm2-sm4-gcm", payload, bytes(bad)))
    print(f"A2) C1=随机 64B       → {try_decrypt(f, ART / 'o2', priv)}")

    # A3) 旧审计的 3 阶无效点（x=7 同 a 不同 b'）
    y2 = (pow(7, 3, P) + A3 * 7) % P
    # 解 b' 使 (7,y) 在曲线: y^2 = x^3+ax+b' → 任取 y, b'=y^2-x^3-ax
    yv = 1234567891
    f.write_bytes(build_encx("sm2-sm4-gcm", payload, bytes(
        bytearray(meta[:1]) + bytearray((7).to_bytes(32, "big") + yv.to_bytes(32, "big"))
        + bytearray(meta[65:]))))
    print(f"A3) C1=3阶无效点变体  → {try_decrypt(f, ART / 'o3', priv)}")

    # B) C1 = G（合法点，但非本密文的 C1）
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    bad = bytearray(meta)
    bad[off : off + 64] = Gx.to_bytes(32, "big") + Gy.to_bytes(32, "big")
    f.write_bytes(build_encx("sm2-sm4-gcm", payload, bytes(bad)))
    print(f"B) C1=G（合法点）      → {try_decrypt(f, ART / 'o4', priv)}")

    # C) 对照
    print(f"C) 对照（未篡改）      → {try_decrypt(base, ART / 'o5', priv)}")


if __name__ == "__main__":
    main()
