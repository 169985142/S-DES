# -*- coding: utf-8 -*-
"""S-DES 解密算法实现。

解密与加密结构完全相同，唯一区别是子密钥使用顺序相反：
加密用 k1 -> k2，解密用 k2 -> k1。

公式：P = IP^-1( f_k1( SW( f_k2( IP(C) ) ) ) )
"""

# ---------------------------------------------------------------------------
# 置换表（与加密标准一致，1-based）
# ---------------------------------------------------------------------------

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

EP_BOX = (4, 1, 2, 3, 2, 3, 4, 1)
SP_BOX = (2, 4, 3, 1)

SBOX_1 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 0, 2),
)

SBOX_2 = (
    (0, 1, 2, 3),
    (2, 3, 1, 0),
    (3, 0, 1, 2),
    (2, 1, 0, 3),
)


# ---------------------------------------------------------------------------
# 基础工具函数
# ---------------------------------------------------------------------------

def permute(bits, table):
    """按 1-based 置换表 table 重排比特串 bits。"""
    return "".join(bits[index - 1] for index in table)


def left_shift(bits, shift_count):
    """对比特串循环左移 shift_count 位。"""
    if not bits:
        return bits
    shift_count %= len(bits)
    return bits[shift_count:] + bits[:shift_count]


def xor(bits_a, bits_b):
    """逐位异或两个等长比特串。"""
    return "".join("1" if a != b else "0" for a, b in zip(bits_a, bits_b))


# ---------------------------------------------------------------------------
# 密钥扩展（加密与解密共用）
# ---------------------------------------------------------------------------

def key_generation(key):
    """由 10-bit 密钥生成两个 8-bit 子密钥 (k1, k2)。

    k_i = P8( Shift^i( P10(K) ) )，i = 1, 2
    """
    permuted_key = permute(key, P10)
    left_half, right_half = permuted_key[:5], permuted_key[5:]

    subkey_1 = permute(
        left_shift(left_half, 1) + left_shift(right_half, 1), P8
    )
    subkey_2 = permute(
        left_shift(left_half, 2) + left_shift(right_half, 2), P8
    )
    return subkey_1, subkey_2


# ---------------------------------------------------------------------------
# 轮函数 F
# ---------------------------------------------------------------------------

def _sbox_lookup(bits, sbox):
    """对 4-bit 输入查 S-Box：首尾两位定行，中间两位定列。"""
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1] + bits[2], 2)
    return format(sbox[row][column], "02b")


def sbox_substitute(bits):
    """高 4-bit 查 SBOX_1、低 4-bit 查 SBOX_2，拼接为 4-bit 输出。"""
    return _sbox_lookup(bits[:4], SBOX_1) + _sbox_lookup(bits[4:], SBOX_2)


def round_function(right_half, subkey):
    """轮函数 F：EP 扩展 -> 与子密钥异或 -> S-Box -> SP 置换。"""
    expanded = permute(right_half, EP_BOX)
    xor_result = xor(expanded, subkey)
    substituted = sbox_substitute(xor_result)
    return permute(substituted, SP_BOX)


def fk(bits, subkey):
    """单轮 f_k：左半与轮函数结果异或，右半保持不变。"""
    left_half, right_half = bits[:4], bits[4:]
    new_left = xor(left_half, round_function(right_half, subkey))
    return new_left + right_half


# ---------------------------------------------------------------------------
# 解密主流程
# ---------------------------------------------------------------------------

def decrypt(ciphertext, key):
    """S-DES 解密主流程，返回明文及各步骤中间值。

    参数：
        ciphertext: 8-bit 二进制密文，如 "00001001"
        key       : 10-bit 二进制密钥，如 "1010000010"

    返回：
        包含明文和各中间值的字典，字段说明见函数末尾注释。
    """
    # 1. 生成子密钥（与加密完全一致）
    subkey_1, subkey_2 = key_generation(key)

    # 2. 初始置换 IP（与加密相同）
    initial_permutation = permute(ciphertext, IP)

    # 3. 第 1 轮 f_k：使用 k2（关键点！解密顺序与加密相反）
    round_1 = fk(initial_permutation, subkey_2)

    # 4. 左右交换 SW
    swapped = round_1[4:] + round_1[:4]

    # 5. 第 2 轮 f_k：使用 k1
    round_2 = fk(swapped, subkey_1)

    # 6. 最终置换 IP^-1
    plaintext = permute(round_2, IP_INV)

    return {
        "ciphertext": ciphertext,             # 输入的密文
        "key": key,                           # 输入的密钥
        "subkey_1": subkey_1,                 # 扩展出的子密钥 k1
        "subkey_2": subkey_2,                 # 扩展出的子密钥 k2
        "initial_permutation": initial_permutation,  # IP(C)
        "round_1": round_1,                   # 第 1 轮 f_k2 输出
        "swapped": swapped,                   # 左右交换后
        "round_2": round_2,                   # 第 2 轮 f_k1 输出
        "plaintext": plaintext,               # 最终明文 P
    }


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # 先用加密逻辑验证：再写个简易加密，用来生成密文
    def encrypt(plaintext, key):
        subkey_1, subkey_2 = key_generation(key)
        ip = permute(plaintext, IP)
        r1 = fk(ip, subkey_1)
        sw = r1[4:] + r1[:4]
        r2 = fk(sw, subkey_2)
        return permute(r2, IP_INV)

    test_cases = [
        ("00000000", "0000000000"),
        ("11111111", "1111111111"),
        ("10101010", "1010000010"),
        ("01010100", "1010000010"),
    ]

    print("加解密闭环测试：")
    print("-" * 60)
    for pt, k in test_cases:
        ct = encrypt(pt, k)
        pt_back = decrypt(ct, k)["plaintext"]
        status = "✅ 通过" if pt_back == pt else "❌ 失败"
        print("明文 {} -> 密文 {} -> 解密 {}  {}".format(pt, ct, pt_back, status))
    print("-" * 60)
    print("若全部显示 ✅，说明解密逻辑正确。")