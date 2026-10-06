# -*- coding: utf-8 -*-
"""S-DES 加密算法核心模块（纯算法，无界面依赖）。

所有置换表均为 1-based，取值与作业 README 第 4 节给定的标准一致。
"""

# 密钥扩展置换
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
LEFT_SHIFT_1 = (2, 3, 4, 5, 1)
LEFT_SHIFT_2 = (3, 4, 5, 1, 2)

# 初始置换与最终置换
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

# 轮函数置换与 S-Box
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


def permute(bits, table):
    """按 1-based 置换表 table 重排比特串 bits。"""
    return "".join(bits[index - 1] for index in table)


def left_shift(bits, shift_count):
    """对比特串循环左移 shift_count 位。"""
    if not bits:
        return bits
    shift_count %= len(bits)
    return bits[shift_count:] + bits[:shift_count]


def key_generation(key):
    """由 10-bit 密钥生成两个 8-bit 子密钥 (k1, k2)。

    依据规范 2.3.3：k_i = P8(Shift^i(P10(K)))，i = 1, 2。
    先对 K 做 P10 置换，再分别循环左移 1 位、2 位，最后经 P8 置换。
    """
    permuted_key = permute(key, P10)
    left_half, right_half = permuted_key[:5], permuted_key[5:]

    # 循环左移 1 位，经 P8 得到 k1
    subkey_1 = permute(
        left_shift(left_half, 1) + left_shift(right_half, 1), P8
    )
    # 循环左移 2 位，经 P8 得到 k2
    subkey_2 = permute(
        left_shift(left_half, 2) + left_shift(right_half, 2), P8
    )
    return subkey_1, subkey_2


def _sbox_lookup(bits, sbox):
    """对 4-bit 输入查 S-Box：首尾两位定行，中间两位定列。"""
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1] + bits[2], 2)
    return format(sbox[row][column], "02b")


def sbox_substitute(bits):
    """高 4-bit 查 SBOX_1、低 4-bit 查 SBOX_2，拼接为 4-bit 输出。"""
    return _sbox_lookup(bits[:4], SBOX_1) + _sbox_lookup(bits[4:], SBOX_2)


def _xor(bits_a, bits_b):
    """逐位异或两个等长比特串。"""
    return "".join("1" if a != b else "0" for a, b in zip(bits_a, bits_b))


def round_function(right_half, subkey):
    """轮函数 F：EP 扩展 -> 与子密钥异或 -> S-Box -> SP 置换。"""
    expanded = permute(right_half, EP_BOX)
    xor_result = _xor(expanded, subkey)
    substituted = sbox_substitute(xor_result)
    return permute(substituted, SP_BOX)


def fk(bits, subkey):
    """单轮 f_k：左半与轮函数结果异或，右半保持不变。"""
    left_half, right_half = bits[:4], bits[4:]
    new_left = _xor(left_half, round_function(right_half, subkey))
    return new_left + right_half


def encrypt(plaintext, key):
    """S-DES 加密主流程，返回密文及各步骤中间值。

    C = IP^-1( f_k2( SW( f_k1( IP(P) ) ) ) )
    """
    subkey_1, subkey_2 = key_generation(key)

    initial_permutation = permute(plaintext, IP)
    round_1 = fk(initial_permutation, subkey_1)
    swapped = round_1[4:] + round_1[:4]
    round_2 = fk(swapped, subkey_2)
    ciphertext = permute(round_2, IP_INV)

    return {
        "plaintext": plaintext,
        "key": key,
        "subkey_1": subkey_1,
        "subkey_2": subkey_2,
        "initial_permutation": initial_permutation,
        "round_1": round_1,
        "swapped": swapped,
        "round_2": round_2,
        "ciphertext": ciphertext,
    }
