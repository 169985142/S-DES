# -*- coding: utf-8 -*-
"""S-DES 命令行版加解密程序（不依赖 PyQt5）。"""

import sdes_decrypt as sdes


def input_bits(prompt, length):
    """读取指定长度的二进制串，非法则重新输入。"""
    while True:
        value = input(prompt).strip()
        if len(value) == length and all(b in "01" for b in value):
            return value
        print("  [!] 必须为 {}-bit 二进制数（仅含 0 和 1），请重新输入。".format(length))


def show_steps(result, mode):
    """打印中间结果。"""
    print("\n" + "=" * 50)
    if mode == "encrypt":
        print("【加密流程】")
        print("明文 P        :", result["plaintext"])
        print("密钥 K        :", result["key"])
        print("子密钥 k1     :", result["subkey_1"])
        print("子密钥 k2     :", result["subkey_2"])
        print("IP(P)         :", result["initial_permutation"])
        print("第 1 轮 f_k1  :", result["round_1"])
        print("左右交换 SW   :", result["swapped"])
        print("第 2 轮 f_k2  :", result["round_2"])
        print("密文 C        :", result["ciphertext"])
    else:
        print("【解密流程】")
        print("密文 C        :", result["ciphertext"])
        print("密钥 K        :", result["key"])
        print("子密钥 k1     :", result["subkey_1"])
        print("子密钥 k2     :", result["subkey_2"])
        print("IP(C)         :", result["initial_permutation"])
        print("第 1 轮 f_k2  :", result["round_1"])
        print("左右交换 SW   :", result["swapped"])
        print("第 2 轮 f_k1  :", result["round_2"])
        print("明文 P        :", result["plaintext"])
    print("=" * 50 + "\n")


def main():
    print("=" * 50)
    print("       S-DES 加解密程序（命令行版）")
    print("=" * 50)

    while True:
        print("请选择操作：")
        print("  1. 加密")
        print("  2. 解密")
        print("  3. 退出")
        choice = input("输入序号：").strip()

        if choice == "3":
            print("已退出。")
            break

        if choice == "1":
            plaintext = input_bits("请输入 8-bit 明文：", 8)
            key = input_bits("请输入 10-bit 密钥：", 10)
            result = sdes.encrypt(plaintext, key)
            show_steps(result, "encrypt")
            print(">>> 密文：{}\n".format(result["ciphertext"]))

        elif choice == "2":
            ciphertext = input_bits("请输入 8-bit 密文：", 8)
            key = input_bits("请输入 10-bit 密钥：", 10)
            result = sdes.decrypt(ciphertext, key)
            show_steps(result, "decrypt")
            print(">>> 明文：{}\n".format(result["plaintext"]))

        else:
            print("  [!] 无效输入，请重新选择。\n")


if __name__ == "__main__":
    main()