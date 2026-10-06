from sdes import encrypt
import time

def brute_force(plain_bin8: str, target_cipher_bin8: str):
    """
    关卡4：暴力破解S-DES
    :param plain_bin8: 8位二进制明文字符串，例："10111001"
    :param target_cipher_bin8: 8位目标密文字符串
    :return: 匹配密钥列表、运行耗时
    """
    start_time = time.time()
    matched_keys = []

    # 遍历全部10bit密钥，0~1023，共1024种
    for key_int in range(0, 1024):
        key_bin = bin(key_int)[2:].zfill(10)
        # 调用sdes的encrypt，入参都是字符串
        result = encrypt(plain_bin8, key_bin)
        cipher_result = result["ciphertext"]
        if cipher_result == target_cipher_bin8:
            matched_keys.append(key_bin)

    end_time = time.time()
    run_cost = end_time - start_time

    print("=" * 50)
    print(f"✅ 暴力破解完成")
    print(f"⏱ 耗时：{run_cost:.4f} 秒")
    print(f"🔑 找到匹配密钥：{matched_keys}")
    print("=" * 50)
    return matched_keys, run_cost


def find_key_collision(plain_bin8: str):
    """
    关卡5：查找S-DES密钥碰撞
    :param plain_bin8: 固定8bit明文字符串
    :return: 碰撞结果列表
    """
    cipher_map = {}

    for key_int in range(0, 1024):
        key_bin = bin(key_int)[2:].zfill(10)
        result = encrypt(plain_bin8, key_bin)
        cipher_str = result["ciphertext"]

        if cipher_str not in cipher_map:
            cipher_map[cipher_str] = []
        cipher_map[cipher_str].append(key_bin)

    collision_result = []
    for cipher_text, key_list in cipher_map.items():
        if len(key_list) >= 2:
            collision_result.append({
                "cipher": cipher_text,
                "keys": key_list
            })

    print("=" * 50)
    print(f"✅ 密钥碰撞检索完成，明文：{plain_bin8}")
    if len(collision_result) == 0:
        print("本次测试没有找到密钥碰撞")
    else:
        for item in collision_result:
            print(f"密文 {item['cipher']} ，对应多个密钥：{item['keys']}")
    print("=" * 50)
    return collision_result


if __name__ == "__main__":
    print("==== S-DES 测试工具 ====")
    print("1 - 关卡4：暴力破解")
    print("2 - 关卡5：密钥碰撞分析")
    choice = input("请输入功能序号(1/2)：")

    if choice == "1":
        p_input = input("请输入8bit明文二进制：")
        c_input = input("请输入8bit密文二进制：")
        brute_force(p_input, c_input)
    elif choice == "2":
        p_input = input("请输入8bit明文二进制：")
        find_key_collision(p_input)
    else:
        print("输入错误，请重新运行程序")
