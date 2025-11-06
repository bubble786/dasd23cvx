import time
import random
import string
import sys
import numpy as np

# 将父目录添加到sys.path中，以便可以导入my_vaultsys.utils
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from my_vaultsys.utils import PBE_AES

# 定义一个大的整数作为随机数上限 (对应于C语言的 unsigned long)
MAXINT = 2**32 - 1

def generate_random_mpw(length=12):
    """生成一个指定长度的随机字符串作为mpw"""
    letters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(letters) for i in range(length))

def test_pbe_aes_performance(iterations=100, PBKDF2_count=100000):
    """
    测试PBE_AES类的加密和解密平均时间。
    """
    encryption_times = []
    decryption_times = []

    print(f"🚀 开始进行 PBE_AES 性能测试 (重复 {iterations} 次, PBKDF2_count={PBKDF2_count})...")

    for i in range(iterations):
        # 1. 准备测试数据
        pbe = PBE_AES(count=PBKDF2_count)
        mpw = generate_random_mpw()
        seed = [random.randint(0, MAXINT) for _ in range(100)]

        # 2. 测试加密时间
        start_time_encrypt = time.perf_counter()
        encrypted_data = pbe.encrypt(seed, mpw)
        end_time_encrypt = time.perf_counter()
        encryption_times.append(end_time_encrypt - start_time_encrypt)

        # 3. 测试解密时间
        start_time_decrypt = time.perf_counter()
        decrypted_seed = pbe.decrypt(encrypted_data, mpw)
        end_time_decrypt = time.perf_counter()
        decryption_times.append(end_time_decrypt - start_time_decrypt)

        # 验证解密是否正确
        assert seed == decrypted_seed, f"第 {i+1} 次迭代解密失败！"

    # 4. 计算并打印平均时间
    avg_encrypt_time = np.mean(encryption_times)
    avg_decrypt_time = np.mean(decryption_times)

    print("\n✅ 测试完成！")
    print("==========================================")
    print(f"平均加密时间: {avg_encrypt_time:.6f} 秒")
    print(f"平均解密时间: {avg_decrypt_time:.6f} 秒")
    print("==========================================")

if __name__ == "__main__":
    test_pbe_aes_performance(PBKDF2_count=100000)
    test_pbe_aes_performance(PBKDF2_count=1)
