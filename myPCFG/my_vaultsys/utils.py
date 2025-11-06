import random
import numpy as np
from cryptography.hazmat.primitives import hashes
#import torch
from hashlib import sha256
from Crypto.Hash import SHA512, SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1, PBKDF2
from Crypto.Util import Counter
import struct
import secrets
from linecache import getline

salt = secrets.token_hex(8)
ctr = Counter.new(8 * 16, initial_value=int(1))

class PBE_AES:
    def __init__(self, count=1):
        # 在初始化时生成固定的加密参数
        self.salt = secrets.token_bytes(16)  # 使用 token_bytes 而不是 token_hex
        self.ctr = Counter.new(128, initial_value=1)
        self.PBKDF2_count = count  # 可以调整迭代次数以平衡安全性和性能
    
    def encrypt(self, seed, mpw):
        """加密方法"""
        # 使用实例的 salt 和 counter
        key = PBKDF2(mpw, self.salt, 32, count=self.PBKDF2_count) # generally set count = 100000 / 1
        cipher = AES.new(key, AES.MODE_CTR, counter=self.ctr)
        
        # 将 seed 列表转换为 bytes
        seed_bytes = struct.pack('{}L'.format(len(seed)), *seed)
        
        # 加密并返回 salt + 密文
        ciphertext = cipher.encrypt(seed_bytes)
        return self.salt + ciphertext
    
    def decrypt(self, encrypted_data, mpw):
        """解密方法"""
        # 提取 salt 和密文
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # 重新生成密钥和计数器
        key = PBKDF2(mpw, salt, 32, count=self.PBKDF2_count) # generally set count = 100000 / 1
        ctr = Counter.new(128, initial_value=1)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        
        # 解密
        decrypted_bytes = cipher.decrypt(ciphertext)
        
        # 转换回整数列表
        num_integers = len(decrypted_bytes) // 8
        seed = list(struct.unpack('{}L'.format(num_integers), decrypted_bytes))
        return seed


def permutation(raw_lst, pw_num, pin, mpw, recover=False, kernel=3, stride=1, MAX_PWS=500, MAX_LEN=10000):

    digest = hashes.Hash(hashes.SHA256())
    mpw = mpw if isinstance(mpw, str) else str(mpw)
    pin = pin if isinstance(pin, str) else str(pin)
    digest.update(bytes((mpw+pin).encode("ascii")))
    random.seed(digest.finalize())
    seq = [random.randint(0, MAX_PWS) for _ in range(MAX_LEN)]
    rolls = [vali for vali in seq if vali < pw_num][:pw_num+kernel-1]
    rolls = minpooling1d(rolls)
    if not recover:
        for i in range(pw_num - 1, -1, -1):
            raw_lst[i], raw_lst[rolls[i]] = raw_lst[rolls[i]], raw_lst[i]
    else:
        for i in range(pw_num):
            raw_lst[i], raw_lst[rolls[i]] = raw_lst[rolls[i]], raw_lst[i]
    return raw_lst

'''def minpooling1d_torch(inp, size=3, stride=1):

    inp = -torch.from_numpy(np.array(inp))[None, None].float()
    inp = -torch.nn.functional.max_pool1d(inp, kernel_size=size, stride=stride)
    return list(inp.squeeze().long().numpy())'''

def minpooling1d(feature_map, size=3, stride=1):
    #Preparing the output of the pooling operation.
    pool_out = np.zeros((np.uint16((len(feature_map)-size)/stride+1)))
    r2 = 0
    for r in np.arange(0,len(feature_map)-size+1, stride):
        pool_out[r2] = np.min([feature_map[r:r+size]])
        r2 = r2 +1
    return list(pool_out.astype(np.long))


#salt = 0x12345678.to_bytes(8, 'little')
def set_crypto(mpw, salt = salt, ctr = ctr):
    # salt = hash(pin).to_bytes(8, 'little')
    key = PBKDF2(mpw, salt, 32, hmac_hash_module=SHA256)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes


def main():
    mpw_tmp1 = 'awearwE2EA24'
    mpw_tmp2 = '131easd12'
    mpw_tmp3 = 'QERQ3DCXxca$e'
    msg1 = list(range(40))
    msg2 = list(range(40,80))
    msg3 = list(range(80,120))
    cpht = bytearray()
    salt = secrets.token_hex(8)

    ctr = Counter.new(8 * 16, initial_value=int(1))
    aes = set_crypto(mpw_tmp1, salt=salt, ctr=ctr)
    cpht += aes.encrypt(struct.pack('{}L'.format(len(msg1)), *msg1))
    ctr = Counter.new(8 * 16, initial_value=int(21))
    aes = set_crypto(mpw_tmp2, salt=salt, ctr=ctr)
    cpht += aes.encrypt(struct.pack('{}L'.format(len(msg2)), *msg2))
    ctr = Counter.new(8 * 16, initial_value=int(41))
    aes = set_crypto(mpw_tmp3, salt=salt, ctr=ctr)
    cpht += aes.encrypt(struct.pack('{}L'.format(len(msg3)), *msg3))

    ctr = Counter.new(8 * 16, initial_value=int(1))
    aes = set_crypto(mpw_tmp2, salt=salt, ctr=ctr)
    msg = aes.decrypt(cpht[: 80*8])
    msg = list(struct.unpack('{}L'.format(len(msg)//8), msg))[40:80]
    print(msg == msg2)

if __name__ == '__main__':
    main()