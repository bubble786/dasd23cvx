import sys
import os
# 添加项目根目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.join(current_dir, '..')
sys.path.insert(0, project_root)

from MSPM.unreused_prob import unreuse_p
from MSPM.SSPM.pcfg import RulePCFGCreator
from MSPM.utils import random, gen_gilst
from Vault.utils import set_crypto
import struct
import logging
import numpy as np
from MSPM.mspm_config import *
import os
import json
numba_logger = logging.getLogger('numba')
numba_logger.setLevel(logging.WARNING)
#from Golla.configs.configure import *
#from Golla.ngram_creator import NGramCreator
from numba import cuda
from MSPM.SPM.configs.configure import Configure
from MSPM.SPM.ngram_creator import NGramCreator
#from numba import jit
from opts import opts
args = opts().parse()

class Incremental_Encoder:
    """
    1. each encoding sequence has to be chosen randomly (according to sequence probability)
    2. seed sequence has to be padded to certain length (a hyperparameter #len_padded)
    3. modulo of spm and sspm can be different (seed itself is random, unless modulo is discovered)
    4.
    """

    def __init__(self, train=True):
        print("initializing markov encoder ...")
        # initialization of spm
        CONFIG = Configure({'name': '4-gram'}, train=False)
        length, progress_bar = 6, True
        # initialization of gi
        self.gi_lst = gen_gilst()

        self.spm = NGramCreator({
            "name": (
                "NGramCreator, Session: {}, Length: {}, Progress bar: {}".format(CONFIG.NAME, length, progress_bar)),
            "ngram_size": CONFIG.NGRAM_SIZE,
            "training_file": CONFIG.TRAINING_FILE,
            "length": length, # minimum length of password trained for spm
            "laplace_smooth": CONFIG.LAPLACE_SMOOTH,
            "ls_compensation": CONFIG.LS_COMPENATE,
            "progress_bar": progress_bar,
            "train": CONFIG.TRAIN,
        })
        self.spm.load("ip_list")
        self.spm.load("cp_list")
        self.spm.load("ep_list")
        print("single password model loading done ...")

        # initialization of sspm
        self.sspm = RulePCFGCreator(args)
        self.sspm.load()
        #print("single similar password model loading done ...")

    def to_cpu(self):
        self.spm.ip_list = self.spm.ip_list.copy_to_host()
        self.spm.cp_list = self.spm.cp_list.copy_to_host()

    def to_gpu(self):
        with cuda.gpus[args.gpu]:
            self.spm.ip_list = cuda.to_device(self.spm.ip_list)
            self.spm.cp_list = cuda.to_device(self.spm.cp_list)

    def encode_pw(self, concatenation, pw):
        """
            note the password length better falls in the range of [MIN_PW_LENGTH, MAX_PW_LENGTH]
        :param concatenation: of pws in seeds
        :param pw: i+1 th password to be encoded
        :return: concatenation of seeds over all pws
        """
        pw_lst = self.decode_pw(concatenation)
        ith = len(pw_lst) # starting from 1 for f(ith)
        seed, prob = self.spm.encode_pw(pw)
        seed.insert(0, self.encode_pathnum(1, ith))
        if ith > 0:
            prob_lst = [np.log(np.array(prob)).sum() + np.log(unreuse_p(ith))]
            seeds_lst = [seed]
            for i in range(ith):
                seed, prob = self.sspm.encode_pw(pw_lst[i], pw, ith)
                seed.insert(0, self.encode_pathnum(i+2, ith))
                prob = np.log(np.array(prob)).sum() + np.log((1-unreuse_p(ith)) / ith) \
                    if len(prob) != 0 else -np.inf
                prob_lst.append(prob)
                seeds_lst.append(seed)
            prob_lst = np.exp(np.array(prob_lst)) / np.exp(np.array(prob_lst)).sum()
            ind = [i for i in range(len(prob_lst))]
            id_chosen = np.random.choice(ind, p=prob_lst)
            # print('using', str(id_chosen+1) + '/' + str(len(prob_lst)))
            seed = seeds_lst[id_chosen]
        # else:
        #     print('using 1/1')
        concatenation.extend(seed)
        return concatenation

    def encode_pw_frompriorpws(self, pw_lst, pw, pw_lst_spmprob=None):
        """
            note the password length better falls in the range of [MIN_PW_LENGTH, MAX_PW_LENGTH]
        :param concatenation: of pws in seeds
        :param pw: i+1 th password to be encoded
        :return: concatenation of seeds over all pws
        """
        #pw_lst = self.decode_pw(concatenation)
        ith = len(pw_lst) # starting from 1 for f(ith)
        seed, prob = self.spm.encode_pw(pw)
        seed.insert(0, self.encode_pathnum(1, ith))
        independent_flag = 1 # 1 for independently, 0 for dependently encoded seed

        prob_seed_lst = [np.log(np.array(prob)).sum() + (np.log(unreuse_p(ith)) if ith > 0 else 0)]
        seeds_lst = [seed]
        id_chosen = 0
        if ith > 0:
            for i in range(ith):
                seed, prob = self.sspm.encode_pw(pw_lst[i], pw, ith)
                seed.insert(0, self.encode_pathnum(i+2, ith))
                prob = np.log(np.array(prob)).sum() + np.log((1-unreuse_p(ith)) / ith) if len(prob) != 0 else -np.inf
                if prob != -np.inf:
                    ind_pr = np.log(np.array(self.spm.encode_pw(pw_lst[i])[1])).sum() if pw_lst_spmprob is None else pw_lst_spmprob[i]
                    prob += ind_pr
                prob_seed_lst.append(prob)
                seeds_lst.append(seed)
            prob_lst = np.exp(np.array(prob_seed_lst)) / np.exp(np.array(prob_seed_lst)).sum()
            ind = [i for i in range(len(prob_lst))]
            id_chosen = np.random.choice(ind, p=prob_lst)
            #print('using', str(id_chosen+1) + '/' + str(len(prob_lst)))
            if id_chosen != 0:
                independent_flag = 0
            seed = seeds_lst[id_chosen]
            independent_prob = prob_lst[0]
        else:
            independent_prob = 1
            #print('using 1/1')
        return seed, independent_flag, independent_prob, prob_seed_lst[id_chosen]

    def encode_pw_testunit(self, concatenation, pw, tset):
        """
            note the password length better falls in the range of [MIN_PW_LENGTH, MAX_PW_LENGTH]
        :param concatenation: of pws in seeds
        :param pw: i+1 th password to be encoded
        :return: concatenation of seeds over all pws
        """
        pw_lst = tset#self.decode_pw(concatenation)
        assert pw_lst == tset[:len(pw_lst)]
        ith = len(pw_lst) # starting from 1 for f(ith)
        seed, prob = self.spm.encode_pw(pw)
        seed.append(self.encode_pathnum(1, ith))
        if ith > 0:
            prob_lst = [np.log(np.array(prob)).sum() + np.log(unreuse_p(ith))]
            seeds_lst = [seed]
            for i in range(ith):
                seed, prob = self.sspm.encode_pwtest(pw_lst[i], pw, ith)
                if seed.size != 0:
                    seed[-1] = self.encode_pathnum(i+2, ith)
                prob = np.log(np.array(prob)).sum() + np.log((1-unreuse_p(ith)) / ith) \
                    if len(prob) != 0 else -np.inf
                prob_lst.append(prob)
                seeds_lst.append(seed)
            prob_lst = np.exp(np.array(prob_lst)) / np.exp(np.array(prob_lst)).sum()
            ind = [i for i in range(len(prob_lst))]
            id_chosen = np.random.choice(ind, p=prob_lst)
            print('using', str(id_chosen+1) + '/' + str(len(prob_lst)))
            seed = seeds_lst[id_chosen]
        else:
            print('using 1/1')
        concatenation.extend(seed)
        return concatenation

    def decode_pw(self, concatenation, seed=None, i=None):
        """

        :param concatenation: of seeds
        :param seed: the specific seed needed to be decoded
        :return:
        """
        if seed is None: # decode following 'bottom up'
            pw_num = len(concatenation) / SEED_LEN
            pw_lst = []
            for i in range(int(pw_num)):
                seed = concatenation[i*SEED_LEN : (i+1)*SEED_LEN]
                pathnum = self.decode_pathnum(seed.pop(0), len(pw_lst))
                if pathnum == 1: # decode with spm
                    pw_lst.append(self.spm.decode_pw(seed))
                else: # decode with sspm
                    pw_lst.append(self.sspm.decode_pw(seed, pw_lst[pathnum-2], i))
            return pw_lst
        else: # decode with complexity of log(n) 'up bottom'
            assert i is not None
            i_ = []
            seed_lst = [seed]
            while True:
                seed_tmp = seed_lst[-1].pop(0) # remove path seed: MAX_PW_LENGTH => MAX_PW_LENGTH-1
                pathnum = self.decode_pathnum(seed_tmp, i)
                i_.append(i)
                if pathnum == 1:  # decode with spm
                    pw = self.spm.decode_pw(seed_lst.pop(-1))
                    i_.pop(-1)
                    break
                else:  # decode with sspm
                    i = pathnum - 2
                    seed_lst.append(concatenation[i*SEED_LEN : (i+1)*SEED_LEN])

            while len(seed_lst) != 0:
                assert len(i_) == len(seed_lst)
                pw = self.sspm.decode_pw(seed_lst.pop(-1), pw, i_.pop(-1))
            return pw

    def encode_pathnum(self, i, tot_ind): # 1, ith+1  or  i+2, ith+1
        """
            note: tot needs to be gi_lst[i] for the decode unambiguity (when incorrect mpw comes)
        :param i: i-th path for encode (0<i<num_pws)
        :param tot_ind: every index of encodings has corresponding tot for decoding purpose
        :return: path choice seed
        """
        tot = self.gi_lst[tot_ind][-1]
        l_pt = self.gi_lst[tot_ind][i-1]
        r_pt = self.gi_lst[tot_ind][i] - 1
        return self.sspm.convert2seed(random.randint(l_pt, r_pt), tot)

    def decode_pathnum(self, seed, tot_ind):
        """

        :param seed:
        :return: i-th path to decode (0<i<num_pws)
        """
        tot = self.gi_lst[tot_ind][-1]
        decode = seed % tot
        cum = np.array(self.gi_lst[tot_ind]) - decode
        cum = (cum * np.roll(cum, -1))[:-1]  # roll: <--
        return (cum.argmin() + 1)

    def encode_encrypt(self, vault, mpw):
        """

        :param vault: list of plaintext
        :param mpw: master password
        :return: ciphertext list
        """
        concat = []
        for pw in vault:
            concat = self.encode_pw(concat, pw)
        #concat = list(np.array(concat) / self.spm.ls_compensa_scale)
        aes = set_crypto(mpw)
        return aes.encrypt(struct.pack('{}L'.format(len(concat)), *concat)), len(concat)

    def decrypt_decode(self, vault, mpw, len_conca):
        """

        :param vault: ciphertext sequence (not a list maybe!)
        :param mpw: master password
        :return: plaintext list
        """
        aes = set_crypto(mpw)
        seed = aes.decrypt(vault)
        seed = struct.unpack('{}L'.format(len_conca), seed)
        #seed = list(np.array(seed) * self.spm.ls_compensa_scale)
        #print(len(seed), seed)
        assert len(seed) % SEED_LEN == 0
        pws = self.decode_pw(list(seed))
        return pws

def main():
    vault = {}
    flst = os.listdir(SOURCE_PATH + '/data/pastebin/fold2_pb')
    for fname in flst:
        f = open(os.path.join(SOURCE_PATH + '/data/pastebin/fold2_pb', fname))
        vault.update(json.load(f))
    incre_ecoder = Incremental_Encoder()
    for vault_id in vault:
        print(vault[vault_id])
        conca = []
        for pw in vault[vault_id]:
            if lencheck(pw):
                print('dropping => pw of length', len(pw))
                vault[vault_id].remove(pw)
        for i in range(len(vault[vault_id])):
            conca = incre_ecoder.encode_pw(conca, vault[vault_id][i])
            print('encoding pw:', vault[vault_id][i], '-> seed:', conca[-SEED_LEN:])
            pw = incre_ecoder.decode_pw(conca, conca[-SEED_LEN:], i)
            print('decoding pw:', pw)
            assert pw == vault[vault_id][i]

# 随机采样种子作为n+1个pw的seed,生成new seed
def gen_one_password(origin_vault, encoder):
    
    test_vault = origin_vault
    
    incre_encoder = encoder
    # print(f"编码器导入成功")

    # ==================== 编码测试 ====================

    concatenation = []  
    for i, password in enumerate(test_vault):
        concatenation = encoder.encode_pw(concatenation, password)

    # print(f"  当前总种子长度: {len(concatenation)}")
    
    # 生成新密码
    # print(f"生成新密码ing...")
    gen_pw = None
    while True:
        # 随机采样,从0-SEED_MAX_RANGE中随机选择SEED_LEN个整数作为随机种子
        random_seed = np.random.randint(0, SEED_MAX_RANGE, SEED_LEN).tolist()
        # 从种子的第一个元素解码路径编号
        ith = len(test_vault)  # 当前密码位置索引
        path_seed = random_seed[0]
        decoded_path = encoder.decode_pathnum(path_seed, ith)
        actual_seed = random_seed[1:]  # 移除路径标识位，得到实际编码种子
        gen_pw = encoder.decode_pw(concatenation, random_seed, ith)
        # print(f"解码路径编号: {decoded_path}")

        # ==================== 步骤3：根据路径生成密码 ====================
        generation_info = {}
        if decoded_path == 1:
            # 路径1：独立生成（SPM模型）
            # print("选择路径: 独立生成 (SPM)")
            try:
                new_password = encoder.spm.decode_pw(actual_seed)
                generation_info = {
                    'path': 'SPM独立生成',
                    'path_number': 1,
                    'source_password': None,
                    'probability': unreuse_p(ith) if ith > 0 else 1.0,
                    'description': f'使用SPM模型独立生成新密码'
                }
            except Exception as e:
                print(f"SPM解码失败: {e}")
            gen_pw = new_password
            new_vault = test_vault + [gen_pw]
            return new_vault, gen_pw  
        else:
            # 路径2-N：基于重用生成（SSPM模型）
            if decoded_path > ith + 1:
                # print(f"警告: 解码路径 {decoded_path} 超出范围，调整为路径 1（独立生成）")
                new_password = encoder.spm.decode_pw(actual_seed)
                generation_info = {
                    'path': 'SPM独立生成（路径修正）',
                    'path_number': 1,
                    'source_password': None,
                    'probability': unreuse_p(ith) if ith > 0 else 1.0,
                    'description': f'原路径超出范围，改用独立生成'
                }
            else:
                # 计算重用的源密码索引
                source_index = decoded_path - 2
                source_password = test_vault[source_index]
                
                # print(f"选择路径: 基于重用生成 (SSPM)")
                # print(f"源密码索引: {source_index}, 源密码: '{source_password}'")
                
                try:
                    new_password = encoder.sspm.decode_pw(actual_seed, source_password, ith)
                    reuse_prob = (1 - unreuse_p(ith)) / ith if ith > 0 else 0
                    generation_info = {
                        'path': 'SSPM重用生成',
                        'path_number': decoded_path,
                        'source_password': source_password,
                        'source_index': source_index,
                        'probability': reuse_prob,
                        'description': f'基于密码"{source_password}"使用SSPM模型生成相似密码'
                    }
                except Exception as e:
                    print(f"SSPM解码失败: {e}")
                    # 回退到SPM独立生成
                    print("回退到SPM独立生成")
                    new_password = encoder.spm.decode_pw(actual_seed)
                    generation_info = {
                        'path': 'SPM独立生成（SSPM失败回退）',
                        'path_number': 1,
                        'source_password': None,
                        'probability': unreuse_p(ith) if ith > 0 else 1.0,
                        'description': f'SSPM失败，回退到独立生成'
                    }
        if len(gen_pw) >= 3 and len(gen_pw) <= 20:  # 确保密码长度至少为3
            break

    # print(f"生成新pw: {gen_pw}")
    new_vault = test_vault + [gen_pw]
    # print(f"新vault: {new_vault}")
    
    return new_vault, gen_pw


# def gen_n_password_tail(original_vault, encoder, n):
#     """生成n个新密码,固定在尾索引采样

#     Args:
#         original_vault (_type_): _description_
#         encoder (_type_): _description_
#         n (_type_): _description_

#     Returns:
#         _type_: _description_
#     """
#     print(f"基于MSPM生成 {n} 个新密码")
#     new_vault = original_vault.copy()
#     new_passwords = []
#     for _ in range(n):
#         new_vault, gen_pw = gen_one_password(original_vault, encoder)
#         new_passwords.append(gen_pw)
#     # print(f"original_vault: {original_vault}")
#     # print(f"new_passwords: {new_passwords}")
#     new_vault = new_vault + new_passwords
#     # print(f"new_vault: {new_vault}")
#     return new_passwords,new_vault

def gen_n_password_random(original_vault, encoder, n):
    """生成n个新密码,随机索引采样

    Args:
        original_vault (_type_): _description_
        encoder (_type_): _description_
        n (_type_): _description_

    Returns:
        _type_: _description_
    """
    print(f"基于MSPM生成 {n} 个新密码")
    new_vault = original_vault.copy()
    new_passwords = []
    for _ in range(n):
        sample_index = np.random.randint(0, len(new_vault))
        cur_vault = new_vault[:sample_index]  # 采样当前索引前的密码作为上文
        new_vault, gen_pw = gen_one_password(cur_vault, encoder)
        new_passwords.append(gen_pw)
    return new_passwords

if __name__ == '__main__':
    main()