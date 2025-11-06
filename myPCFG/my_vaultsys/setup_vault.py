#!/usr/bin/env python3
"""
scheme A vault system setup
make fake copy
encode copy by sg family
enc seeds as MCs by PBE
"""
import os
import sys
sys.path.append('.')
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
import hashlib
import string
import time
import copy
import struct
import secrets
from collections import defaultdict, Counter
import math
from itertools import combinations
from datetime import datetime
import json

from helper import random, convert2group
import honeyvault_config as hny_config
from my_vaultsys.utils import PBE_AES
from Crypto.Util import Counter
from pcfg.pcfg import TrainedGrammar, SubGrammar
# from sgfamily_config import *

# TRUE_PASSWORD_COUNT = 6    # 真密码个数
# FALSE_PASSWORD_COUNT = 12  # 假密码个数
# T数量请在offline_guess_v2.py中设置
# SG_INPUT_PASSWORD_COUNT = TRUE_PASSWORD_COUNT

script_dir = os.path.dirname(os.path.abspath(__file__))
version = 'setup'
output_dir = os.path.join(script_dir, 'result_' + version, datetime.now().strftime('%y%m%d%H%M')) + os.sep

# 随机生成mpw len=16
def generate_random_mpw(length=16):
    """生成完全随机的字母数字组合MPW"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

class MyVaultSystem:
    def __init__(self, T, real_vault, true_pw_cnt, false_pw_cnt, btg=None, sgf_cnt=16):
        self.sgf_cnt = sgf_cnt
        self.tg = btg if btg else TrainedGrammar()
        self.subgrammars = {}
        self.sg_input_passwords = {}  # 记录每个SubGrammar的输入密码
        self.true_passwords = []  # 存储真实密码
        self.all_copies = {}  # 存储所有T份copy
        self.mpw2sg = {}  # 主密码到SubGrammar的映射
        self.pbe = PBE_AES(count=1)
        self.T = T  # 构造过程fake copy总数
        self.true_pw_cnt = true_pw_cnt
        self.false_pw_cnt = false_pw_cnt
        self.real_vault = real_vault  # 真实密码集
        self.sg_input_password_count = self.true_pw_cnt + self.false_pw_cnt  # 每个SubGrammar的输入密码数
        self.tag_random_input = 0
        if self.tag_random_input == 1:
            self.RANDOM_PW_SET = load_password_set()

    def hash_function(self, data):
        """通用hash函数"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return int(hashlib.sha256(data).hexdigest(), 16)
    
    def create_password_set(self):
        """创建密码集PS：TRUE_PASSWORD_COUNT个真密码 + FALSE_PASSWORD_COUNT个假密码"""
        total_needed = self.true_pw_cnt+ self.false_pw_cnt
        if len(self.RANDOM_PW_SET) < total_needed:
            raise ValueError(f"RANDOM_PW_SET只有{len(self.RANDOM_PW_SET)}个密码，但需要{total_needed}个密码")
        
        # 随机选择真密码和假密码，确保不重复
        all_passwords = random.sample(self.RANDOM_PW_SET, total_needed)
        true_passwords = all_passwords[:self.true_pw_cnt]
        false_passwords = all_passwords[self.true_pw_cnt:]
        
        PS = true_passwords + false_passwords
        self.true_passwords = true_passwords
        self.real_vault = true_passwords  # 真实vault就是真实密码

        print("真密码 ({}个): {}".format(self.true_pw_cnt, true_passwords))
        print("假密码 ({}个): {}".format(self.false_pw_cnt, false_passwords))
        print("密码集PS ({}个): {}".format(len(PS), PS))
        
        return PS, true_passwords, false_passwords
    
    def verify_subgrammar_independence(self):
        """验证SubGrammar之间是否独立"""
        print("验证SubGrammar独立性...")
        
        # 检查语法规则是否不同
        for i in range(len(self.subgrammars) - 1):
            sg1 = self.subgrammars[i]
            sg2 = self.subgrammars[i + 1]
            
            # 比较语法规则的内存地址
            if id(sg1.G) == id(sg2.G):
                print(f"警告：SubGrammar {i} 和 {i+1} 共享同一个语法对象！")
                return False
        
        print("✓ 所有SubGrammar都是独立的")
        return True
    
    def create_subgrammars(self, PS, true_passwords):
        """创建self.sgf_cnt个SubGrammar，确保每个真实密码至少存在于1个sg的original_passwords"""
        print(f"创建SubGrammar family,size = {self.sgf_cnt}...")
        
        # SubGrammar 0: 使用TRUE_PASSWORD_COUNT个真密码
        tg_copy = copy.deepcopy(self.tg)
        sg0 = SubGrammar(tg_copy)
        sg0.update_grammar(*true_passwords)
        self.subgrammars[0] = sg0
        self.sg_input_passwords[0] = true_passwords.copy()
        # print("SubGrammar 0: 使用真密码 {}".format(true_passwords))
        
        # 跟踪每个真实密码是否已被包含在某个sg中
        true_pw_coverage = {pw: [0] for pw in true_passwords}  # 初始sg0已包含所有真密码
        
        # SubGrammar family: 从PS中随机选择SG_INPUT_PASSWORD_COUNT个不重复的密码
        used_combinations = set()
        
        for i in range(1, self.sgf_cnt):
            # 生成新的密码组合，确保组合间不重复
            while True:
                # 从PS中随机选择SG_INPUT_PASSWORD_COUNT个不重复的密码
                original_passwords = random.sample(PS, self.sg_input_password_count)
                
                # # 检查组合内是否有重复密码
                # if len(set(original_passwords)) != self.sg_input_password_count:
                #     continue
                    
                # # 将密码组合转换为元组并排序，用于去重比较
                password_tuple = tuple(original_passwords)
                
                if password_tuple not in used_combinations:
                    used_combinations.add(password_tuple)
                    break
            tg_copy = copy.deepcopy(self.tg)
            sg = SubGrammar(tg_copy)
            sg.update_grammar(*original_passwords)
            self.subgrammars[i] = sg
            self.sg_input_passwords[i] = original_passwords.copy()
            
            # 更新真实密码覆盖情况
            for pw in original_passwords:
                if pw in true_pw_coverage:
                    true_pw_coverage[pw].append(i)
            
            # print("SubGrammar {}: 使用密码 {}".format(i, original_passwords))
        
        # # 验证每个真实密码都至少存在于一个sg中
        # print("\n验证真实密码覆盖情况:")
        # for pw, sg_list in true_pw_coverage.items():
        #     print(f"真实密码 '{pw}' 存在于SubGrammar: {sg_list}")
        #     if len(sg_list) == 0:
        #         raise ValueError(f"真实密码 '{pw}' 未被任何SubGrammar包含！")
        
        # print(f"✓ 16个SubGrammar创建完成，所有真实密码都有覆盖")
        return true_pw_coverage
    
    def generate_real_copy(self, real_mpw):
        """生成真实copy - 每个密码用相同的MPW"""
        print(f"real mpw: {real_mpw}")

        # 计算real copy的索引
        real_index = self.hash_function(real_mpw) % self.T + 1
        print(f"real copy index: {real_index}")
        
        sg_id = 0  # 真实copy使用SubGrammar 0
        mpw_to_sg_mapping = {}  # 记录MPW到SubGrammar的映射
        mpw_to_sg_mapping[real_mpw] = sg_id
        
        # 为每个密码生成加密密文
        real_copy = []
        for i, pw in enumerate(self.real_vault):
            # 真实copy所有密码都用SubGrammar 0编码
            seed = self.subgrammars[sg_id].encode_pw(pw)
            
            # 用真实MPW加密
            encrypted_seed = self.pbe.encrypt(seed, real_mpw)
            real_copy.append(encrypted_seed)

            # print(f"  密码 '{pw}' 位置{i} 使用 SubGrammar {sg_id} 编码，用 '{real_mpw}' 加密")

        copy_info = {
            'index': real_index,
            'type': 'real',
            'copy': real_copy,
            'base_mpw': real_mpw,
            'mpws': [real_mpw],  # 只有一个真实MPW
            'mpw_to_sg_mapping': mpw_to_sg_mapping
        }
        
        return copy_info, real_index, mpw_to_sg_mapping

    def generate_mpw_single(self, target_index, T, mpw_length=16):
        target = target_index % T  # 目标: hash % T == target
        prefix_len = mpw_length - 4  # 前缀12位随机，后缀4位用于爆破
        prefix = generate_random_mpw(prefix_len)

        for _ in range(T * 10):  # 最多尝试 10T 次，命中概率 > 99%
            suffix = generate_random_mpw(mpw_length - prefix_len)
            mpw = prefix + suffix
            h = int(hashlib.sha256(mpw.encode()).hexdigest(), 16)
            if h % T == target:
                return mpw

        raise ValueError(f"无法为索引 {target_index} 生成合适的fake MPW")
    
    # def generate_fake_copy(self, target_index):
    #     """为指定索引生成fake copy，每个位置使用不同的MPW和随机SubGrammar"""
        
    #     # 初始化映射字典
    #     mpw_to_sg_mapping = {}
        
    #     # 为每个真实密码生成唯一的mpw
    #     fake_mpws = []
    #     gen_tag = 2 # 1,2
    #     TRUE_PASSWORD_COUNT = self.true_pw_cnt
    #     if gen_tag == 1:
    #         for i in range(TRUE_PASSWORD_COUNT):
    #             attempts = 0
    #             while attempts < 10000:  # 防止无限循环
    #                 # 生成随机的mpw候选
    #                 # candidate_mpw = f"fake_mpw_{target_index}_{i}_{random.randint(0, 999999)}"
    #                 candidate_mpw = generate_random_mpw(16)
    #                 if self.hash_function(candidate_mpw) % self.T + 1 == target_index:
    #                     fake_mpws.append(candidate_mpw)
    #                     break
    #                 attempts += 1
                
    #             if attempts >= 10000:
    #                 raise ValueError(f"无法为索引 {target_index} 生成合适的fake MPW")
    #     elif gen_tag == 2:
    #         for i in range(TRUE_PASSWORD_COUNT):
    #             candidate_mpw = self.generate_mpw_single(target_index, self.T)
    #             fake_mpws.append(candidate_mpw)
        
    #     # 为每个真实密码生成加密密文
    #     fake_copy = []
        
    #     for i, pw in enumerate(self.real_vault):
    #         # 随机选择一个包含该密码的SubGrammar
    #         available_sgs = []
    #         for sg_id, passwords in self.sg_input_passwords.items():
    #             if pw in passwords and sg_id != 0:
    #                 available_sgs.append(sg_id)
            
    #         if available_sgs:
    #             sg_id = random.choice(available_sgs)
    #         else:
    #             sg_id = random.choice(range(1, len(self.subgrammars)))  # 备用选择
            
    #         # 用选定的sg编码密码
    #         seed = self.subgrammars[sg_id].encode_pw(pw)
            
    #         # 用对应的fake mpw加密
    #         encrypted_seed = self.pbe.encrypt(seed, fake_mpws[i])
    #         fake_copy.append(encrypted_seed)
            
    #         # 记录映射关系
    #         mpw_to_sg_mapping[fake_mpws[i]] = sg_id
            
    #         # print(f"  密码 '{pw}' 位置{i} 使用 SubGrammar {sg_id} 编码，用 '{fake_mpws[i]}' 加密")
        
    #     copy_info = {
    #         'index': target_index,
    #         'type': 'fake',
    #         'copy': fake_copy,
    #         'mpws': fake_mpws,
    #         'mpw_to_sg_mapping': mpw_to_sg_mapping
    #     }
        
    #     return copy_info, mpw_to_sg_mapping
    
    def generate_fake_copy_with_mpws(self, target_index, fake_mpws):
        """使用预生成的MPWs生成fake copy"""
        mpw_to_sg_mapping = {}
        fake_copy = []
        
        for i, pw in enumerate(self.real_vault):
            # 随机选择一个包含该密码的SubGrammar
            available_sgs = []
            for sg_id, passwords in self.sg_input_passwords.items():
                if pw in passwords and sg_id != 0:
                    available_sgs.append(sg_id)
            
            if available_sgs:
                sg_id = random.choice(available_sgs)
            else:
                sg_id = random.choice(range(1, len(self.subgrammars)))
            
            # 用选定的sg编码密码
            seed = self.subgrammars[sg_id].encode_pw(pw)
            
            # 用对应的fake mpw加密
            encrypted_seed = self.pbe.encrypt(seed, fake_mpws[i])
            fake_copy.append(encrypted_seed)
            
            # 记录映射关系
            mpw_to_sg_mapping[fake_mpws[i]] = sg_id
        
        copy_info = {
            'index': target_index,
            'type': 'fake',
            'copy': fake_copy,
            'mpws': fake_mpws,
            'mpw_to_sg_mapping': mpw_to_sg_mapping
        }

        return copy_info, mpw_to_sg_mapping

    def generate_all_fake_mpws(self, T, true_pw_cnt, mpw_length=16):
        """批量生成所有需要的fake MPWs"""
        print("生成fake MPWs...")
        
        # 预分配结果字典 {target_index: [mpw1, mpw2, ...]}
        fake_mpws_dict = {}
        found_count = {}  # 记录每个索引已找到的MPW数量
        
        # 初始化
        for i in range(1, T + 1):
            fake_mpws_dict[i] = []
            found_count[i] = 0
        
        total_needed = (T - 1) * true_pw_cnt  # 总共需要的MPW数量
        found_total = 0
        attempts = 0
        max_attempts = total_needed * 100  # 最大尝试次数
        
        while found_total < total_needed and attempts < max_attempts:
            # 生成随机MPW
            mpw = generate_random_mpw(mpw_length)
            h = int(hashlib.sha256(mpw.encode()).hexdigest(), 16)
            target_index = (h % T) + 1
            
            # 检查是否需要这个索引的MPW
            if (found_count[target_index] < true_pw_cnt and 
                target_index != self.get_real_copy_index()):  # 排除real copy索引
                fake_mpws_dict[target_index].append(mpw)
                found_count[target_index] += 1
                found_total += 1
                
                # if found_total % 1000 == 0:
                #     print(f"已生成 {found_total}/{total_needed} 个MPW...")
            
            attempts += 1
        
        if found_total < total_needed:
            # 对缺失的索引进行补充生成
            for target_index in range(1, T + 1):
                if (found_count[target_index] < true_pw_cnt and 
                    target_index != self.get_real_copy_index()):
                    needed = true_pw_cnt - found_count[target_index]
                    for _ in range(needed):
                        mpw = self.generate_mpw_single_fallback(target_index, T, mpw_length)
                        fake_mpws_dict[target_index].append(mpw)
        
        return fake_mpws_dict

    def generate_mpw_single_fallback(self, target_index, T, mpw_length=16):
        """单个MPW生成的回退方法"""
        target = target_index - 1
        
        for retry in range(10):  # 最多重试10次不同的前缀
            prefix = generate_random_mpw(12)
            for _ in range(T * 20):
                suffix = generate_random_mpw(mpw_length - 12)
                mpw = prefix + suffix
                h = int(hashlib.sha256(mpw.encode()).hexdigest(), 16)
                if h % T == target:
                    return mpw
        
        # 最后的回退：使用计数器确保找到
        import time
        base_mpw = f"fallback_{target_index}_{int(time.time())}_"
        counter = 0
        while True:
            mpw = base_mpw + str(counter).zfill(mpw_length - len(base_mpw))
            if len(mpw) == mpw_length:
                h = int(hashlib.sha256(mpw.encode()).hexdigest(), 16)
                if h % T == target:
                    return mpw
            counter += 1
            if counter > 100000:
                raise ValueError(f"完全无法生成索引 {target_index} 的MPW")
        
    def generate_all_copies(self, real_mpw):
        """生成所有T份copy"""
        
        T = self.T 
        
        # 生成真实copy
        print(f"\n开始生成real copy...")
        real_copy_info, real_index, real_mapping = self.generate_real_copy(real_mpw)
        self.all_copies[real_index] = real_copy_info
        
        # 批量生成所有fake MPWs
        fake_mpws_dict = self.generate_all_fake_mpws(T, self.true_pw_cnt)
    
        # 生成fake copies
        print(f"生成fake copies...")
        fake_count = 0
        for j in range(1, T + 1):
            if j != real_index:  # 跳过真实copy的索引
                fake_mpws = fake_mpws_dict[j]
                fake_copy_info, fake_mapping = self.generate_fake_copy_with_mpws(j, fake_mpws)
                # fake_copy_info, fake_mapping = self.generate_fake_copy(j)
                self.all_copies[j] = fake_copy_info
                fake_count += 1
                
                # if fake_count % 100 == 0:
                #     # print(f"已生成 {fake_count}/{T-1} 个fake copy...")
        
        print(f"✓ 生成完成：1个real copy (索引{real_index}) + {T-1}个fake copy")
    
    def get_copy(self, index):
        """获取指定索引的copy"""
        return self.all_copies.get(index, None)
    
    def get_real_copy_index(self):
        """获取真实copy的索引"""
        for index, copy_info in self.all_copies.items():
            if copy_info['type'] == 'real':
                return index
        return None
    
    def save_to_file(self, filename=None):
        """保存vault system到文件"""
        if filename is None:
            filename = output_dir + 'vault_system.json'
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # 准备要保存的数据（需要序列化处理）
        save_data = {
            'config': {
                'TRUE_PASSWORD_COUNT': self.true_pw_cnt,
                'FALSE_PASSWORD_COUNT': self.false_pw_cnt,
                'T': self.T
            },
            'true_passwords': self.true_passwords,
            'real_vault': self.real_vault,
            'sg_input_passwords': self.sg_input_passwords,
            'real_copy_index': self.get_real_copy_index(),
            'total_copies': len(self.all_copies)
        }
        
        # 保存基本信息（不包含二进制密文数据）
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Vault system信息已保存到 {filename}")
    
    def get_statistics(self):
        """获取系统统计信息"""
        real_count = sum(1 for copy_info in self.all_copies.values() if copy_info['type'] == 'real')
        fake_count = sum(1 for copy_info in self.all_copies.values() if copy_info['type'] == 'fake')
        
        return {
            'total_copies': len(self.all_copies),
            'real_copies': real_count,
            'fake_copies': fake_count,
            'subgrammars': len(self.subgrammars),
            'true_passwords': len(self.true_passwords),
            'real_copy_index': self.get_real_copy_index()
        }

# 从文件读取密码集
def load_password_set():
    """从pw_PB.json文件中加载密码集"""
    try:
        # 构建相对于当前脚本文件的绝对路径
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # data 目录位于上上级目录中
        data_file_path = os.path.join(script_dir, '..', 'data', 'pw_PB.json')
        
        with open(data_file_path, 'r', encoding='utf-8') as f:
            passwords = json.load(f)
        print(f"成功从 {data_file_path} 加载了 {len(passwords)} 个密码")
        return passwords
    except FileNotFoundError:
        print(f"错误：找不到 {data_file_path} 文件")
        raise
    except json.JSONDecodeError:
        print(f"错误：{data_file_path} 文件格式错误")
        raise

# 密码输入来源
# RANDOM_PW_SET = load_password_set()

def main():
    default_T = 1000
    print("setup vault system - " + version)
    
    start_time = time.time()

    # 初始化输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    real_vault = ['123456', '123456789', 'wangsimin', '123456', '3981257619', '626075', '68921820', '951236', '123456789', '6363001', 'thought1', '123456']
    
    # 创建vault system实例
    vault_system = MyVaultSystem(T=default_T, true_pw_cnt=6, false_pw_cnt=12, real_vault=real_vault)

    # 1. 创建密码集
    print(f"Init input pws...")
    PS, true_passwords, false_passwords = vault_system.create_password_set()
    
    # 2. 创建SubGrammar family
    true_pw_coverage = vault_system.create_subgrammars(PS, true_passwords)
    
    # 3. 设置真实用户主密码
    real_MPW = generate_random_mpw(16)
    # real_MPW = "user_real_master_password_2025"  # 真实用户主密码
    print(f"\n真实用户主密码: {real_MPW}")

    print(f"测试模式：生成 {vault_system.T} 份copy进行验证...")
    vault_system.generate_all_copies(real_MPW)
    
    # 5. 验证系统
    print("\n验证vault system:")
    stats = vault_system.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # 6. 测试copy访问
    real_index = vault_system.get_real_copy_index()
    print(f"真实copy索引: {real_index}")
    
    real_copy_info = vault_system.get_copy(real_index)
    if real_copy_info:
        print(f"真实copy类型: {real_copy_info['type']}")
        print(f"真实copy长度: {len(real_copy_info['copy'])}")
    
    # 测试一个fake copy
    for index, copy_info in vault_system.all_copies.items():
        if copy_info['type'] == 'fake':
            print(f"Fake copy {index} 长度: {len(copy_info['copy'])}")
            print(f"Fake copy {index} MPWs数量: {len(copy_info['mpws'])}")
            break
    
    # 7. 保存系统信息
    vault_system.save_to_file()
    
    print(f"\n✓ Vault system构建完成！")
    print(f"  - 总计: {stats['total_copies']} 份copy")
    print(f"  - 真实: {stats['real_copies']} 份")
    print(f"  - 假冒: {stats['fake_copies']} 份")
    print(f"  - SubGrammar数量: {stats['subgrammars']}")

    end_time = time.time()
    total_time = end_time - start_time
    print(f"total time: {total_time:.2f} seconds")

    return vault_system

def checkcall():
    default_T = 1000
    real_vault = ['123456', '123456789', 'wangsimin', '123456', '3981257619', '626075', '68921820', '951236', '123456789', '6363001', 'thought1', '123456']
    
    # 创建vault system实例
    vault_system = MyVaultSystem(T=default_T, true_pw_cnt=6, false_pw_cnt=12, real_vault=real_vault)
    tg = vault_system.tg 
    sg0 = SubGrammar(tg)
    sg1 = SubGrammar(tg)
    vault_system.subgrammars[0] = sg0
    vault_system.subgrammars[1] = sg1
    vault_system.verify_subgrammar_independence()

if __name__ == "__main__":
    checkcall()
    '''
    验证SubGrammar独立性...
    ✓ 所有SubGrammar都是独立的
    '''
