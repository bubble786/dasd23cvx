#!/usr/bin/env python3
"""
Honey Vault Attack Program
攻击程序设计：针对honey vault系统的离线攻击
包含Type I和Type II两种测试类型，模拟真实攻击场景
"""

import os
import sys
sys.path.append('.')
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# 添加当前目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

import time
import numpy as np
from scipy.sparse import csr_matrix
import hashlib
import traceback

from pcfg.pcfg import TrainedGrammar, SubGrammar
from setup_vault import MyVaultSystem, generate_random_mpw
from helper import random, convert2group
import honeyvault_config as hny_config
from collections import defaultdict, Counter
from itertools import combinations
from datetime import datetime
from my_vaultsys.utils import PBE_AES
from dte.honey_enc import DTE
from honeyvault_config import MAX_INT
    
class TimeProfiler:
    """时间分析器"""
    def __init__(self):
        self.timers = {}
        
    def start_timer(self, name):
        """启动计时器"""
        self.timers[name] = {'start': time.time(), 'end': None, 'duration': None}
        
    def end_timer(self, name):
        """停止计时器并记录持续时间"""
        if name in self.timers and self.timers[name]['start'] is not None:
            self.timers[name]['end'] = time.time()
            self.timers[name]['duration'] = self.timers[name]['end'] - self.timers[name]['start']
            return self.timers[name]['duration']
        return 0
    
    def get_stats(self, name):
        """获取特定计时器的统计信息"""
        return self.timers.get(name)
    
    def print_summary(self):
        """打印所有计时器的摘要"""
        print("\n--- Time Profiling Summary ---")
        for name, stats in self.timers.items():
            if stats['duration'] is not None:
                print(f"{name}: {stats['duration']:.4f} seconds")
        print("----------------------------\n")

class sgf:
    def __init__(self,T,real_pws, dummy_pws, intersection_attack_result_dir, tag = 'withreal', mpwset:dict = None):
        self.T = T
        self.vault_system = None
        self.all_mpws = []  # 存储所有T个MPW (包含1个真实MPW + T-1个fake MPW)
        self.real_mpw = None
        self.mpw_to_sg_map = {}  # MPW到SubGrammar的映射表
        self.fixed_mappings = {}  # 固定映射表
        self.test_results = []
        self.type1_tests = []  # Type I 测试结果
        self.type2_tests = []  # Type II 测试结果
        self.pbe = PBE_AES()
        self.all_decoded_passwords = set()  # 记录所有解码出现过的密码全集
        self.profiler = TimeProfiler()  # 时间分析器
        self.real_pws = real_pws
        self.real_vault = real_pws
        print(f"Init sgf class...")
        # print(f"len(real_pws): {len(real_pws)}")
        self.real_pw_cnt = len(real_pws)
        self.dummy_pws = dummy_pws
        self.intersection_attack_result_dir = intersection_attack_result_dir
        self.tag = tag
        self.mpwset = mpwset
    
    def acquire_realvault_seed(self, real_pws):
        vaultseed = []
        real_sg_id = 0
        for pw in real_pws:
            seed = self.vault_system.subgrammars[real_sg_id].encode_pw(pw)
            vaultseed.extend(seed)

        return vaultseed
    
    def gen_decoyvaults(self, mpws):
        decoy_vaults, probs_spm_mspm = [], []

        for mpw in mpws:
            if mpw in self.mpw_position_map:# type I
                ts = time.time()
                mpw_info = self.mpw_position_map[mpw]
                copy_index = mpw_info['copy_index']
                copy_info = self.vault_system.get_copy(copy_index)
                if copy_info is None:
                    print(f"typeI警告: Copy {copy_index} 不存在，跳过MPW {mpw}")
                    continue
                sg_id = self.mpw_to_subgrammar(mpw)
                dv = []
                for encrypted_seed in copy_info['copy']:
                    seed = self.pbe.decrypt(encrypted_seed, mpw)
                    ith_pw, ith_prob = self.vault_system.subgrammars[sg_id].decode_pw_withprob(seed)
                    dv.append(ith_pw)
                    probs_spm_mspm.append([ith_prob,ith_prob])
                decoy_vaults.append(dv)
                # print("password decode:", ts - time.time())
            else:# type II
                ts = time.time()
                copy_index = self.hash_function(mpw) % self.T + 1
                copy_info = self.vault_system.get_copy(copy_index)
                if copy_info is None:
                    print(f"typeII警告: Copy {copy_index} 不存在，跳过MPW {mpw}")
                    continue
                sg_id = self.mpw_to_subgrammar(mpw)
                dv = []
                for encrypted_seed in copy_info['copy']:
                    seed = self.pbe.decrypt(encrypted_seed, mpw)
                    ith_pw, ith_prob = self.vault_system.subgrammars[sg_id].decode_pw_withprob(seed)
                    dv.append(ith_pw)
                    probs_spm_mspm.append([ith_prob,ith_prob])
                decoy_vaults.append(dv)
                # print("password decode:", ts - time.time())
        return decoy_vaults, probs_spm_mspm
        
    def hash_function(self, data):
        """通用hash函数"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return int(hashlib.sha256(data).hexdigest(), 16)
    
    def setup_vault_system(self, setup_T:int, btg:TrainedGrammar):
        """步骤1: 构造vault system并收集所有MPW"""
        print("步骤1: 构造Vault System...")        
        # 导入密码集
        # PS, true_passwords, false_passwords = self.vault_system.create_password_set()
        true_passwords = self.real_pws
        false_passwords = self.dummy_pws
        PS = true_passwords + false_passwords

        # 创建vault system实例
        true_pw_cnt = len(true_passwords)
        false_pw_cnt = len(false_passwords)
        sgf_cnt = 16
        self.vault_system = MyVaultSystem(setup_T, true_passwords, 
                                          true_pw_cnt, false_pw_cnt, btg=btg, sgf_cnt=sgf_cnt)

        # 创建SubGrammar family
        self.vault_system.create_subgrammars(PS, true_passwords)
        
        # 设置真实用户主密码
        self.real_mpw = generate_random_mpw(16)  # 生成16位随机MPW
        
        # 生成所有T份copy
        self.vault_system.generate_all_copies(self.real_mpw)
        
        # 收集所有MPW
        self.all_mpws = []
        self.mpw_position_map = {}  # MPW到其在vault中位置的映射
        self.mpw_to_sg_map = {}     # MPW到SubGrammar的映射
        
        # 收集真实copy的MPW
        real_copy_index = self.vault_system.get_real_copy_index()
        if real_copy_index is not None:
            real_copy_info = self.vault_system.get_copy(real_copy_index)
            if real_copy_info and 'mpws' in real_copy_info:
                # real copy只有一个MPW
                real_mpw = real_copy_info['mpws'][0]  # 取第一个（也是唯一的）MPW
                self.real_mpw = real_mpw
                self.all_mpws.append(real_mpw)
                self.mpw_position_map[real_mpw] = {
                    'copy_index': real_copy_index,
                    'position': 0,  # real copy所有密码都在同一个"位置"（用同一个MPW）
                    'type': 'real'
                }
                # 从映射表中获取SubGrammar ID
                if 'mpw_to_sg_mapping' in real_copy_info:
                    self.mpw_to_sg_map[real_mpw] = real_copy_info['mpw_to_sg_mapping'][real_mpw]
        
        # 收集所有fake copy的MPW
        for copy_info in self.vault_system.all_copies.values():
            if copy_info['type'] == 'fake':
                for i, mpw in enumerate(copy_info['mpws']):
                    self.all_mpws.append(mpw)
                    self.mpw_position_map[mpw] = {
                        'copy_index': copy_info['index'],
                        'position': i,
                        'type': 'fake'
                    }
                    # 从映射表中获取SubGrammar ID
                    if 'mpw_to_sg_mapping' in copy_info:
                        self.mpw_to_sg_map[mpw] = copy_info['mpw_to_sg_mapping'][mpw]
        
        print(f"✓ 收集到总计 {len(self.all_mpws)} 个MPW")
        print(f"  - 真实MPW: 1个")
        print(f"  - Fake MPW: {len(self.all_mpws) - 1}个")
        
        # # 保存vault system信息到文件
        # self.save_vault_system_info()
        
        return True
    
    def setup_sgf(self, real_pws, dummy_pws, num_T):
        """步骤1: 构造vault system并收集所有MPW"""
        T = num_T
        print("步骤1: 构造Honey Vault System...")
        
        print("全局参数T：", T)
        
        # 创建vault system实例
        self.vault_system = MyVaultSystem(T)
        
        # 创建密码集
        PS = real_pws + dummy_pws
        
        # 创建SubGrammar family
        self.vault_system.create_subgrammars(PS, real_pws)

        # 设置真实用户主密码
        self.real_mpw = generate_random_mpw(16)  # 生成16位随机MPW
        # self.real_mpw = real_mpw

        # 生成所有T份copy
        self.vault_system.generate_all_copies(self.real_mpw)
        
        # 收集所有MPW
        self.all_mpws = []
        self.mpw_position_map = {}  # MPW到其在vault中位置的映射
        self.mpw_to_sg_map = {}     # MPW到SubGrammar的映射
        
        # 收集真实copy的MPW
        real_copy_index = self.vault_system.get_real_copy_index()
        if real_copy_index is not None:
            real_copy_info = self.vault_system.get_copy(real_copy_index)
            if real_copy_info and 'mpws' in real_copy_info:
                # real copy只有一个MPW
                real_mpw = real_copy_info['mpws'][0]  # 取第一个（也是唯一的）MPW
                self.real_mpw = real_mpw
                self.all_mpws.append(real_mpw)
                self.mpw_position_map[real_mpw] = {
                    'copy_index': real_copy_index,
                    'position': 0,  # real copy所有密码都在同一个"位置"（用同一个MPW）
                    'type': 'real'
                }
                # 从映射表中获取SubGrammar ID
                if 'mpw_to_sg_mapping' in real_copy_info:
                    self.mpw_to_sg_map[real_mpw] = real_copy_info['mpw_to_sg_mapping'][real_mpw]
        
        # 收集所有fake copy的MPW
        for copy_info in self.vault_system.all_copies.values():
            if copy_info['type'] == 'fake':
                for i, mpw in enumerate(copy_info['mpws']):
                    self.all_mpws.append(mpw)
                    self.mpw_position_map[mpw] = {
                        'copy_index': copy_info['index'],
                        'position': i,
                        'type': 'fake'
                    }
                    # 从映射表中获取SubGrammar ID
                    if 'mpw_to_sg_mapping' in copy_info:
                        self.mpw_to_sg_map[mpw] = copy_info['mpw_to_sg_mapping'][mpw]
        
        return True
        
    def design_mpw_to_sg_mapping(self):
        """步骤2: MPW到SubGrammar的映射已在vault生成时建立"""
        print("步骤2: 建立MPW到sgf的映射...")
        
        print(f"✓ 已建立 {len(self.mpw_to_sg_map)} 个MPW到sgf的映射")
        
        # 统计映射分布
        sg_counts = {}
        for sg_id in self.mpw_to_sg_map.values():
            sg_counts[sg_id] = sg_counts.get(sg_id, 0) + 1
        
        # print("SubGrammar使用分布:")
        # for sg_id in sorted(sg_counts.keys()):
        #     print(f"  SubGrammar {sg_id}: {sg_counts[sg_id]} 个MPW")
        
        # 验证真实MPW都映射到SG0
        real_mpws = [mpw for mpw, info in self.mpw_position_map.items() if info['type'] == 'real']
        real_sg_mappings = [self.mpw_to_sg_map.get(mpw, -1) for mpw in real_mpws]
        real_sg0_count = sum(1 for sg_id in real_sg_mappings if sg_id == 0)
        
        # print(f"真实copy MPW映射验证: {real_sg0_count}/{len(real_mpws)} 个MPW映射到SubGrammar 0")
        
    def save_vault_system_info(self):
        """保存vault system的详细信息到文件"""
        print(" 保存Vault System信息...")
        
        # 检查vault_system是否已初始化
        if not self.vault_system:
            print("❌ Vault System未初始化，无法保存信息")
            return
        
        # # 确保输出目录存在
        # os.makedirs(self.intersection_attack_result_dir, exist_ok=True)
        
        # 1. 保存所有copy的信息和对应的MPW
        with open(self.intersection_attack_result_dir + 'vault_copies_info.txt', 'w', encoding='utf-8') as f:
            f.write("Vault System Copies Information ")
            f.write("=" * 80 + "\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Copy总数: {len(self.vault_system.all_copies)}\n")
            f.write(f"真实密码数: {self.real_pw_cnt}\n")
            f.write(f"真实MPW: {self.real_mpw}\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            # 保存每个copy的详细信息
            for copy_index in sorted(self.vault_system.all_copies.keys()):
                copy_info = self.vault_system.all_copies[copy_index]
                f.write(f"Copy ID: {copy_index}\n")
                f.write(f"Type: {copy_info['type']}\n")
                
                if copy_info['type'] == 'real':
                    f.write(f"Base MPW: {copy_info.get('base_mpw', 'N/A')}\n")
                    f.write(f"MPWs数量: {len(copy_info.get('mpws', []))}\n")
                    f.write(f"SubGrammar ID: 0 (固定使用SG0)\n")
                    f.write(f"加密密码数量: {len(copy_info['copy'])}\n")
                    f.write("MPWs列表:\n")
                    mpws = copy_info.get('mpws', [])
                    for i, mpw in enumerate(mpws):
                        if i < len(self.vault_system.real_vault):
                            pw = self.vault_system.real_vault[i]
                            f.write(f"  {i+1}. MPW: {mpw}\n")
                            f.write(f"     密码: {pw}\n")
                            f.write(f"     SubGrammar ID: 0\n")
                else:  # fake copy
                    f.write(f"MPWs数量: {len(copy_info['mpws'])}\n")
                    f.write("MPWs列表:\n")
                    for i, mpw in enumerate(copy_info['mpws']):
                        # 找到对应的密码和SubGrammar
                        if i < len(self.vault_system.real_vault):
                            pw = self.vault_system.real_vault[i]
                            # 从映射表中获取SubGrammar ID
                            sg_id = copy_info.get('mpw_to_sg_mapping', {}).get(mpw, -1)
                            f.write(f"  {i+1}. MPW: {mpw}\n")
                            f.write(f"     密码: {pw}\n")
                            f.write(f"     SubGrammar ID: {sg_id}\n")
                
                f.write("-" * 60 + "\n")
        
        # 2. 保存MPW到SubGrammar的映射表
        with open(self.intersection_attack_result_dir + 'mpw_to_sg_mapping.txt', 'w', encoding='utf-8') as f:
            f.write("MPW to SubGrammar Mapping\n")
            f.write("=" * 80 + "\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总映射数量: {len(self.all_mpws)}\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            f.write("真实MPW映射:\n")
            real_copy_index = self.vault_system.get_real_copy_index()
            real_copy_info = self.vault_system.get_copy(real_copy_index)
            if real_copy_info and 'mpws' in real_copy_info:
                for i, mpw in enumerate(real_copy_info['mpws']):
                    pw = self.vault_system.real_vault[i] if i < len(self.vault_system.real_vault) else "N/A"
                    f.write(f"{i+1}. MPW: {mpw}\n")
                    f.write(f"   Copy Index: {real_copy_index}\n")
                    f.write(f"   Position: {i}\n")
                    f.write(f"   密码: {pw}\n")
                    f.write(f"   SubGrammar ID: 0\n")
                    f.write(f"   验证Copy Index: {self.hash_function(mpw) % self.T + 1}\n\n")
            
            f.write("Fake MPW映射:\n")
            fake_count = 0
            for copy_info in self.vault_system.all_copies.values():
                if copy_info['type'] == 'fake':
                    copy_index = copy_info['index']
                    for i, mpw in enumerate(copy_info['mpws']):
                        fake_count += 1
                        if i < len(self.vault_system.real_vault):
                            pw = self.vault_system.real_vault[i]
                            sg_id = copy_info.get('mpw_to_sg_mapping', {}).get(mpw, -1)
                            f.write(f"{fake_count}. MPW: {mpw}\n")
                            f.write(f"   Copy Index: {copy_index}\n")
                            f.write(f"   Position: {i}\n")
                            f.write(f"   密码: {pw}\n")
                            f.write(f"   SubGrammar ID: {sg_id}\n")
                            f.write(f"   验证Copy Index: {self.hash_function(mpw) % self.T + 1}\n\n")
        
        print(f"✓ Vault System信息已保存到:")
        print(f"  - {self.intersection_attack_result_dir}vault_copies_info.txt")
        print(f"  - {self.intersection_attack_result_dir}mpw_to_sg_mapping.txt")
    
    def mpw_to_subgrammar(self, mpw):
        """将MPW映射到SubGrammar ID"""
        # 如果在预建立的映射表中，直接返回
        if mpw in self.mpw_to_sg_map:
            return self.mpw_to_sg_map[mpw]
        
        # 对于新的MPW，在SG1-15中随机选择
        # 使用MPW的哈希值确保一致性
        hash_value = self.hash_function(mpw)
        sg_id = (hash_value % 15) + 1  # 返回1-15之间的值
        
        return sg_id
    
    def execute_type1_tests(self):
        """步骤3.1: 执行Type I测试 - 使用初始化时的正确MPW"""
        print("步骤3.1: 执行Type I测试...")
        
        # 保存Type I测试开始前的MPW信息
        # self.save_type1_test_info_start()
        
        total_start_time = time.time()
        pbe_decrypt_total = 0
        sg_decode_total = 0
        other_operations_total = 0

        print(f"预计需要解密操作: {len(self.all_mpws)} 次测试 × {self.real_pw_cnt} 个密码 = {len(self.all_mpws) * self.real_pw_cnt} 次")
        # print(f"按0.04s/次计算，预计PBE解密时间: {(len(self.all_mpws) * self.real_pw_cnt * 0.04):.1f}秒")
        
        for i, mpw in enumerate(self.all_mpws):
            if i % 10000 == 0:
                elapsed = time.time() - total_start_time
                if i > 0:
                    avg_time_per_test = elapsed / i
                    remaining_tests = len(self.all_mpws) - i
                    eta = remaining_tests * avg_time_per_test
                    print(f"  执行第 {i}/{len(self.all_mpws)} 个Type I测试... "
                          f"已用时 {elapsed:.1f}s | 平均 {avg_time_per_test:.4f}s/测试 | 预计剩余 {eta:.1f}s")
                else:
                    print(f"  执行第 {i}/{len(self.all_mpws)} 个Type I测试...")
            
            try:
                # 计时：哈希计算和copy获取
                self.profiler.start_timer('hash_and_copy_lookup')
                
                # 获取MPW的位置信息
                if mpw not in self.mpw_position_map:
                    print(f"警告：MPW {mpw} 不在位置映射表中")
                    continue
                
                mpw_info = self.mpw_position_map[mpw]
                copy_index = mpw_info['copy_index']
                
                copy_info = self.vault_system.get_copy(copy_index)
                if not copy_info:
                    continue
                    
                sg_id = self.mpw_to_subgrammar(mpw)
                self.profiler.end_timer('hash_and_copy_lookup')
                
                # 对整个copy内的所有加密种子都采用相同的mpw和sg解密解码
                decrypted_vault = []
                success = True
                
                for encrypted_seed in copy_info['copy']:
                    try:
                        self.profiler.start_timer('pbe_decrypt')
                        seed = self.pbe.decrypt(encrypted_seed, mpw)
                        decrypt_time = self.profiler.end_timer('pbe_decrypt')
                        if decrypt_time is not None:
                            pbe_decrypt_total += decrypt_time
                        
                        # 计时：SubGrammar解码
                        self.profiler.start_timer('sg_decode')
                        decoded_pw = self.vault_system.subgrammars[sg_id].decode_pw(seed)
                        decode_time = self.profiler.end_timer('sg_decode')
                        if decode_time is not None:
                            sg_decode_total += decode_time
                        
                        decrypted_vault.append(decoded_pw)
                        
                        # 记录所有解码出现的密码
                        if decoded_pw != "ERROR":
                            self.all_decoded_passwords.add(decoded_pw)
                            
                    except Exception as e:
                        print(f"❌ 解密或解码失败 - {e}")
                        print(f"测试详情: MPW={mpw}, Copy Index={copy_index}, SG ID={sg_id}")
                        traceback.print_exc()
                        sys.exit(1)
                
                # 计时：其他操作
                self.profiler.start_timer('other_type1_ops')
                # 检查是否包含真实密码
                contains_real_pw = any(pw in self.vault_system.real_vault for pw in decrypted_vault if pw != "ERROR")
                
                # 保存所有测试结果，不论是否包含真实密码
                test_result = {
                    'type': 'Type_I',
                    'test_id': f"type1_{i}",
                    'mpw': mpw,
                    'copy_index': copy_index,
                    'sg_id': sg_id,
                    'decrypted_vault': decrypted_vault,
                    'contains_real_pw': contains_real_pw,
                    'success': success,
                    'cross_count': 0
                }
                
                self.type1_tests.append(test_result)
                other_time = self.profiler.end_timer('other_type1_ops')
                if other_time is not None:
                    other_operations_total += other_time
                
            except Exception as e:
                print(f"Type I测试 {i} 失败: {e}")
                continue
        
        total_time = time.time() - total_start_time
        
        print(f"✓ Type I测试完成，共 {len(self.type1_tests)} 个测试")
        print(f"⏱️  Type I 时间统计:")
        print(f"  - 总耗时: {total_time:.2f}s")
        print(f"  - PBE解密: {pbe_decrypt_total:.2f}s ({pbe_decrypt_total/total_time*100:.1f}%)")
        print(f"  - SG解码: {sg_decode_total:.2f}s ({sg_decode_total/total_time*100:.1f}%)")
        print(f"  - 其他操作: {other_operations_total:.2f}s ({other_operations_total/total_time*100:.1f}%)")
        print(f"  - 平均每次测试: {total_time/len(self.all_mpws):.3f}s")
        
        # 保存Type I测试结束后的详细结果
        self.save_type1_test_results()
        
        # 验证逻辑正确性
        verification_passed = self.verify_type1_logic()
        
        # 如果验证失败，进行详细的SubGrammar调试
        if not verification_passed:
            self.debug_subgrammar_encoding()
        
    def verify_type1_logic(self):
        """验证Type I测试逻辑的正确性"""
        print("\n验证Type I满足Assumption1正确性...")
        
        verification_results = []
        correct_count = 0
        total_count = 0
        real_mpw_mismatch = []  # 记录真实MPW的解码不匹配情况
        
        for mpw in self.all_mpws:  # 验证前10个MPW
            if mpw not in self.mpw_position_map:
                continue
                
            total_count += 1
            mpw_info = self.mpw_position_map[mpw]
            copy_index = mpw_info['copy_index']
            position = mpw_info['position']
            mpw_type = mpw_info['type']
            
            # 获取copy和SubGrammar
            copy_info = self.vault_system.get_copy(copy_index)
            sg_id = self.mpw_to_subgrammar(mpw)
            
            # 如果是真实MPW，需要验证整个vault的解码结果
            if mpw_type == 'real':
                # print(f"\n🔍 验证真实MPW: {mpw}")
                # print(f"   Copy Index: {copy_index}")
                # print(f"   SubGrammar ID: {sg_id}")
                # print(f"   期望的real vault: {self.vault_system.real_vault}")
                
                # 解码整个copy
                decoded_vault = []
                for i, encrypted_seed in enumerate(copy_info['copy']):
                    try:
                        seed = self.pbe.decrypt(encrypted_seed, mpw)
                        decoded_pw = self.vault_system.subgrammars[sg_id].decode_pw(seed)
                        decoded_vault.append(decoded_pw)
                        
                        expected_pw = self.vault_system.real_vault[i]
                        if decoded_pw != expected_pw:
                            real_mpw_mismatch.append({
                                'position': i,
                                'expected': expected_pw,
                                'decoded': decoded_pw,
                                'mpw': mpw,
                                'sg_id': sg_id
                            })
                            # print(f"   ❌ 位置{i}: 期望'{expected_pw}', 解码得到'{decoded_pw}'")
                        else:
                            # print(f"   ✅ 位置{i}: '{decoded_pw}' 正确")
                            pass
                    except Exception as e:
                        decoded_vault.append("ERROR")
                        print(f"   ❌ 位置{i}: 解码失败 - {e}")
                
                # print(f"   解码结果: {decoded_vault}")
                
                # 检查整体是否匹配
                is_correct = (decoded_vault == self.vault_system.real_vault)
                if is_correct:
                    correct_count += 1
                    print(f"   ✅ 真实MPW整体验证通过")
                else:
                    print(f"   ❌ 真实MPW整体验证失败")
                
                verification_results.append({
                    'mpw': mpw[:20] + "...",
                    'type': mpw_type,
                    'copy_index': copy_index,
                    'position': 'all',
                    'sg_id': sg_id,
                    'expected_pw': str(self.vault_system.real_vault),
                    'decoded_pw': str(decoded_vault),
                    'correct': is_correct
                })
            else:
                # 对于fake MPW，只验证单个位置
                try:
                    encrypted_seed = copy_info['copy'][position]
                    seed = self.pbe.decrypt(encrypted_seed, mpw)
                    decoded_pw = self.vault_system.subgrammars[sg_id].decode_pw(seed)
                    
                    # 检查是否解码出预期的密码
                    expected_pw = self.vault_system.real_vault[position]
                    is_correct = (decoded_pw == expected_pw)
                    
                    if is_correct:
                        correct_count += 1
                    
                    verification_results.append({
                        'mpw': mpw[:20] + "...",
                        'type': mpw_type,
                        'copy_index': copy_index,
                        'position': position,
                        'sg_id': sg_id,
                        'expected_pw': expected_pw,
                        'decoded_pw': decoded_pw,
                        'correct': is_correct
                    })
                    
                except Exception as e:
                    verification_results.append({
                        'mpw': mpw[:20] + "...",
                        'type': mpw_type,
                        'copy_index': copy_index,
                        'position': position,
                        'sg_id': sg_id,
                        'expected_pw': self.vault_system.real_vault[position] if position < len(self.vault_system.real_vault) else "N/A",
                        'decoded_pw': f"ERROR: {e}",
                        'correct': False
                    })
        
        # 保存验证结果
        with open(self.intersection_attack_result_dir + 'type1_logic_verification.txt', 'w', encoding='utf-8') as f:
            f.write("Type I Logic Verification Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"验证时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"验证MPW数量: {total_count}\n")
            f.write(f"正确解码数量: {correct_count}\n")
            f.write(f"正确率: {correct_count/total_count*100:.2f}%\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            # 如果有真实MPW的解码不匹配，详细记录
            if real_mpw_mismatch:
                f.write("🚨 真实MPW解码不匹配问题:\n")
                f.write("=" * 60 + "\n")
                f.write(f"真实MPW: {self.real_mpw}\n")
                f.write(f"期望的real vault: {self.vault_system.real_vault}\n")
                f.write(f"SubGrammar ID: {self.mpw_to_subgrammar(self.real_mpw)}\n\n")
                f.write("不匹配的位置详情:\n")
                for mismatch in real_mpw_mismatch:
                    f.write(f"  位置 {mismatch['position']}: 期望 '{mismatch['expected']}', 解码得到 '{mismatch['decoded']}'\n")
                f.write("\n这表明SubGrammar编码/解码过程存在问题，需要进一步调查！\n\n")
            
            for result in verification_results:
                f.write(f"MPW: {result['mpw']}\n")
                f.write(f"  Type: {result['type']}\n")
                f.write(f"  Copy Index: {result['copy_index']}\n")
                f.write(f"  Position: {result['position']}\n")
                f.write(f"  SubGrammar ID: {result['sg_id']}\n")
                f.write(f"  Expected Password: {result['expected_pw']}\n")
                f.write(f"  Decoded Password: {result['decoded_pw']}\n")
                f.write(f"  Correct: {result['correct']}\n")
                f.write("-" * 60 + "\n")
        
        if real_mpw_mismatch:
            print(f"🚨 发现真实MPW解码不匹配问题！共 {len(real_mpw_mismatch)} 个位置不匹配")
            for mismatch in real_mpw_mismatch:
                print(f"   位置{mismatch['position']}: 期望'{mismatch['expected']}' != 解码'{mismatch['decoded']}'")
        
        print(f"✓ 验证完成：{correct_count}/{total_count} 个MPW正确解码")
        print(f"  验证结果已保存到: {self.intersection_attack_result_dir}type1_logic_verification.txt")
        
        return len(real_mpw_mismatch) == 0  # 返回是否通过验证
    
    def debug_subgrammar_encoding(self):
        """调试SubGrammar编码解码过程"""
        print("\n🔍 调试SubGrammar编码解码过程...")
        
        # 测试SubGrammar 0对真实密码的编码解码
        sg0 = self.vault_system.subgrammars[0]
        
        print(f"SubGrammar 0 input passwords: {self.vault_system.sg_input_passwords[0]}")
        print(f"Real vault: {self.vault_system.real_vault}")
        
        debug_file = self.intersection_attack_result_dir + 'subgrammar_debug.txt'
        with open(debug_file, 'w', encoding='utf-8') as f:
            f.write("SubGrammar Encoding/Decoding Debug Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"调试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"SubGrammar 0 input passwords: {self.vault_system.sg_input_passwords[0]}\n")
            f.write(f"Real vault: {self.vault_system.real_vault}\n\n")
            
            for i, pw in enumerate(self.vault_system.real_vault):
                print(f"测试密码 {i}: '{pw}'")
                f.write(f"密码 {i}: '{pw}'\n")
                
                try:
                    # 编码
                    encoded_seed = sg0.encode_pw(pw)
                    print(f"  编码结果: {encoded_seed}")
                    f.write(f"  编码结果: {encoded_seed}\n")
                    
                    # 解码
                    decoded_pw = sg0.decode_pw(encoded_seed)
                    print(f"  解码结果: '{decoded_pw}'")
                    f.write(f"  解码结果: '{decoded_pw}'\n")
                    
                    # 验证一致性
                    is_consistent = (pw == decoded_pw)
                    status = "✅ 一致" if is_consistent else "❌ 不一致"
                    print(f"  状态: {status}")
                    f.write(f"  状态: {status}\n")
                    
                    if not is_consistent:
                        print(f"  🚨 发现编码解码不一致！")
                        f.write(f"  🚨 编码解码不一致问题！\n")
                        f.write(f"     原始: '{pw}'\n")
                        f.write(f"     解码: '{decoded_pw}'\n")
                        
                        # 检查密码是否在SubGrammar 0的input中
                        in_sg0 = pw in self.vault_system.sg_input_passwords[0]
                        f.write(f"     在SG0输入中: {in_sg0}\n")
                        
                except Exception as e:
                    error_msg = f"  ❌ 编码解码失败: {e}"
                    print(error_msg)
                    f.write(error_msg + "\n")
                
                f.write("\n")
        
        print(f"✓ SubGrammar调试完成，结果保存到: {debug_file}")
        
    def execute_type2_tests(self):
        """步骤3.2: 执行Type II测试 - 随机猜测MPW"""
        print("\n步骤3.2: 执行Type II测试...")
        
        total_start_time = time.time()
        
        # 计算t1 = Type I测试的实际数量（即收集到的所有MPW数量）
        t1 = len(self.all_mpws)
        total_type2_tests = 9 * t1  # Type II总计输入9*t1个随机MPW
        
        type2_test_id = 0
        
        print(f"Type I测试数量 t1 = {t1}")
        print(f"Type II测试数量 = 9*t1 = 9*{t1} = {total_type2_tests}")
        print(f"预计解密操作: {total_type2_tests * self.real_pw_cnt} 次")
        # print(f"按0.04s/次计算，预计PBE解密时间: {(total_type2_tests * self.real_pw_cnt * 0.04):.1f}秒")

        pbe_decrypt_total = 0
        sg_decode_total = 0
        random_mpw_gen_total = 0
        other_operations_total = 0
        
        # 执行9*t1次Type II测试
        for test_index in range(total_type2_tests):
            if test_index % 10000 == 0:
                elapsed = time.time() - total_start_time
                if test_index > 0:
                    avg_time_per_test = elapsed / test_index
                    remaining_tests = total_type2_tests - test_index
                    eta = remaining_tests * avg_time_per_test
                    print(f"  执行第 {test_index}/{total_type2_tests} 个Type II测试... "
                          f"已用时 {elapsed:.1f}s | 平均 {avg_time_per_test:.3f}s/测试 | 预计剩余 {eta:.1f}s")
                else:
                    print(f"  执行第 {test_index}/{total_type2_tests} 个Type II测试...")
            
            # 计时：生成随机MPW
            self.profiler.start_timer('random_mpw_gen')
            random_mpw = generate_random_mpw(16)
            mpw_gen_time = self.profiler.end_timer('random_mpw_gen')
            if mpw_gen_time is not None:
                random_mpw_gen_total += mpw_gen_time
            
            # 计算该MPW对应的copy index
            copy_index = self.hash_function(random_mpw) % self.T + 1
            copy_info = self.vault_system.get_copy(copy_index)
            if not copy_info:
                continue
            
            # 获取映射的SubGrammar
            sg_id = self.mpw_to_subgrammar(random_mpw)
            
            try:
                # 尝试解密并解码
                decrypted_vault = []
                success = True
                
                for encrypted_seed in copy_info['copy']:
                    try:
                        # 计时：PBE解密
                        self.profiler.start_timer('pbe_decrypt_type2')
                        seed = self.pbe.decrypt(encrypted_seed, random_mpw)
                        decrypt_time = self.profiler.end_timer('pbe_decrypt_type2')
                        if decrypt_time is not None:
                            pbe_decrypt_total += decrypt_time
                        
                        # 计时：SubGrammar解码
                        self.profiler.start_timer('sg_decode_type2')
                        decoded_pw = self.vault_system.subgrammars[sg_id].decode_pw(seed)
                        decode_time = self.profiler.end_timer('sg_decode_type2')
                        if decode_time is not None:
                            sg_decode_total += decode_time
                        
                        decrypted_vault.append(decoded_pw)
                        
                        # 记录所有解码出现的密码
                        if decoded_pw != "ERROR":
                            self.all_decoded_passwords.add(decoded_pw)
                    except:
                        decrypted_vault.append("ERROR")
                        success = False
                
                # 计时：其他操作
                self.profiler.start_timer('other_type2_ops')
                # 检查是否包含真实密码
                contains_real_pw = any(pw in self.vault_system.real_vault for pw in decrypted_vault if pw != "ERROR")
                
                # 保存所有测试结果，不论是否包含真实密码
                test_result = {
                    'type': 'Type_II',
                    'test_id': f"type2_{type2_test_id}",
                    'mpw': random_mpw,
                    'copy_index': copy_index,
                    'sg_id': sg_id,
                    'decrypted_vault': decrypted_vault,
                    'contains_real_pw': contains_real_pw,
                    'success': success,
                    'cross_count': 0
                }

                self.type2_tests.append(test_result)
                type2_test_id += 1
                
                other_time = self.profiler.end_timer('other_type2_ops')
                if other_time is not None:
                    other_operations_total += other_time
                    
            except Exception as e:
                # 确保计时器被正确结束
                other_time = self.profiler.end_timer('other_type2_ops')
                if other_time is not None:
                    other_operations_total += other_time
                
                # 即使失败也记录，保持测试总数为9*t1
                test_result = {
                    'type': 'Type_II',
                    'test_id': f"type2_{type2_test_id}",
                    'mpw': random_mpw,
                    'copy_index': copy_index,
                    'sg_id': sg_id,
                    'decrypted_vault': ["ERROR"] * self.real_pw_cnt,
                    'contains_real_pw': False,
                    'success': False,
                    'cross_count': 0
                }
                self.type2_tests.append(test_result)
                type2_test_id += 1
                continue
        
        total_time = time.time() - total_start_time
        
        print(f"✓ Type II测试完成，共 {len(self.type2_tests)} 个有效测试")
        print(f"⏱️  Type II 时间统计:")
        print(f"  - 总耗时: {total_time:.2f}s")
        print(f"  - PBE解密: {pbe_decrypt_total:.2f}s ({pbe_decrypt_total/total_time*100:.1f}%)")
        print(f"  - SG解码: {sg_decode_total:.2f}s ({sg_decode_total/total_time*100:.1f}%)")
        print(f"  - MPW生成: {random_mpw_gen_total:.2f}s ({random_mpw_gen_total/total_time*100:.1f}%)")
        print(f"  - 其他操作: {other_operations_total:.2f}s ({other_operations_total/total_time*100:.1f}%)")
        print(f"  - 总尝试次数: {total_type2_tests}")
        print(f"  - 成功率: {len(self.type2_tests)/total_type2_tests*100:.2f}%")
        
        # 保存Type II测试结束后的详细结果
        self.save_type2_test_results(total_type2_tests)
    
    def calculate_cross_counts(self):
        """步骤4: 计算交集测试并排名"""
        print("\n步骤4: 计算交集测试...")
        
        # 合并所有测试
        all_tests = self.type1_tests + self.type2_tests
        
        if self.tag == 'noreal':
            # 去掉real copy的测试
            self.test_results = [test for test in all_tests if test['copy_index'] != self.vault_system.get_real_copy_index()]
        else:
            # 保留所有测试，包括real copy
            self.test_results = all_tests
              
        # 计算每个测试的交集计数
        for i, test1 in enumerate(self.test_results):
            if i % 10000 == 0:
                print(f"  计算交集进度: {i}/{len(self.test_results)}")
                
            cross_count = 0
            test1_passwords = set(pw for pw in test1['decrypted_vault'] if pw != "ERROR")

            for j, test2 in enumerate(self.test_results):
                if i != j:  # 不与自己比较
                    test2_passwords = set(pw for pw in test2['decrypted_vault'] if pw != "ERROR")
                    if test1_passwords & test2_passwords:  # 有交集
                        cross_count += 1
            
            test1['cross_count'] = cross_count
        
        # 按交集计数排序
        self.test_results.sort(key=lambda x: x['cross_count'], reverse=True)
        
        # 找到真实MPW测试的排名
        real_mpw_rank = None
        for i, test in enumerate(self.test_results):
            if test['mpw'] == self.real_mpw:
                real_mpw_rank = i + 1
                break
        
        print(f"✓ 交集计算完成")
        print(f"  - 总测试数: {len(self.test_results)}")
        print(f"  - 真实MPW测试排名: {real_mpw_rank}")
        
        return real_mpw_rank
    
    def calculate_cross_counts_optimized_large(self):
        """步骤4: 针对大规模数据的优化交集计算"""
        print("\n步骤4: 计算交集测试（大规模优化版）...")
        
        # 合并所有测试
        all_tests = self.type1_tests + self.type2_tests
        
        if self.tag == 'noreal':
            self.test_results = [test for test in all_tests if test['copy_index'] != self.vault_system.get_real_copy_index()]
        else:
            self.test_results = all_tests
        
        print(f"  总测试数: {len(self.test_results)}")
        
        # 预处理：为每个测试创建密码集合
        print("  预处理密码集合...")
        test_password_sets = []
        for i, test in enumerate(self.test_results):
            if i % 100000 == 0:
                print(f"    预处理进度: {i}/{len(self.test_results)}")
            password_set = set(pw for pw in test['decrypted_vault'] if pw != "ERROR")
            test_password_sets.append(password_set)
        
        # 构建密码到测试索引的倒排索引
        print("  构建倒排索引...")
        password_to_tests = {}
        for test_idx, password_set in enumerate(test_password_sets):
            if test_idx % 100000 == 0:
                print(f"    索引构建进度: {test_idx}/{len(test_password_sets)}")
            for password in password_set:
                if password not in password_to_tests:
                    password_to_tests[password] = []
                password_to_tests[password].append(test_idx)
        
        print(f"  构建完成，共 {len(password_to_tests)} 个唯一密码")
        
        # 快速计算每个测试的交集计数
        print("  计算交集计数...")
        cross_counts = [0] * len(self.test_results)
        
        for test_idx in range(len(self.test_results)):
            if test_idx % 50000 == 0:
                print(f"    计算进度: {test_idx}/{len(self.test_results)}")
            
            # 获取与当前测试有共同密码的所有其他测试
            intersecting_tests = set()
            for password in test_password_sets[test_idx]:
                if password in password_to_tests:
                    intersecting_tests.update(password_to_tests[password])
            
            # 移除自己
            intersecting_tests.discard(test_idx)
            cross_counts[test_idx] = len(intersecting_tests)
        
        # 将结果写回测试对象
        for i, count in enumerate(cross_counts):
            self.test_results[i]['cross_count'] = count
        
        # 按交集计数排序
        print("  排序结果...")
        self.test_results.sort(key=lambda x: x['cross_count'], reverse=True)
        
        # 找到真实MPW测试的排名
        real_mpw_rank = None
        for i, test in enumerate(self.test_results):
            if test['mpw'] == self.real_mpw:
                real_mpw_rank = i + 1
                break
        
        print(f"✓ 大规模优化交集计算完成")
        print(f"  - 真实MPW测试排名: {real_mpw_rank}")
        
        return real_mpw_rank

    def calculate_cross_counts_matrix(self):
        """步骤4: 使用矩阵运算的交集计算（修正版）"""
        print("\n步骤4: 计算交集测试（矩阵运算）...")
        
        # 合并所有测试
        all_tests = self.type1_tests + self.type2_tests
        
        if self.tag == 'noreal':
            self.test_results = [test for test in all_tests if test['copy_index'] != self.vault_system.get_real_copy_index()]
        else:
            self.test_results = all_tests
        
        print(f"  总测试数: {len(self.test_results)}")
        
        # 收集所有唯一密码
        all_passwords = set()
        test_password_lists = []
        
        for test in self.test_results:
            passwords = [pw for pw in test['decrypted_vault'] if pw != "ERROR"]
            test_password_lists.append(passwords)
            all_passwords.update(passwords)
        
        # 创建密码到索引的映射
        password_to_idx = {pw: idx for idx, pw in enumerate(sorted(all_passwords))}
        num_passwords = len(all_passwords)
        num_tests = len(self.test_results)
        
        print(f"  唯一密码数: {num_passwords}")
        
        # 构建测试-密码矩阵（稀疏矩阵）
        row_indices = []
        col_indices = []
        
        for test_idx, passwords in enumerate(test_password_lists):
            for password in passwords:
                row_indices.append(test_idx)
                col_indices.append(password_to_idx[password])
        
        # 创建二进制矩阵 (test_idx, password_idx)
        data = np.ones(len(row_indices), dtype=bool)
        test_password_matrix = csr_matrix((data, (row_indices, col_indices)), 
                                        shape=(num_tests, num_passwords))
        
        print("  开始矩阵乘法计算交集数量...")
        
        # 计算交集矩阵: 每对测试之间的共同密码数
        intersection_matrix = test_password_matrix.dot(test_password_matrix.T)
        
        # 修正：计算每个测试的交集计数（排除自己）
        cross_counts = []
        for i in range(num_tests):
            # 获取第i行，排除对角线元素
            row = intersection_matrix.getrow(i).toarray().flatten()
            row[i] = 0  # 排除自己
            
            # 关键修正：只要共同密码数 > 0，就算作有交集
            cross_count = np.count_nonzero(row > 0)  # 修正：统计有多少个其他测试与当前测试有交集
            cross_counts.append(cross_count)
            
            if i % 10000 == 0:
                print(f"  计算交集进度: {i}/{num_tests}")
        
        # 将结果写回
        for i, count in enumerate(cross_counts):
            self.test_results[i]['cross_count'] = count
        
        # 排序
        self.test_results.sort(key=lambda x: x['cross_count'], reverse=True)
        
        # 找到真实MPW测试的排名
        real_mpw_rank = None
        for i, test in enumerate(self.test_results):
            if test['mpw'] == self.real_mpw:
                real_mpw_rank = i + 1
                break
        
        print(f"✓ 矩阵运算交集计算完成")
        print(f"  - 真实MPW测试排名: {real_mpw_rank}")
        
        return real_mpw_rank

    def save_attack_results(self, real_mpw_rank):
        """步骤5: 保存所有攻击结果"""
        print("\n步骤5: 保存攻击结果...")
        
        # 确保输出目录存在
        os.makedirs(self.intersection_attack_result_dir, exist_ok=True)
        
        # 5a. 保存每个真实密码对应的测试结果
        self.save_real_password_tests()
        
        # 5b. 保存所有测试的交集排名
        self.save_intersection_rankings(real_mpw_rank)
        
        # # 5c. 保存所有测试的详细结果
        # self.save_all_test_results()
        
        # 5d. 保存所有解码密码全集
        self.save_all_decoded_passwords()
        
        print("✓ 所有结果已保存")
    
    def save_type1_test_info_start(self):
        """保存Type I测试开始前的MPW信息"""
        print("保存Type I测试的MPW信息...")
        
        # 确保输出目录存在
        os.makedirs(self.intersection_attack_result_dir, exist_ok=True)
        
        with open(self.intersection_attack_result_dir + 'type1_test_mpw_info.txt', 'w', encoding='utf-8') as f:
            f.write("Type I Test MPW Information\n")
            f.write("=" * 80 + "\n")
            f.write(f"测试开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总MPW数量: {len(self.all_mpws)}\n")
            f.write(f"真实MPW: {self.real_mpw}\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            f.write("Type I测试用到的所有MPW信息:\n")
            f.write("-" * 80 + "\n")
            
            for i, mpw in enumerate(self.all_mpws):
                # 计算copy index
                copy_index = self.hash_function(mpw) % self.T + 1
                
                # 获取SubGrammar ID
                sg_id = self.mpw_to_subgrammar(mpw)
                
                # 判断是否为真实MPW
                mpw_type = "Real" if mpw == self.real_mpw else "Fake"
                
                f.write(f"{i+1:4d}. MPW: {mpw}\n")
                f.write(f"      Type: {mpw_type}\n")
                f.write(f"      Copy Index: {copy_index}\n")
                f.write(f"      SubGrammar ID: {sg_id}\n")
                
                # 如果是fake MPW，尝试找到对应的密码
                if mpw != self.real_mpw:
                    # 在fake copies中查找这个MPW
                    for copy_info in self.vault_system.all_copies.values():
                        if copy_info['type'] == 'fake' and 'mpws' in copy_info:
                            if mpw in copy_info['mpws']:
                                mpw_index = copy_info['mpws'].index(mpw)
                                if mpw_index < len(self.vault_system.real_vault):
                                    pw = self.vault_system.real_vault[mpw_index]
                                    f.write(f"      对应密码: {pw}\n")
                                break
                
                f.write("\n")
        
        print(f"✓ Type I测试MPW信息已保存到: {self.intersection_attack_result_dir}type1_test_mpw_info.txt")
    
    def save_type1_test_results(self):
        """保存Type I测试结束后的详细结果"""
        print("保存Type I测试结果...")
        
        with open(self.intersection_attack_result_dir + 'type1_test_results.txt', 'w', encoding='utf-8') as f:
            f.write("Type I Test Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"测试完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总测试数量: {len(self.all_mpws)}\n")
            f.write(f"成功测试数量: {len(self.type1_tests)}\n")
            f.write(f"成功率: {len(self.type1_tests)/len(self.all_mpws)*100:.2f}%\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            f.write("每个MPW的测试结果:\n")
            f.write("-" * 80 + "\n")
            
            # 保存所有MPW的测试结果
            for i, mpw in enumerate(self.all_mpws):
                copy_index = self.hash_function(mpw) % self.T + 1
                sg_id = self.mpw_to_subgrammar(mpw)
                mpw_type = "Real" if mpw == self.real_mpw else "Fake"
                
                # 查找对应的测试结果
                test_result = None
                for test in self.type1_tests:
                    if test['mpw'] == mpw:
                        test_result = test
                        break
                
                f.write(f"{i+1:4d}. MPW: {mpw}\n")
                f.write(f"      Type: {mpw_type}\n")
                f.write(f"      Copy Index: {copy_index}\n")
                f.write(f"      SubGrammar ID: {sg_id}\n")
                
                if test_result:
                    if test_result['contains_real_pw']:
                        f.write(f"      测试状态: 成功 (包含真实密码)\n")
                    else:
                        f.write(f"      测试状态: 完成 (未包含真实密码)\n")
                    f.write(f"      解码成功: {test_result['success']}\n")
                    f.write(f"      解码密码数: {len([pw for pw in test_result['decrypted_vault'] if pw != 'ERROR'])}\n")
                    f.write(f"      解码密码: {[pw for pw in test_result['decrypted_vault'] if pw != 'ERROR']}\n")
                else:
                    f.write(f"      测试状态: 异常 (未找到测试结果)\n")
                    f.write(f"      解码密码: []\n")
                
                f.write("\n")
            
            # 统计信息
            f.write("\n" + "=" * 80 + "\n")
            f.write("统计信息:\n")
            f.write("-" * 40 + "\n")
            
            real_mpw_tests = [test for test in self.type1_tests if test['mpw'] == self.real_mpw]
            fake_mpw_tests = [test for test in self.type1_tests if test['mpw'] != self.real_mpw]
            
            f.write(f"真实MPW测试成功: {len(real_mpw_tests)}/1\n")
            f.write(f"Fake MPW测试成功: {len(fake_mpw_tests)}/{len(self.all_mpws)-1}\n")
            
            if real_mpw_tests:
                real_test = real_mpw_tests[0]
                f.write(f"真实MPW使用的SubGrammar: {real_test['sg_id']}\n")
                f.write(f"真实MPW解码的密码: {[pw for pw in real_test['decrypted_vault'] if pw != 'ERROR']}\n")
        
        print(f"✓ Type I测试结果已保存到: {self.intersection_attack_result_dir}type1_test_results.txt")
    
    def save_type2_test_results(self, total_type2_tests):
        """保存Type II测试结束后的详细结果"""
        print("保存Type II测试结果...")
        
        with open(self.intersection_attack_result_dir + 'type2_test_results.txt', 'w', encoding='utf-8') as f:
            f.write("Type II Test Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"测试完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总测试数量: {total_type2_tests}\n")
            f.write(f"成功测试数量: {len(self.type2_tests)}\n")
            f.write(f"成功率: {len(self.type2_tests)/total_type2_tests*100:.2f}%\n")
            
            # 计算包含真实密码的比例
            type2_with_real = sum(1 for test in self.type2_tests if test['contains_real_pw'])
            f.write(f"包含真实密码的测试数量: {type2_with_real}\n")
            f.write(f"包含真实密码的比例: {type2_with_real/len(self.type2_tests)*100:.2f}%\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            f.write("所有Type II测试结果:\n")
            f.write("-" * 80 + "\n")
            
            # 保存所有Type II测试的详细结果
            for i, test in enumerate(self.type2_tests):
                f.write(f"{i+1:4d}. 测试ID: {test['test_id']}\n")
                f.write(f"      MPW: {test['mpw']}\n")
                f.write(f"      Copy Index: {test['copy_index']}\n")
                f.write(f"      SubGrammar ID: {test['sg_id']}\n")
                f.write(f"      包含真实密码: {'是' if test['contains_real_pw'] else '否'}\n")
                f.write(f"      解码成功: {'是' if test['success'] else '否'}\n")
                f.write(f"      解码密码数: {len([pw for pw in test['decrypted_vault'] if pw != 'ERROR'])}\n")
                f.write(f"      解码密码: {[pw for pw in test['decrypted_vault'] if pw != 'ERROR']}\n")
                
                # 如果包含真实密码，标注哪些是真实密码
                if test['contains_real_pw']:
                    real_pws_in_test = [pw for pw in test['decrypted_vault'] if pw in self.vault_system.real_vault]
                    f.write(f"      其中真实密码: {real_pws_in_test}\n")
                
                f.write(f"      验证Copy Index: {self.hash_function(test['mpw']) % self.T + 1}\n")
                f.write("\n")
            
            # 统计信息
            f.write("\n" + "=" * 80 + "\n")
            f.write("Type II测试统计信息:\n")
            f.write("-" * 40 + "\n")
            
            # 按Copy Index分组统计
            copy_stats = {}
            for test in self.type2_tests:
                copy_idx = test['copy_index']
                if copy_idx not in copy_stats:
                    copy_stats[copy_idx] = {'total': 0, 'with_real': 0}
                copy_stats[copy_idx]['total'] += 1
                if test['contains_real_pw']:
                    copy_stats[copy_idx]['with_real'] += 1
            
            f.write("按Copy Index分组统计:\n")
            for copy_idx in sorted(copy_stats.keys()):
                stats = copy_stats[copy_idx]
                f.write(f"  Copy {copy_idx}: {stats['total']} 个测试, {stats['with_real']} 个包含真实密码 ({stats['with_real']/stats['total']*100:.1f}%)\n")
            
            # 按SubGrammar分组统计
            sg_stats = {}
            for test in self.type2_tests:
                sg_id = test['sg_id']
                if sg_id not in sg_stats:
                    sg_stats[sg_id] = {'total': 0, 'with_real': 0}
                sg_stats[sg_id]['total'] += 1
                if test['contains_real_pw']:
                    sg_stats[sg_id]['with_real'] += 1
            
            f.write("\n按SubGrammar分组统计:\n")
            for sg_id in sorted(sg_stats.keys()):
                stats = sg_stats[sg_id]
                f.write(f"  SubGrammar {sg_id}: {stats['total']} 个测试, {stats['with_real']} 个包含真实密码 ({stats['with_real']/stats['total']*100:.1f}%)\n")
            
            # 真实密码覆盖统计
            f.write("\n真实密码在Type II测试中的覆盖情况:\n")
            for real_pw in self.vault_system.real_vault:
                count = sum(1 for test in self.type2_tests if real_pw in test['decrypted_vault'])
                f.write(f"  '{real_pw}': 出现在 {count} 个测试中\n")
        
        print(f"✓ Type II测试结果已保存到: {self.intersection_attack_result_dir}type2_test_results.txt")
    
    def save_all_decoded_passwords(self):
        """保存所有测试解码出现过的密码全集"""
        with open(self.intersection_attack_result_dir + 'all_decoded_passwords.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")
            f.write("所有测试解码出现过的密码全集\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            # 过滤掉ERROR
            valid_passwords = {pw for pw in self.all_decoded_passwords if pw != "ERROR"}
            
            f.write(f"总密码数量: {len(valid_passwords)}\n")
            f.write(f"总测试数量: {len(self.test_results)}\n")
            
            f.write("所有密码列表 (按字母顺序排序):\n")
            f.write("-" * 60 + "\n")
            
            for i, password in enumerate(sorted(valid_passwords), 1):
                f.write(f"{i:4d}: {password}\n")
            
            f.write(f"\n总计: {len(valid_passwords)} 个不同的密码\n")
    
    def save_real_password_tests(self):
        """保存每个真实密码对应的测试结果"""
        with open(self.intersection_attack_result_dir + 'real_password_tests.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")
            f.write("每个真实密码对应的测试结果\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            for real_pw in self.vault_system.real_vault:
                f.write(f"真实密码: '{real_pw}'\n")
                f.write("-" * 60 + "\n")
                
                matching_tests = []
                for test in self.test_results:
                    if real_pw in test['decrypted_vault']:
                        matching_tests.append(test)
                
                f.write(f"包含该密码的测试数量: {len(matching_tests)}\n\n")
                
                # for i, test in enumerate(matching_tests[:20]):  # 只显示前20个
                #     f.write(f"  测试 {i+1}: {test['test_id']}\n")
                #     f.write(f"    MPW: {test['mpw']}\n")
                #     f.write(f"    Copy索引: {test['copy_index']}\n")
                #     f.write(f"    SubGrammar: {test['sg_id']}\n")
                #     f.write(f"    Cross Count: {test['cross_count']}\n")
                #     f.write(f"    解密结果: {test['decrypted_vault']}\n\n")
                
                f.write("\n" + "="*80 + "\n\n")
    
    def save_intersection_rankings(self, real_mpw_rank):
        """保存交集测试总排名"""
        with open(self.intersection_attack_result_dir + 'intersection_rankings.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")
            f.write("交集测试排名结果\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            f.write(f"真实MPW: {self.real_mpw}\n")
            f.write(f"真实MPW测试排名: {real_mpw_rank}/{len(self.test_results)}\n")
            if real_mpw_rank:
                percentage = (real_mpw_rank / len(self.test_results)) * 100
                f.write(f"排名百分位: {percentage:.2f}%\n\n")
            
            f.write("交集统计结果:\n")
            f.write("-" * 80 + "\n")
            
            for i, test in enumerate(self.test_results):
                f.write(f"排名 {i+1:2d}: {test['test_id']:<15} | Type: {test['type']:<7} | ")
                f.write(f"Cross Count: {test['cross_count']:<4} | MPW: {test['mpw'][:30]}...\n")
                
                if test['mpw'] == self.real_mpw:
                    f.write("    *** 这是真实MPW测试 ***\n")
                
                f.write(f"    Copy: {test['copy_index']} | SG: {test['sg_id']} | ")
                f.write(f"结果: {test['decrypted_vault'][:6]}...\n\n")
    
    def save_all_test_results(self):
        """保存所有测试的详细结果"""
        with open(self.intersection_attack_result_dir + 'all_test_results.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 100 + "\n")
            f.write("所有测试的详细结果\n")
            f.write("=" * 100 + "\n\n")
            
            f.write(f"Type I 测试数量: {len(self.type1_tests)}\n")
            f.write(f"Type II 测试数量: {len(self.type2_tests)}\n")
            f.write(f"总测试数量: {len(self.test_results)}\n\n")
            f.write(f"真实密码库: {self.vault_system.true_passwords}\n")
            
            for test in self.test_results:
                f.write(f"测试ID: {test['test_id']}\n")
                f.write(f"  类型: {test['type']}\n")
                f.write(f"  MPW: {test['mpw']}\n")
                f.write(f"  Copy索引: {test['copy_index']}\n")
                f.write(f"  SubGrammar ID: {test['sg_id']}\n")
                f.write(f"  Cross Count: {test['cross_count']}\n")
                f.write(f"  包含真实密码: {test['contains_real_pw']}\n")
                f.write(f"  解密成功: {test['success']}\n")
                f.write(f"  解密结果: {test['decrypted_vault']}\n")
                f.write("-" * 80 + "\n")

def offline_attack_intersection():
    default_T = 10  # decoy copy数量,10,100(测试),1000+(正式)
    tag = 'withreal' # 可选withreal/noreal

    script_dir = os.path.dirname(os.path.abspath(__file__))
    version = 'result_intersection_attack'
    output_dir = script_dir+'/'+version+'/'+datetime.now().strftime('%y%m%d%H%M')+tag+"T"+str(default_T) +'/'

    profiler = TimeProfiler()
    profiler.start_timer("Total Execution")

    print("🚀 Subgrammar family DTE交集攻击启动")
    print("=" * 60)
    
    real_pws = ['123456', '123456789', 'wangsimin', '123456', '3981257619', '626075', '68921820', '951236', '123456789', '6363001', 'thought1', '123456']
    dummy_pws = ['biendy', '.inf2lf', 'babyko', 'wangsimin', 'lilmach', '3981257619', '3981257619', '1234511at9;0d', 'sanado', '123456', '8981257619', 'wangsimin', '626075', 'babylore', 'cartake123', '180808', 'gemancanda', '6363001', '123456789', '12345iq', 'nik99954', '123456', '123456789', '3981257619']

    # 创建攻击实例
    attack = sgf(default_T, real_pws, dummy_pws, intersection_attack_result_dir = output_dir, tag = tag)
    print(f"参数设置: T={default_T}, real vault size={attack.real_pw_cnt}, tag='{tag}'")
    # print(f"预计时长:{14.4*default_T}s")
    
    # 初始化结果保存目录
    os.makedirs(attack.intersection_attack_result_dir, exist_ok=True)

    try:
        # 执行完整攻击流程
        
        # 步骤1: 构造vault system并收集MPW
        btg = TrainedGrammar()
        attack.setup_vault_system(default_T, btg)
        # attack.setup_sgf(real_pws, dummy_pws, default_T)
        
        # 步骤2: 设计MPW到SubGrammar的映射
        attack.design_mpw_to_sg_mapping()
        
        # 步骤3.1: 执行Type I测试
        attack.execute_type1_tests()
        
        # 步骤3.2: 执行Type II测试  
        attack.execute_type2_tests()
        
        # 步骤4: 计算交集并排名
        # real_mpw_rank = attack.calculate_cross_counts_matrix()
        real_mpw_rank = attack.calculate_cross_counts_optimized_large()

        # 步骤5: 保存攻击结果
        attack.save_attack_results(real_mpw_rank)
        
        # 输出最终统计
        print("\n🎯 攻击完成！最终统计:")
        print("=" * 60)
        print(f"Type I 测试数量: {len(attack.type1_tests)}")
        print(f"Type II 测试数量: {len(attack.type2_tests)}")
        print(f"总测试数量: {len(attack.test_results)}")
        print(f"真实MPW测试排名: {real_mpw_rank}")
        
        if real_mpw_rank:
            percentage = (real_mpw_rank / len(attack.test_results)) * 100
            print(f"真实MPW排名百分位: {percentage:.2f}%")
        
        print(f"结果已保存到: {output_dir}")
        
        # 分析攻击效果
        type1_with_real = sum(1 for test in attack.type1_tests if test['contains_real_pw'])
        type2_with_real = sum(1 for test in attack.type2_tests if test['contains_real_pw'])
        
        print(f"\n攻击效果分析:")
        print(f"Type I包含真实密码的测试: {type1_with_real}/{len(attack.type1_tests)}")
        print(f"Type II包含真实密码的测试: {type2_with_real}/{len(attack.type2_tests)}")
        
        # Top 10排名分析
        print(f"\nTop 10测试分析:")
        for i, test in enumerate(attack.test_results[:10]):
            marker = "★" if test['mpw'] == attack.real_mpw else " "
            print(f"{marker} 排名{i+1}: {test['test_id']} (Cross Count: {test['cross_count']})")
        
        # 打印详细时间分析
        # attack.profiler.print_summary()
        
    except Exception as e:
        print(f"❌ 攻击过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        profiler.end_timer("Total Execution")
        print(f"总执行时间: {profiler.get_stats('Total Execution')['duration']:.2f}秒")

if __name__ == "__main__":
    offline_attack_intersection()