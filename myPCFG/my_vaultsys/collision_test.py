#!/usr/bin/env python3
"""
SubGrammar碰撞测试v2
测试不同SubGrammar之间的密码生成碰撞情况
求所有解密密码的并集
打印所有密码出现次数的统计
"""
import sys
import os
# 添加当前文件所在目录的父目录到Python模块搜索路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append('.')
# Change to the parent directory to access collision_test folder
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(parent_dir)
from pcfg.pcfg import TrainedGrammar, SubGrammar
import json
from helper import random, convert2group
import honeyvault_config as hny_config
from collections import defaultdict, Counter
import math
from itertools import combinations
from datetime import datetime

record_dir = 'data/'
version = 'v3'
output_dir = record_dir + 'test-' + version + '/' + datetime.now().strftime('%y%m%d%H%M') + '/'

# 从文件读取密码集
def load_password_set():
    """从pw_PB.json文件中加载密码集"""
    try:
        with open(record_dir+'pw_PB.json', 'r', encoding='utf-8') as f:
            passwords = json.load(f)
        print(f"成功从 pw_PB.json 加载了 {len(passwords)} 个密码")
        return passwords
    except FileNotFoundError:
        print("错误：找不到 data/pw_PB.json 文件")
        raise
    except json.JSONDecodeError:
        print("错误：pw_PB.json 文件格式错误")
        raise

# 加载密码集
RANDOM_PW_SET = load_password_set()

# 配置参数
TRUE_PASSWORD_COUNT = 6    # 真密码个数
FALSE_PASSWORD_COUNT = 12  # 假密码个数
SG_INPUT_PASSWORD_COUNT = 6  # 每个SubGrammar的输入密码个数

class CollisionTest:
    def __init__(self):
        self.tg = TrainedGrammar()
        self.subgrammars = {}
        self.test_results = {}
        self.all_passwords = set()  # 存储所有解码得到的密码（去重）
        self.sg_password_stats = defaultdict(Counter)  # 每个SubGrammar的密码频率统计
        self.sg_input_passwords = {}  # 存储每个SubGrammar使用的输入密码
        self.valut_size = TRUE_PASSWORD_COUNT
        self.sg_test_counters = defaultdict(int)  # 记录每个sg_id被访问的次数
        self.true_passwords = []  # 存储真实密码
        self.assumption1_stats = defaultdict(list)  # 记录每个真实密码下满足assumption1的test_label
        self.real_password_test = None  # 存储真实密码测试样本            
    
    def create_password_set(self):
        """创建密码集PS：6个真密码 + 12个假密码"""
        # 检查RANDOM_PW_SET是否有足够的密码
        total_needed = TRUE_PASSWORD_COUNT + FALSE_PASSWORD_COUNT
        if len(RANDOM_PW_SET) < total_needed:
            raise ValueError(f"RANDOM_PW_SET只有{len(RANDOM_PW_SET)}个密码，但需要{total_needed}个密码")
        
        # 随机选择真密码和假密码，确保不重复
        all_passwords = random.sample(RANDOM_PW_SET, total_needed)
        true_passwords = all_passwords[:TRUE_PASSWORD_COUNT]
        false_passwords = all_passwords[TRUE_PASSWORD_COUNT:]
        
        PS = true_passwords + false_passwords
        print("真密码 ({}个): {}".format(TRUE_PASSWORD_COUNT, true_passwords))
        print("假密码 ({}个): {}".format(FALSE_PASSWORD_COUNT, false_passwords))
        print("密码集PS ({}个): {}".format(len(PS), PS))
        
        # 保存真实密码用于后续assumption1统计
        self.true_passwords = true_passwords
        
        return PS, true_passwords, false_passwords
    
    def create_subgrammars(self, PS, true_passwords):
        """创建16个SubGrammar"""
        print("\n开始创建16个SubGrammar...")
        
        # SubGrammar 0: 使用6个真密码
        sg0 = SubGrammar(self.tg)
        sg0.update_grammar(*true_passwords)
        self.subgrammars[0] = sg0
        self.sg_input_passwords[0] = true_passwords  # 记录输入密码
        print("SubGrammar 0: 使用真密码 {}".format(true_passwords))
        
        # SubGrammar 1-15: 从PS中随机选择6个不重复的密码
        used_combinations = set()  # 记录已使用的密码组合
        
        for i in range(1, 16):
            # 生成新的密码组合，确保组合间不重复且组合内密码不重复
            while True:
                # 从PS中随机选择6个不重复的密码
                original_passwords = random.sample(PS, SG_INPUT_PASSWORD_COUNT)
                
                # 检查组合内是否有重复密码（理论上random.sample已经保证不重复，但为了安全起见）
                if len(set(original_passwords)) != SG_INPUT_PASSWORD_COUNT:
                    continue
                    
                # 将密码组合转换为元组并排序，用于去重比较
                password_tuple = tuple(sorted(original_passwords))
                
                if password_tuple not in used_combinations:
                    used_combinations.add(password_tuple)
                    break
            
            sg = SubGrammar(self.tg)
            sg.update_grammar(*original_passwords)
            self.subgrammars[i] = sg
            self.sg_input_passwords[i] = original_passwords  # 记录输入密码
            print("SubGrammar {}: 使用密码 {}".format(i, original_passwords))
        
        print("✓ 16个SubGrammar创建完成")
    
    def run_single_test(self, test_global_id):
        """执行单次测试"""
        # 生成valut_size+1个随机数
        random_numbers = [random.randint(0, hny_config.MAX_INT) for _ in range(self.valut_size + 1)]
        
        # 第一个随机数用于确定sg_id
        sg_id = random_numbers[0] % 16
        
        # 剩下的随机数作为种子值，每个种子值用来生成完整的种子数组
        seed_values = random_numbers[1:]
        
        # 更新该sg_id的test计数器
        test_id = self.sg_test_counters[sg_id]
        self.sg_test_counters[sg_id] += 1
        
        test_label = f"test_{sg_id}_{test_id}"
        sg = self.subgrammars[sg_id]
        
        passwords = []
        for seed_value in seed_values:
            # 使用单个随机数生成完整的种子数组
            seed = [seed_value] * hny_config.PASSWORD_LENGTH
            try:
                decoded_pw = sg.decode_pw(seed)
                passwords.append(decoded_pw)
                self.all_passwords.add(decoded_pw)  # 添加到所有密码集合
                self.sg_password_stats[sg_id][decoded_pw] += 1  # 更新SubGrammar密码统计
            except:
                passwords.append("ERROR")
        
        # 检查assumption1：解码密码中是否包含真实密码
        decoded_passwords_set = set(passwords)
        for true_pw in self.true_passwords:
            if true_pw in decoded_passwords_set:
                self.assumption1_stats[true_pw].append(test_label)
        
        return {
            'label': test_label,
            'sg_id': sg_id,
            'test_id': test_id,
            'global_test_id': test_global_id,
            'passwords': passwords,
            'cross_count': 0
        }
    
    def calculate_cross_count(self, test_result, all_tests):
        """计算当前test与其他test的交叉计数"""
        cross_count = 0
        current_passwords = set(test_result['passwords'])
        
        # 与所有其他测试计算交集
        for other_test in all_tests:
            if other_test['label'] != test_result['label']:
                other_passwords = set(other_test['passwords'])
                if current_passwords & other_passwords:  # 有交集
                    cross_count += 1
        
        # 与真实密码测试样本计算交集
        if self.real_password_test and test_result['label'] != 'test_real':
            real_passwords = set(self.real_password_test['passwords'])
            if current_passwords & real_passwords:
                cross_count += 1
                
        return cross_count
    
    def calculate_real_test_cross_count(self, all_tests):
        """计算真实密码测试样本的交叉计数"""
        if not self.real_password_test:
            return 0
            
        cross_count = 0
        real_passwords = set(self.real_password_test['passwords'])
        
        for test in all_tests:
            test_passwords = set(test['passwords'])
            if real_passwords & test_passwords:  # 有交集
                cross_count += 1
                
        return cross_count
    
    def run_all_tests(self):
        """执行所有测试"""
        print("\n开始执行碰撞测试...")
        
        # 创建真实密码测试样本
        self.real_password_test = {
            'label': 'test_real',
            'sg_id': 'real',
            'test_id': 'real',
            'global_test_id': 'real',
            'passwords': self.true_passwords,
            'cross_count': 0
        }
        
        # 执行16000次测试
        all_tests = []
        for global_test_id in range(16000):
            if global_test_id % 1000 == 0:
                print(f"执行第 {global_test_id}/16000 次测试...")
            
            test_result = self.run_single_test(global_test_id)
            all_tests.append(test_result)
        
        # 计算cross_count
        print("\n计算交叉计数...")
        for i, test_result in enumerate(all_tests):
            cross_count = self.calculate_cross_count(test_result, all_tests)
            test_result['cross_count'] = cross_count
            
            if i % 2000 == 0:
                print(f"  已处理 {i}/{len(all_tests)} 个测试")
        
        # 计算真实密码测试样本的cross_count
        real_cross_count = self.calculate_real_test_cross_count(all_tests)
        self.real_password_test['cross_count'] = real_cross_count
        
        self.test_results = all_tests
        print("✓ 所有测试完成")
        
        # 打印每个sg_id被访问的次数统计
        print("\n各SubGrammar被访问次数统计:")
        for sg_id in sorted(self.sg_test_counters.keys()):
            print(f"SubGrammar {sg_id}: {self.sg_test_counters[sg_id]} 次")
        
        # 打印assumption1统计
        print("\nAssumption1统计:")
        for true_pw in self.true_passwords:
            count = len(self.assumption1_stats[true_pw])
            print(f"真实密码 '{true_pw}': {count} 次测试满足assumption1")
        
        # 打印真实密码测试样本统计
        print(f"\n真实密码测试样本 (test_real) Cross Count: {real_cross_count}")
    
    def save_results(self):
        """保存测试结果到文件"""
        print("\n保存测试结果...")
        
        # 确保collision_test目录存在
        os.makedirs('collision_test', exist_ok=True)
        
        # 按cross_count排序（包含真实密码测试样本）
        all_tests_with_real = self.test_results + [self.real_password_test]
        sorted_tests = sorted(all_tests_with_real, key=lambda x: x['cross_count'], reverse=True)
        
        # 找到test_real的排名
        real_test_rank = None
        for i, test in enumerate(sorted_tests):
            if test['label'] == 'test_real':
                real_test_rank = i + 1
                break
        
        # 保存所有结果
        with open(output_dir + 'collision_test_results.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")
            f.write("SubGrammar碰撞测试结果\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("测试配置:\n")
            f.write("- 16个SubGrammar (编号0-15)\n")
            f.write("- SubGrammar 0使用{}个真密码\n".format(TRUE_PASSWORD_COUNT))
            f.write("- SubGrammar 1-15各使用{}个随机密码 (从{}个真密码+{}个假密码的集合中采样)\n".format(
                SG_INPUT_PASSWORD_COUNT, TRUE_PASSWORD_COUNT, FALSE_PASSWORD_COUNT))
            f.write("- 总计执行16000次测试\n")
            f.write("- 每次测试随机选择一个SubGrammar执行\n")
            f.write("- 每次测试生成{}个密码\n".format(self.valut_size))
            f.write("- 添加真实密码作为特殊测试样本 (test_real) 参与交叉计数\n\n")
            
            f.write("所有测试结果 (按cross_count降序排列，包含test_real):\n")
            f.write("-" * 80 + "\n")
            
            for test in sorted_tests:
                f.write("标签: {:<15} | SubGrammar: {:<4} | 测试编号: {:<4} | Cross Count: {:<4} | 密码: {}\n".format(
                    test['label'], test['sg_id'], test['test_id'], 
                    test['cross_count'], test['passwords']))
        
        # 保存前50个最高cross_count的测试（不包含test_real）
        sorted_tests_no_real = sorted(self.test_results, key=lambda x: x['cross_count'], reverse=True)
        with open(output_dir + 'collision_top50_test.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 60 + "\n")
            f.write("Cross Count最高的前50个测试\n")
            f.write("=" * 60 + "\n\n")
            
            for i, test in enumerate(sorted_tests_no_real[:50]):
                f.write("排名 {:<2}: {:<15} | SubGrammar: {:<2} | 测试编号: {:<4} | Cross Count: {:<4}\n".format(
                    i+1, test['label'], test['sg_id'], test['test_id'], test['cross_count']))
                f.write("  密码: {}\n\n".format(test['passwords']))
        
        # 统计信息
        cross_counts = [test['cross_count'] for test in self.test_results]
        avg_cross_count = sum(cross_counts) / len(cross_counts)
        max_cross_count = max(cross_counts)
        min_cross_count = min(cross_counts)
        
        with open(output_dir + 'collision_statistics.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 50 + "\n")
            f.write("碰撞测试统计信息\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("总测试数: {}\n".format(len(self.test_results)))
            f.write("平均Cross Count: {:.2f}\n".format(avg_cross_count))
            f.write("最大Cross Count: {}\n".format(max_cross_count))
            f.write("最小Cross Count: {}\n".format(min_cross_count))
            
            # 真实密码测试样本统计
            f.write("\n真实密码测试样本 (test_real) 统计:\n")
            f.write("- 密码集合: {}\n".format(self.real_password_test['passwords']))
            f.write("- Cross Count: {}\n".format(self.real_password_test['cross_count']))
            f.write("- 排名: {}/{}\n".format(real_test_rank, len(all_tests_with_real)))
            percentage = (real_test_rank / len(all_tests_with_real)) * 100
            f.write("- 排名百分位: {:.2f}%\n".format(percentage))
            
            # 按SubGrammar统计
            f.write("\n按SubGrammar统计:\n")
            sg_stats = defaultdict(list)
            for test in self.test_results:
                sg_stats[test['sg_id']].append(test['cross_count'])
            
            for sg_id in sorted(sg_stats.keys()):
                counts = sg_stats[sg_id]
                f.write("SubGrammar {}: 平均 {:.2f}, 最大 {}, 最小 {}\n".format(
                    sg_id, sum(counts)/len(counts), max(counts), min(counts)))
        
        # 新增功能1: 保存所有唯一密码
        self.save_all_unique_passwords()
        # 新增功能2: 保存每个SubGrammar的密码频率统计
        self.save_subgrammar_password_stats()
        # 新增功能3: 保存所有SubGrammar的详细统计分析（放在最后执行）
        self.save_subgrammar_family_comprehensive_stats()
        
        print("✓ 结果已保存到以下文件:")
        print(" - " + output_dir + "collision_test_results.txt (所有结果，包含test_real)")
        print(" - " + output_dir + "collision_top50_test.txt (前50名)")
        print(" - " + output_dir + "collision_statistics.txt (统计信息，包含test_real排名)")
        print(" - " + output_dir + "collision_all_pw.txt (所有唯一密码)")
        print(" - " + output_dir + "collision_sg_pw_count.txt (各SubGrammar密码频率统计)")
        print(" - " + output_dir + "collision_sg_family_stat.txt (SubGrammar综合统计分析)")

    def save_all_unique_passwords(self):
        """保存所有唯一密码到collision_all_pw.txt"""
        # 过滤掉ERROR密码
        unique_passwords = {pw for pw in self.all_passwords if pw != "ERROR"}
        
        with open(output_dir + 'collision_all_pw.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 60 + "\n")
            f.write("所有解码得到的唯一密码集合\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("总数量: {}\n\n".format(len(unique_passwords)))
            
            f.write("所有唯一密码列表:\n")
            f.write("-" * 40 + "\n")
            
            # 按字母顺序排序输出
            for i, password in enumerate(sorted(unique_passwords), 1):
                f.write("{:<4}: {}\n".format(i, password))
    
    def save_subgrammar_password_stats(self):
        """保存每个SubGrammar的密码频率统计到sg_pw_count.txt"""
        with open(output_dir + 'collision_sg_pw_count.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")
            f.write("各SubGrammar密码频率统计 (按频率降序排列)\n")
            f.write("=" * 80 + "\n\n")
            
            for sg_id in sorted(self.sg_password_stats.keys()):
                f.write("SubGrammar {} 密码频率统计:\n".format(sg_id))
                f.write("-" * 50 + "\n")
                
                # 显示该SubGrammar的输入原始密码
                input_passwords = self.sg_input_passwords.get(sg_id, [])
                f.write("输入原始密码: {}\n".format(input_passwords))
                f.write("-" * 50 + "\n")
                
                # 获取该SubGrammar的密码计数器，按频率降序排序
                password_counts = self.sg_password_stats[sg_id]
                
                # 过滤掉ERROR密码并按频率降序排序
                sorted_passwords = sorted(
                    [(pw, count) for pw, count in password_counts.items() if pw != "ERROR"],
                    key=lambda x: x[1], 
                    reverse=True
                )
                
                total_valid_passwords = sum(count for _, count in sorted_passwords)
                f.write("唯一密码数: {}\n\n".format(len(sorted_passwords)))
                
                f.write("密码频率统计 (密码 | 频率 | 百分比):\n")
                for i, (password, count) in enumerate(sorted_passwords, 1):
                    percentage = (count / total_valid_passwords * 100) if total_valid_passwords > 0 else 0
                    f.write("{:<4}: {:<30} | {:<6} | {:.2f}%\n".format(
                        i, password, count, percentage))
                
                f.write("\n" + "=" * 80 + "\n\n")
    
    def save_subgrammar_family_comprehensive_stats(self):
        """保存所有SubGrammar的综合统计分析到sg_family_stat.txt（程序最后执行）"""
        with open(output_dir + 'collision_sg_family_stat.txt', 'w', encoding='utf-8') as f:
            f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 100 + "\n")
            f.write("SubGrammar综合统计分析\n")
            f.write("=" * 100 + "\n\n")
            
            f.write("配置信息:\n")
            f.write("- 真密码个数: {}\n".format(TRUE_PASSWORD_COUNT))
            f.write("- 假密码个数: {}\n".format(FALSE_PASSWORD_COUNT))
            f.write("- 每个SubGrammar输入密码个数: {}\n".format(SG_INPUT_PASSWORD_COUNT))
            f.write("- SubGrammar总数: {}\n".format(len(self.sg_input_passwords)))
            f.write("- 总计执行测试次数: 16000\n")
            f.write("- 每次测试生成密码数: {}\n".format(self.valut_size))
            f.write("- 真实密码列表: {}\n\n".format(self.true_passwords))
            
            # 统计数据收集
            all_unique_counts = []  # 所有sg的唯一密码数
            all_high_prob_counts = []  # 所有sg的高概率密码数
            
            f.write("详细统计分析:\n")
            f.write("=" * 100 + "\n\n")
            
            for sg_id in sorted(self.sg_input_passwords.keys()):
                f.write("SubGrammar {} 详细分析:\n".format(sg_id))
                f.write("-" * 80 + "\n")
                
                # 1. 输入密码
                input_passwords = self.sg_input_passwords[sg_id]
                f.write("输入密码: {}\n".format(input_passwords))
                if sg_id == 0:
                    f.write("说明: 仅包含真密码\n")
                else:
                    f.write("说明: 从真密码+假密码集合中采样\n")
                f.write("\n")
                
                # 2. 唯一密码数统计
                password_counts = self.sg_password_stats[sg_id]
                unique_passwords = [(pw, count) for pw, count in password_counts.items() if pw != "ERROR"]
                unique_count = len(unique_passwords)
                all_unique_counts.append(unique_count)
                
                f.write("解码唯一密码数: {}\n".format(unique_count))
                
                # 3. 高概率密码集合（频率>0.1%）
                total_valid_passwords = sum(count for _, count in unique_passwords)
                high_prob_passwords = []
                
                for pw, count in unique_passwords:
                    percentage = (count / total_valid_passwords * 100) if total_valid_passwords > 0 else 0
                    if percentage > 0.1:
                        high_prob_passwords.append((pw, count, percentage))
                
                high_prob_count = len(high_prob_passwords)
                all_high_prob_counts.append(high_prob_count)

                f.write("高概率密码数 (频率>0.1%): {}\n".format(high_prob_count))
                f.write("高概率密码集合:\n")
                for i, (pw, count, percentage) in enumerate(high_prob_passwords, 1):
                    # 只记录前20个
                    if i > 20:
                        break
                    f.write("  {:<3}: {:<30} | {:<6} | {:.2f}%\n".format(i, pw, count, percentage))
                
                if not high_prob_passwords:
                    f.write("  (无频率超过0.1%的密码)\n")
                f.write("\n")
                
                # 4. SubGrammar语法规则 (self.G['G'])
                sg = self.subgrammars[sg_id]
                if hasattr(sg, 'G') and 'G' in sg.G:
                    f.write("语法规则 (self.G['G']):\n")
                    grammar_rules = sg.G['G']
                    if grammar_rules:
                        # 按规则名排序
                        sorted_rules = sorted(grammar_rules.items())
                        for rule_name, frequency in sorted_rules:
                            if rule_name != '__total__':
                                total_freq = grammar_rules.get('__total__', 1)
                                probability = frequency / total_freq if total_freq > 0 else 0
                                f.write("  {:<20} | 频率: {:<8} | 概率: {:.6f}\n".format(
                                    rule_name, frequency, probability))
                    else:
                        f.write("  (无语法规则)\n")
                else:
                    f.write("语法规则: (无法访问)\n")
                
                f.write("\n" + "=" * 100 + "\n\n")
            
            # 全局统计分析
            f.write("全局统计分析:\n")
            f.write("=" * 100 + "\n\n")
            
            # 收集所有使用过的密码
            all_used_passwords = set()
            for passwords in self.sg_input_passwords.values():
                all_used_passwords.update(passwords)
            
            f.write("密码使用统计:\n")
            f.write("- 所有SubGrammar共使用了 {} 个不同的输入密码\n".format(len(all_used_passwords)))
            f.write("- 使用的密码列表: {}\n\n".format(sorted(list(all_used_passwords))))
            
            # 唯一密码数统计
            if all_unique_counts:
                avg_unique = sum(all_unique_counts) / len(all_unique_counts)
                f.write("解码唯一密码数统计:\n")
                f.write("- 最小值: {}\n".format(min(all_unique_counts)))
                f.write("- 最大值: {}\n".format(max(all_unique_counts)))
                f.write("- 平均值: {:.2f}\n".format(avg_unique))
                f.write("- 总计: {}\n".format(sum(all_unique_counts)))
                f.write("- 各SubGrammar唯一密码数: {}\n\n".format(all_unique_counts))
            
            # 高概率密码数统计
            if all_high_prob_counts:
                avg_high_prob = sum(all_high_prob_counts) / len(all_high_prob_counts)
                f.write("高概率密码数统计 (频率>0.1%):\n")
                f.write("- 最小值: {}\n".format(min(all_high_prob_counts)))
                f.write("- 最大值: {}\n".format(max(all_high_prob_counts)))
                f.write("- 平均值: {:.2f}\n".format(avg_high_prob))
                f.write("- 总计: {}\n".format(sum(all_high_prob_counts)))
                f.write("- 各SubGrammar高概率密码数: {}\n\n".format(all_high_prob_counts))
            
            # 整体测试概览
            f.write("整体测试概览:\n")
            f.write("- 总测试次数: 16000\n")
            f.write("- 总解码密码数: {} (包含重复)\n".format(len(self.test_results) * self.valut_size))
            f.write("- 全局唯一密码数: {}\n".format(len([pw for pw in self.all_passwords if pw != "ERROR"])))
            
            # 各SubGrammar被访问次数统计
            f.write("\n各SubGrammar被访问次数统计:\n")
            for sg_id in sorted(self.sg_test_counters.keys()):
                f.write("- SubGrammar {}: {} 次\n".format(sg_id, self.sg_test_counters[sg_id]))
            
            # Assumption1统计
            f.write("\nAssumption1统计分析:\n")
            f.write("=" * 100 + "\n")
            f.write("(Assumption1: 测试解码得到的密码中包含某个真实密码)\n\n")
            
            total_assumption1_tests = 0
            for true_pw in self.true_passwords:
                test_labels = self.assumption1_stats[true_pw]
                count = len(test_labels)
                total_assumption1_tests += count
                
                f.write("真实密码 '{}' 下满足Assumption1的测试:\n".format(true_pw))
                f.write("- 满足条件的测试总数: {}\n".format(count))
                f.write("- 满足条件的测试标签: {}\n\n".format(test_labels))
            
            f.write("所有真实密码下满足Assumption1的测试总数: {}\n".format(total_assumption1_tests))
            f.write("注: 同一个测试可能在多个真实密码下都满足Assumption1，因此总数可能重复计算\n")

def main():
    print("🚀 SubGrammar碰撞测试开始")
    
    # 初始化输出目录,如collision_test/test-v2/2507141735,2507141735表示25年07月14日17时35分
    os.makedirs(output_dir, exist_ok=True)
    
    # 创建测试实例
    collision_test = CollisionTest()
    
    # 随机选择密码集
    # PS, real_pws, dummy_passwords = collision_test.create_password_set()
    
    '''
    13
    real_pws: ['BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'ba06111990']
    dummy_pws: ['honor', 'BA06111990w', 'BA06111990s', 'BA06111990w', 'frien10', 'BA06111990', 'BA06111990s', 'BA061119', 'BA06111990a', 'BA0611199015', 'BA06111990q', 'BA06111990123', 'BA0611199015', '9cPI!1:nau', 'BA06111990w', 'sugmaldo', 'BA06111990d', 'BA06111990qwerty', '6111990w', 'com1ille', 'A06111990dw', 'BA06111990qwerty', 'BA06111990qwerd', 'BA06111990qwerty', 'BA06111990e', 'BA06111990d', 'yogikilli', 'BA06111990q', 'ritoub', 'BA06111990e', 'BA06111990qwerty', 'kate2018', 'BA06111990', 'BA06111990123', 'bycraze151', 'BA06111990a', 'BA06111990a', 'BA06111990wr', 'BA0611199015', 'BA06111990e', 'MYK4P-E-', 'BA06111990s']
    18
    real_pws: ['23022008kis', 'Kis45706', 'Kisv200', 'kis23022008', 'kis4570', 'kis45706', 'kisv200', 'Kis45706', 'Kisv200', 'kis45706', 'kisv200']
    dummy_pws: ['kisv200', '5isv200', 'kis4', 'Kisv200', 'kisv200', 'kis45706', 'Kisv200', 'eiley1', 'Kisv200d', 'kis4570', 'Kis45706', 'birds', 'kis23022008', '960256789', 'noelly', 'Kisv200', 'Kis45706r', 'Kis45706', 'kis23022008', 'kis23022008', 'kis45706', 'kis45706']
    '''
    # 手动设置测试集
    real_pws = ['BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'ba06111990']

    dummy_pws = ['honor', 'BA06111990w', 'BA06111990s', 'BA06111990w', 'frien10', 'BA06111990', 'BA06111990s', 'BA061119', 'BA06111990a', 'BA0611199015', 'BA06111990q', 'BA06111990123', 'BA0611199015', '9cPI!1:nau', 'BA06111990w', 'sugmaldo', 'BA06111990d', 'BA06111990qwerty', '6111990w', 'com1ille', 'A06111990dw', 'BA06111990qwerty', 'BA06111990qwerd', 'BA06111990qwerty', 'BA06111990e', 'BA06111990d', 'yogikilli', 'BA06111990q', 'ritoub', 'BA06111990e', 'BA06111990qwerty', 'kate2018', 'BA06111990', 'BA06111990123', 'bycraze151', 'BA06111990a', 'BA06111990a', 'BA06111990wr', 'BA0611199015', 'BA06111990e', 'MYK4P-E-', 'BA06111990s']

    PS = real_pws + dummy_pws
    
    # 创建SubGrammar
    collision_test.create_subgrammars(PS, real_pws)
    
    # 执行所有测试
    collision_test.run_all_tests()
    
    # 保存结果
    collision_test.save_results()
    
    print("\n🎯 碰撞测试完成！")

if __name__ == "__main__":
    main()