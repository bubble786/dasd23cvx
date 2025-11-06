#!/usr/bin/env python3
"""
SubGrammar碰撞测试v1
测试不同SubGrammar之间的密码生成碰撞情况
"""

import sys
sys.path.append('.')
from pcfg.pcfg import TrainedGrammar, SubGrammar
import json
from helper import random, convert2group
import honeyvault_config as hny_config
from collections import defaultdict, Counter
import math
from itertools import combinations

RANDOM_PW_SET = ["bhabyko", "barkley", "baltazar", "augusta",
                 "asuncion", "april7", "adam12", "Thomas", "686868", "575757",
                 "1234565", "121090", "111189", "1111", "110589", "01230123", "ysabel",
                 "123xxxxxxxx", "thomson", "sweetz", "srilanka", "softball6",
                 "sexylove1", "sexyangel", "screen!!@", "1runaway", "randolph",
                 "pyramid", "putanginamo", "pinkys", "payatot", "patrik", "papagal",
                 "<oneluv>", "namaste", "mymother", "misery", "mimamamemima",
                 "luis123", "luckystar", "lucky8", "12lucky12", "loveyah", "lovey",
                 "loveisblind", "leopardo", "lala12", "knicks", "jonas1"]

class CollisionTest:
    def __init__(self):
        self.tg = TrainedGrammar()
        self.subgrammars = {}
        self.test_results = {}
        
    def create_password_set(self):
        """创建密码集PS：4个真密码 + 4个假密码"""
        # 随机选择4个真密码和4个假密码
        all_passwords = random.sample(RANDOM_PW_SET, 8)
        true_passwords = all_passwords[:4]
        false_passwords = all_passwords[4:]
        
        PS = true_passwords + false_passwords
        print("真密码: {}".format(true_passwords))
        print("假密码: {}".format(false_passwords))
        print("密码集PS: {}".format(PS))
        
        return PS, true_passwords, false_passwords
    
    def create_subgrammars(self, PS, true_passwords):
        """创建16个SubGrammar"""
        print("\n开始创建16个SubGrammar...")
        
        # SubGrammar 0: 使用4个真密码
        sg0 = SubGrammar(self.tg)
        sg0.update_grammar(*true_passwords)
        self.subgrammars[0] = sg0
        print("SubGrammar 0: 使用真密码 {}".format(true_passwords))
        
        # SubGrammar 1-15: 从PS中随机选择4个密码
        for i in range(1, 16):
            original_passwords = random.sample(PS, 4)
            sg = SubGrammar(self.tg)
            sg.update_grammar(*original_passwords)
            self.subgrammars[i] = sg
            print("SubGrammar {}: 使用密码 {}".format(i, original_passwords))
        
        print("✓ 16个SubGrammar创建完成")
    
    def generate_random_seed(self):
        """生成一个随机种子"""
        return [random.randint(0, hny_config.MAX_INT) for _ in range(hny_config.PASSWORD_LENGTH)]
    
    def run_single_test(self, sg_id, test_id):
        """执行单次测试"""
        sg = self.subgrammars[sg_id]
        test_label = f"test_{sg_id}_{test_id}"
        
        # 生成4个不同的随机种子
        random_seeds = []
        passwords = []
        
        for _ in range(4):
            while True:
                seed = self.generate_random_seed()
                if seed not in random_seeds:  # 确保种子不同
                    random_seeds.append(seed)
                    break
            
            try:
                decoded_pw = sg.decode_pw(seed)
                passwords.append(decoded_pw)
            except:
                passwords.append("ERROR")
        
        return {
            'label': test_label,
            'sg_id': sg_id,
            'test_id': test_id,
            'passwords': passwords,
            'cross_count': 0
        }
    
    def calculate_cross_count(self, test_result, all_tests):
        """计算当前test与其他test的交叉计数"""
        cross_count = 0
        current_passwords = set(test_result['passwords'])
        
        for other_test in all_tests:
            if other_test['label'] != test_result['label']:
                other_passwords = set(other_test['passwords'])
                if current_passwords & other_passwords:  # 有交集
                    cross_count += 1
        
        return cross_count
    
    def run_all_tests(self):
        """执行所有测试"""
        print("\n开始执行碰撞测试...")
        
        # 执行所有测试
        all_tests = []
        for sg_id in range(16):
            print(f"执行SubGrammar {sg_id} 的1000次测试...")
            for test_id in range(1000):
                test_result = self.run_single_test(sg_id, test_id)
                all_tests.append(test_result)
                
                if test_id % 100 == 0:
                    print(f"  SubGrammar {sg_id}: {test_id}/1000")
        
        # 计算cross_count
        print("\n计算交叉计数...")
        for i, test_result in enumerate(all_tests):
            cross_count = self.calculate_cross_count(test_result, all_tests)
            test_result['cross_count'] = cross_count
            
            if i % 1000 == 0:
                print(f"  已处理 {i}/{len(all_tests)} 个测试")
        
        self.test_results = all_tests
        print("✓ 所有测试完成")
    
    def save_results(self):
        """保存测试结果到文件"""
        print("\n保存测试结果...")
        
        # 按cross_count排序
        sorted_tests = sorted(self.test_results, key=lambda x: x['cross_count'], reverse=True)
        
        # 保存所有结果
        with open('collision_test_results.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SubGrammar碰撞测试结果\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("测试配置:\n")
            f.write("- 16个SubGrammar (编号0-15)\n")
            f.write("- 每个SubGrammar执行1000次测试\n")
            f.write("- 每次测试生成4个密码\n")
            f.write("- 总计16000次测试\n\n")
            
            f.write("所有测试结果 (按cross_count降序排列):\n")
            f.write("-" * 80 + "\n")
            
            for test in sorted_tests:
                f.write("标签: {:<15} | SubGrammar: {:<2} | 测试编号: {:<4} | Cross Count: {:<4} | 密码: {}\n".format(
                    test['label'], test['sg_id'], test['test_id'], 
                    test['cross_count'], test['passwords']))
        
        # 保存前50个最高cross_count的测试
        with open('top_50_collision_tests.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("Cross Count最高的前50个测试\n")
            f.write("=" * 60 + "\n\n")
            
            for i, test in enumerate(sorted_tests[:50]):
                f.write("排名 {:<2}: {:<15} | SubGrammar: {:<2} | 测试编号: {:<4} | Cross Count: {:<4}\n".format(
                    i+1, test['label'], test['sg_id'], test['test_id'], test['cross_count']))
                f.write("  密码: {}\n\n".format(test['passwords']))
        
        # 统计信息
        cross_counts = [test['cross_count'] for test in self.test_results]
        avg_cross_count = sum(cross_counts) / len(cross_counts)
        max_cross_count = max(cross_counts)
        min_cross_count = min(cross_counts)
        
        with open('collision_statistics.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 50 + "\n")
            f.write("碰撞测试统计信息\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("总测试数: {}\n".format(len(self.test_results)))
            f.write("平均Cross Count: {:.2f}\n".format(avg_cross_count))
            f.write("最大Cross Count: {}\n".format(max_cross_count))
            f.write("最小Cross Count: {}\n".format(min_cross_count))
            
            # 按SubGrammar统计
            f.write("\n按SubGrammar统计:\n")
            sg_stats = defaultdict(list)
            for test in self.test_results:
                sg_stats[test['sg_id']].append(test['cross_count'])
            
            for sg_id in sorted(sg_stats.keys()):
                counts = sg_stats[sg_id]
                f.write("SubGrammar {}: 平均 {:.2f}, 最大 {}, 最小 {}\n".format(
                    sg_id, sum(counts)/len(counts), max(counts), min(counts)))
        
        print("✓ 结果已保存到以下文件:")
        print("  - collision_test_results.txt (所有结果)")
        print("  - top_50_collision_tests.txt (前50名)")
        print("  - collision_statistics.txt (统计信息)")

def main():
    print("🚀 SubGrammar碰撞测试开始")
    
    # 创建测试实例
    collision_test = CollisionTest()
    
    # 创建密码集
    PS, true_passwords, false_passwords = collision_test.create_password_set()
    
    # 创建SubGrammar
    collision_test.create_subgrammars(PS, true_passwords)
    
    # 执行所有测试
    collision_test.run_all_tests()
    
    # 保存结果
    collision_test.save_results()
    
    print("\n🎯 碰撞测试完成！")

if __name__ == "__main__":
    main() 