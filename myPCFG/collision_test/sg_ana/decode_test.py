#!/usr/bin/env python3
"""
Advanced SubGrammar Analysis Script
深度分析SubGrammar的密码生成能力、概率分布和安全性
"""

import sys
sys.path.append('.')
from pcfg.pcfg import TrainedGrammar, SubGrammar
import json
from helper import random, convert2group
import honeyvault_config as hny_config
from collections import defaultdict, Counter
import math
from advanced_subgrammar_analysis import test_original_password_recovery

outdir = "collision_test/sg_ana/"

def rule_record(sg):
    # 创建详细的语法规则记录
    rule_coverage = {}
    with open(outdir + 'dt_sg_rules.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("SubGrammar 完整语法规则记录\n")
        f.write("=" * 60 + "\n\n")
        
        for nt in sorted(sg.G.keys()):
            if nt != '__total__':
                rules = [k for k in sg.G[nt].keys() if k != '__total__']
                total_freq = sg.G[nt].get('__total__', 0)
                rule_coverage[nt] = {
                    'rule_count': len(rules),
                    'total_frequency': total_freq,
                    'rules': rules[:10]  # 显示前10条规则
                }
                
                # 写入文件
                f.write("非终结符: {}\n".format(nt))
                f.write("规则数量: {}\n".format(len(rules)))
                f.write("总频率: {}\n".format(total_freq))
                f.write("所有规则:\n")
                
                for rule in rules:
                    freq = sg.G[nt].get(rule, 0)
                    prob = freq / total_freq if total_freq > 0 else 0
                    f.write("  {} -> {} (频率: {}, 概率: {:.6f})\n".format(nt, rule, freq, prob))
                f.write("\n" + "-" * 40 + "\n\n")

    print("✓ 完整语法规则已记录到 {} 文件中".format(outdir + 'dt_sg_rules.txt'))

def main():
    print("调试subgrammar解码")
    
    # 创建SubGrammar
    tg = TrainedGrammar()
    
    # 初始化输入密码
    # original_passwords = ['bos08051585@boingo.com', 'a1b2c3d4f6g9', 'glenjacobs1994', 'zak3120', 'qwerty4un', 'kallenc.c']
    original_passwords = ['pint17', 'nmont32', 'jillxsheva', 'bos08051585@boingo.com', 'NASUWT06/87', 'y0us0k']
    
    sg = SubGrammar(tg)
    sg.update_grammar(*original_passwords)
    
    pw1 = 'pint17'
    
    # encode
    seed1 = sg.encode_pw(pw1)
    # print("{} 编码种子: {}".format(pw1, seed1))

    # decode
    random_seed = [random.randint(0, hny_config.MAX_INT) 
                      for _ in range(hny_config.PASSWORD_LENGTH)]
    decoded_rs = sg.decode_pw(seed1)
    print("解码后的密码: {}".format(decoded_rs))
    
    # get G
    rule_record(sg)
    
    # 原始密码恢复测试 - 测试test_times次
    test_times = 10000
    recovery_stats = test_original_password_recovery(sg, original_passwords, test_times, filename='dt_sg_recovery_stats.txt')
    # 对比base PCFG的密码恢复测试
    # recovery_stats_base = test_original_password_recovery(tg, original_passwords, test_times, filename='dt_base_recovery_stats.txt')

    print("原始密码集: {}".format(original_passwords))
    print("SubGrammar包含 {} 个非终结符".format(len(sg.G)))

if __name__ == "__main__":
    main()
