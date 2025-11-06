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

RANDOM_PW_SET = ["bhabyko", "barkley", "baltazar", "augusta",
                 "asuncion", "april7", "adam12", "Thomas", "686868", "575757",
                 "1234565", "121090", "111189", "1111", "110589", "01230123", "ysabel",
                 "123xxxxxxxx", "thomson", "sweetz", "srilanka", "softball6",
                 "sexylove1", "sexyangel", "screen!!@", "1runaway", "randolph",
                 "pyramid", "putanginamo", "pinkys", "payatot", "patrik", "papagal",
                 "<oneluv>", "namaste", "mymother", "misery", "mimamamemima",
                 "luis123", "luckystar", "lucky8", "12lucky12", "loveyah", "lovey",
                 "loveisblind", "leopardo", "lala12", "knicks", "jonas1"]

outdir = "collision_test/sg_ana/"

def analyze_subgrammar_exhaustive(sg, max_samples=1000):
    """彻底分析SubGrammar的密码生成空间"""
    print("🔍 开始详细分析SubGrammar...")
    
    # 1. 分析语法规则覆盖度并完整记录到文件
    print("\n=== 语法规则分析 ===")
    rule_coverage = {}
    
    # 创建详细的语法规则记录
    with open(outdir + 'asa_sg_rules.txt', 'w', encoding='utf-8') as f:
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

    print("✓ 完整语法规则已记录到 {} 文件中".format(outdir + 'asa_sg_rules.txt'))
    
    # for nt, info in sorted(rule_coverage.items()):
    #     print("  {}: {}条规则, 总频率: {}".format(nt, info['rule_count'], info['total_frequency']))
    #     if len(info['rules']) <= 5:
    #         print("    规则: {}".format(info['rules']))
    #     else:
    #         print("    前5条规则: {}...".format(info['rules'][:5]))
    
    # 2. 生成大量样本分析
    print("\n=== 生成 {} 个样本密码 ===".format(max_samples))
    password_samples = []
    generation_stats = {
        'success': 0,
        'errors': 0,
        'duplicate_codes': 0
    }
    
    seen_codes = set()
    
    for i in range(max_samples):
        try:
            # 生成随机编码
            random_code = tuple([random.randint(0, hny_config.MAX_INT) 
                               for _ in range(hny_config.PASSWORD_LENGTH)])
            
            if random_code in seen_codes:
                generation_stats['duplicate_codes'] += 1
            seen_codes.add(random_code)
            
            # 解码为密码
            password = sg.decode_pw(list(random_code))
            password_samples.append(password)
            generation_stats['success'] += 1
            
            if i % 100 == 0:
                print("  进度: {}/{}".format(i, max_samples))
                
        except Exception as e:
            generation_stats['errors'] += 1
            if generation_stats['errors'] < 5:  # 只显示前5个错误
                print("  生成错误 #{}: {}".format(generation_stats['errors'], e))
    
    print("生成统计: 成功{}, 错误{}, 重复编码{}".format(
        generation_stats['success'], generation_stats['errors'], generation_stats['duplicate_codes']))
    
    # 3. 密码频率分析
    password_counter = Counter(password_samples)
    unique_count = len(password_counter)
    
    print("\n=== 密码频率分析 ===")
    print("唯一密码数量: {}".format(unique_count))
    print("总样本数量: {}".format(len(password_samples)))
    print("多样性比率: {:.4f}".format(unique_count/len(password_samples)))
    
    # 4. 长度分布分析
    length_dist = Counter([len(pw) for pw in password_samples])
    print("\n=== 密码长度分布 ===")
    for length in sorted(length_dist.keys()):
        count = length_dist[length]
        percentage = count / len(password_samples) * 100
        print("  长度 {}: {} 个 ({:.1f}%)".format(length, count, percentage))
    
    # 5. 字符集分析
    char_analysis = {
        'letters': 0,
        'digits': 0,
        'symbols': 0,
        'mixed': 0
    }
    
    for pw in password_samples:
        has_letter = any(c.isalpha() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_symbol = any(not c.isalnum() for c in pw)
        
        if has_letter and has_digit and has_symbol:
            char_analysis['mixed'] += 1
        elif has_letter:
            char_analysis['letters'] += 1
        elif has_digit:
            char_analysis['digits'] += 1
        else:
            char_analysis['symbols'] += 1
    
    print("\n=== 字符类型分布 ===")
    for char_type, count in char_analysis.items():
        percentage = count / len(password_samples) * 100
        print("  {}: {} 个 ({:.1f}%)".format(char_type, count, percentage))
    
    # 6. 概率分析
    print("\n=== Top 20 最频繁密码 ===")
    top_passwords = password_counter.most_common(20)
    for i, (pw, count) in enumerate(top_passwords, 1):
        probability = count / len(password_samples)
        display_pw = pw[:30] + "..." if len(pw) > 30 else pw
        print("  {:2d}. '{}' - {}次 (概率: {:.4f})".format(i, display_pw, count, probability))
    
    # 7. 熵计算
    entropy = calculate_shannon_entropy(password_counter, len(password_samples))
    max_entropy = math.log2(unique_count) if unique_count > 0 else 0
    
    print("\n=== 信息熵分析 ===")
    print("实际熵值: {:.4f} bits".format(entropy))
    print("最大可能熵值: {:.4f} bits".format(max_entropy))
    entropy_efficiency = "熵效率: {:.4f}".format(entropy/max_entropy) if max_entropy > 0 else "熵效率: N/A"
    print(entropy_efficiency)
    
    return {
        'password_samples': password_samples,
        'password_counter': password_counter,
        'unique_count': unique_count,
        'entropy': entropy,
        'max_entropy': max_entropy,
        'generation_stats': generation_stats,
        'rule_coverage': rule_coverage
    }

def calculate_shannon_entropy(counter, total):
    """计算香农熵"""
    entropy = 0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy

def test_original_password_recovery(sg, original_passwords, num_trials=10000000, filename='asa_password_recovery_stats.txt'):
    """测试原始密码的恢复概率 - 提高到10000000次试验"""
    print("\n=== 原始密码恢复测试 ({} 次试验) ===".format(num_trials))
    
    recovery_stats = {pw: 0 for pw in original_passwords}
    total_attempts = 0
    
    # 添加所有解密密码的频率统计
    all_passwords_freq = {}
    
    # 创建详细的恢复统计文件
    recovery_file = outdir + filename

    with open(recovery_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("原始密码恢复概率统计 ({} 次试验)\n".format(num_trials))
        f.write("=" * 60 + "\n\n")
        f.write("原始密码集: {}\n\n".format(original_passwords))
    
    for i in range(num_trials):
        random_code = [random.randint(0, hny_config.MAX_INT) 
                      for _ in range(hny_config.PASSWORD_LENGTH)]
        try:
            decoded_pw = sg.decode_pw(random_code)
            total_attempts += 1
            
            # 统计所有解密密码的频率
            if decoded_pw in all_passwords_freq:
                all_passwords_freq[decoded_pw] += 1
            else:
                all_passwords_freq[decoded_pw] = 1
            
            # 统计原始密码的恢复
            if decoded_pw in recovery_stats:
                recovery_stats[decoded_pw] += 1
        except:
            continue

        # 更频繁的进度报告（每5000次）
        if i % 5000 == 0:
            print("  测试进度: {}/{} ({:.1f}%)".format(i, num_trials, i/num_trials*100))
    
    # 详细记录恢复统计
    print("\n原始密码恢复统计:")
    with open(recovery_file, 'a', encoding='utf-8') as f:
        f.write("总试验次数: {}\n".format(num_trials))
        f.write("成功解码次数: {}\n".format(total_attempts))
        f.write("解码成功率: {:.4f}%\n\n".format(total_attempts/num_trials*100))
        
        f.write("各密码恢复统计:\n")
        f.write("-" * 40 + "\n")
        
        total_recoveries = 0
        for pw, count in recovery_stats.items():
            probability = count / num_trials
            probability_given_success = count / total_attempts if total_attempts > 0 else 0
            
            print("  '{}': {}次 (概率: {:.8f})".format(pw, count, probability))
            
            f.write("密码: '{}'\n".format(pw))
            f.write("  恢复次数: {}\n".format(count))
            f.write("  恢复概率: {:.8f} ({}/{})\n".format(probability, count, num_trials))
            f.write("  条件概率: {:.8f} (在成功解码中的比例)\n".format(probability_given_success))
            f.write("\n")
            
            total_recoveries += count
        
        f.write("-" * 40 + "\n")
        f.write("总恢复次数: {}\n".format(total_recoveries))
        f.write("总恢复概率: {:.8f}\n".format(total_recoveries/num_trials))
        
        if total_recoveries > 0:
            f.write("\n安全性分析:\n")
            f.write("- 在{}次随机试验中，共恢复出{}次原始密码\n".format(num_trials, total_recoveries))
            f.write("- 平均每{}次试验恢复1次原始密码\n".format(int(num_trials/total_recoveries) if total_recoveries > 0 else "∞"))
        else:
            f.write("\n安全性分析:\n")
            f.write("- 在{}次随机试验中，没有恢复出任何原始密码\n".format(num_trials))
            f.write("- 这表明SubGrammar提供了很好的蜜罐保护\n")
        
        # 添加前100个最频繁出现的密码统计
        f.write("\n" + "=" * 60 + "\n")
        f.write("前100个最频繁出现的密码统计\n")
        f.write("=" * 60 + "\n\n")
        
        # 按频率排序，取前100个
        sorted_passwords = sorted(all_passwords_freq.items(), key=lambda x: x[1], reverse=True)
        top_100_passwords = sorted_passwords[:100]
        
        f.write("总共解密出 {} 种不同的密码\n".format(len(all_passwords_freq)))
        f.write("前100个最频繁密码及其统计信息:\n\n")
        
        for rank, (password, count) in enumerate(top_100_passwords, 1):
            probability = count / total_attempts if total_attempts > 0 else 0
            frequency_in_trials = count / num_trials
            
            f.write("第{}名: '{}'\n".format(rank, password))
            f.write("  出现次数: {}\n".format(count))
            f.write("  在所有解码中的概率: {:.8f} ({}/{})\n".format(probability, count, total_attempts))
            f.write("  在所有试验中的频率: {:.8f} ({}/{})\n".format(frequency_in_trials, count, num_trials))
            if password in original_passwords:
                f.write("  *** 这是原始密码之一 ***\n")
            f.write("\n")
        
        # 统计前100密码的累计频率
        top_100_total = sum(count for _, count in top_100_passwords)
        top_100_coverage = top_100_total / total_attempts if total_attempts > 0 else 0
        
        f.write("-" * 40 + "\n")
        f.write("前100个密码统计汇总:\n")
        f.write("前100个密码总出现次数: {}\n".format(top_100_total))
        f.write("前100个密码覆盖率: {:.4f}% (在所有成功解码中的占比)\n".format(top_100_coverage * 100))
        
        # 统计前100中有多少是原始密码
        original_in_top100 = sum(1 for pw, _ in top_100_passwords if pw in original_passwords)
        f.write("前100个密码中包含的原始密码数量: {}/{}\n".format(original_in_top100, len(original_passwords)))
    
    print("✓ 详细恢复统计已记录到 {} 文件中".format(recovery_file))
    
    return recovery_stats

def main():
    print("🚀 高级SubGrammar分析开始")
    
    # 创建SubGrammar
    tg = TrainedGrammar()
    # 初始化输入密码
    # original_passwords = ["adam33", "pinkys", "lovey", "12lucky12", "12lucky", "namaste", "12lacky12"]
    # original_passwords = ['11platesx', 'awcobjeue', 'kmk123', '113091', 'hiddenkiller', 'grindcore']
    original_passwords = ['kindred6', 'cowsgomoo', '159753', 'Philipp246', 'pantech1o', 'hiddenkiller']

    sg = SubGrammar(tg)
    sg.update_grammar(*original_passwords)

    seed1 = sg.encode_pw('11platesx')
    # print("12lucky12 编码种子: {}".format(seed1))
    
    print("原始密码集: {}".format(original_passwords))
    print("SubGrammar包含 {} 个非终结符".format(len(sg.G)))
    
    # 详细分析
    analysis_results = analyze_subgrammar_exhaustive(sg, max_samples=2000)
    
    # 原始密码恢复测试 - 测试test_times次
    test_times = 10000
    recovery_stats = test_original_password_recovery(sg, original_passwords, test_times)

    # 安全性评估
    print("\n🔒 安全性评估")
    total_recovery = sum(recovery_stats.values())
    if total_recovery > 0:
        print("在{}次随机试验中，原始密码被恢复 {} 次".format(test_times, total_recovery))
        print("总体恢复率: {:.8f}".format(total_recovery/test_times))
        print("平均每 {} 次试验恢复1次原始密码".format(int(test_times/total_recovery)))
    else:
        print("在{}次随机试验中，没有恢复出任何原始密码".format(test_times))
        print("这表明SubGrammar提供了极强的蜜罐保护")
    
    unique_ratio = analysis_results['unique_count'] / len(analysis_results['password_samples'])
    if unique_ratio > 0.5:
        print("✓ 密码多样性良好")
    else:
        print("⚠ 密码多样性较低，可能存在安全风险")
    
    print("\n🎯 分析完成！")

if __name__ == "__main__":
    main()
