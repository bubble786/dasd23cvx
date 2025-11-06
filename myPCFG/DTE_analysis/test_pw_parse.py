#!/usr/bin/env python3
"""
打印输出basePCFG的grammar统计分布
"""

import sys
import os
source_path = '/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/myPCFG'
sys.path.append(source_path)
# 确保能够在source_path下读写文件
os.chdir(source_path)
from pcfg.pcfg import TrainedGrammar, SubGrammar
import json
from helper import random, convert2group
import honeyvault_config as hny_config
from collections import defaultdict, Counter
import math
from datetime import datetime

outdir = "DTE_analysis/"

def pad_y1_PCFG(tg:TrainedGrammar):
    """
    向TrainedGrammar的Y1非终结符添加缺失的字符规则
    添加字符: ", |, }
    频率从[100, 30000]范围随机选择
    """
    # 需要添加的缺失字符
    missing_chars = ['"', '|', '}', '\\']
    
    # 检查Y1是否存在
    if 'Y1' not in tg.G:
        print("警告: Y1非终结符不存在于语法中")
        return
    
    # 获取Y1的规则字典
    y1_rules = tg.G['Y1']
    
    # 为每个缺失字符添加规则
    added_rules = []
    for char in missing_chars:
        if char not in y1_rules:
            # 从[100, 30000]范围随机选择频率
            freq = random.randint(100, 30000)
            y1_rules[char] = freq
            added_rules.append((char, freq))
            print(f"✓ 添加规则: Y1 -> {char} (频率: {freq})")
        else:
            print(f"× 规则已存在: Y1 -> {char} (频率: {y1_rules[char]})")
    
    # 重新计算__total__
    if '__total__' in y1_rules:
        # 排除__total__键，计算所有规则频率的总和
        total_freq = sum(freq for key, freq in y1_rules.items() if key != '__total__')
        y1_rules['__total__'] = total_freq
        print(f"✓ 更新Y1总频率: {total_freq}")
    
    print(f"✓ 成功添加了 {len(added_rules)} 条新规则到Y1非终结符")

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

    print("✓ 完整语法规则已记录到 {} 文件中".format(outdir + 'bg_sg_rules.txt'))

def save_basePCFG_grammar():
    
    outfile = outdir + "basePCFG_grammar_stats.txt"
    with open(outfile, 'w', encoding='utf-8') as f:
        f.write("处理时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("=" * 80 + "\n")
        f.write("Base PCFG Grammar统计分布\n")
        f.write("=" * 80 + "\n")
        
        sg = tg
        # get G['G'] if it exists
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
        
        # get G['T'] if it exists
        if hasattr(sg, 'G') and 'Y1' in sg.G:
            f.write("语法规则 (self.G['Y1']):\n")
            grammar_rules = sg.G['Y1']
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
    print("✓ 语法统计分布已保存到 {} 文件中".format(outfile))

def test_special_pw(pw, tg:TrainedGrammar):
    
    sg = SubGrammar(tg)
    original_passwords = ['pint17', 'nmont32', 'jillxsheva', 'bos08051585@boingo.com', 'NASUWT06/87', 'y0us0k']
    sg.update_grammar(*original_passwords)
    
    # code_g = sg.encode_pw(pw)
    print(f"pw: {pw}")
    pt = sg.max_parse_tree(pw)
    print(f"max parse tree: {pt}")

if __name__ == "__main__":

    tg = TrainedGrammar()
    pad_y1_PCFG(tg)

    save_basePCFG_grammar()

    bug_pws = ['siddique\\']
    for pw in bug_pws:
        test_special_pw(pw, tg)
