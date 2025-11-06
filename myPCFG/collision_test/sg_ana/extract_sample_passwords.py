#!/usr/bin/env python3
"""
从rockyou-withcount.txt文件中随机选取1000个密码
文件格式: 频数 密码
"""

import random
import sys
import os

def extract_sample_passwords(input_file, output_file, sample_size=1000):
    """
    从输入文件中随机选取指定数量的密码
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        sample_size: 要选取的密码数量
    """
    print(f"开始从 {input_file} 中提取 {sample_size} 个密码...")
    
    # 第一遍扫描：计算总行数
    total_lines = 0
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip():  # 跳过空行
                total_lines += 1
    
    print(f"总共发现 {total_lines} 行密码数据")
    
    # 生成随机行号
    if total_lines < sample_size:
        print(f"警告: 文件中只有 {total_lines} 行，少于要求的 {sample_size} 行")
        sample_size = total_lines
    
    selected_lines = sorted(random.sample(range(total_lines), sample_size))
    print(f"已选择 {len(selected_lines)} 个随机行号")
    
    # 第二遍扫描：提取选中的行
    selected_passwords = []
    current_line = 0
    next_target_idx = 0
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:  # 跳过空行
                continue
                
            if next_target_idx < len(selected_lines) and current_line == selected_lines[next_target_idx]:
                # 解析格式: "频数 密码"
                parts = line.split(' ', 1)  # 只分割第一个空格
                if len(parts) >= 2:
                    frequency = parts[0]
                    password = parts[1]
                    selected_passwords.append((frequency, password))
                    next_target_idx += 1
                    
                    if len(selected_passwords) % 100 == 0:
                        print(f"已提取 {len(selected_passwords)} 个密码...")
            
            current_line += 1
            
            # 如果已经找到所有目标行，提前结束
            if next_target_idx >= len(selected_lines):
                break
    
    # 写入输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for frequency, password in selected_passwords:
            f.write(f"{frequency} {password}\n")
    
    print(f"成功提取 {len(selected_passwords)} 个密码到 {output_file}")
    
    # 显示一些示例
    print("\n前10个密码示例:")
    for i, (freq, pwd) in enumerate(selected_passwords[:10]):
        print(f"{i+1:2d}. {freq:>6s} {pwd}")

def main():
    # 文件路径
    input_file = "/home/zzp/lab/bubble/SubGrammar/PCFG/myPCFG-v2/data/rockyou-withcount.txt"
    output_file = "/home/zzp/lab/bubble/SubGrammar/PCFG/myPCFG-v2/collision_test/sg_ana/sample_pw.txt"

    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 {input_file} 不存在")
        return
    
    # 设置随机种子以确保可重现性（可选）
    random.seed(42)
    
    try:
        extract_sample_passwords(input_file, output_file, 1000)
        print(f"\n处理完成！结果已保存到: {output_file}")
    except Exception as e:
        print(f"错误: {e}")

if __name__ == "__main__":
    main()
