import os
import json
import pickle as cPickle
import numpy as np

MAX_PW_LENGTH = 30 # max length for seed with pathencode,fixed by zzp,origin 30
max_pw_length = MAX_PW_LENGTH - 1 # without pathencode
MIN_PW_LENGTH = 4 # minimum pw length
#   SPM
ALPHABET = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"


def not_in_alphabet(string):
    for char in string:
        if not char in ALPHABET:
            return True
    return False

def init_rky():
    rockyou = {} 
    pky = '/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/data/rockyou-withcount'
    w_dir = '/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/input_dataset/rockyou_withcount.txt'
    print('loading test file (weight.py):', pky)
    with open(pky, 'rb') as f:
        lines = cPickle.load(f)
        for line in lines:
            contents = line.strip().split()  # in the format of 'count password'
            if len(contents) != 2:
                continue
            # print(contents.strip().split())
            if lencheck(contents[1]) or not_in_alphabet(contents[1]):
                continue
            rockyou[contents[1]] = int(contents[0])
    print('loaded', len(rockyou), 'pws')
    n = np.array(list(rockyou.values())).sum()
    
    # 将rockyou数据写入文件，每行一个元素（格式：count password）
    print(f'writing rockyou data to: {w_dir}')
    os.makedirs(os.path.dirname(w_dir), exist_ok=True)
    with open(w_dir, 'w', encoding='utf-8') as f:
        f.write(f'total_n: {n}\n')
        f.write(f'count password\n')
        for password, count in rockyou.items():
            f.write(f'{count} {password}\n')
    print(f'rockyou data written to {w_dir}, total passwords: {len(rockyou)}, total count: {n}')
    
    return rockyou, n

def lencheck(pw):
    # true for unqualified pw
    return (not ((len(pw) >= MIN_PW_LENGTH) and (len(pw) <= MAX_PW_LENGTH)))

def load_testset():
    # return  testset
    testset = {}
    max_vault_size = 0
    data_path = '/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/data/breachcompilation/fold2_bc50'
    flst = os.listdir(data_path)
    TEST_FOLD = [1]
    TEST_DATA_ID = 0
    for id in TEST_FOLD:
        for fname in flst:
            if str(TEST_DATA_ID)+'_'+str(id) in fname:
                print('train w/o test file:', fname)
                f = open(os.path.join(data_path, fname))
                vaults_tmp = json.load(f)
                for vid in vaults_tmp:
                    if len(vaults_tmp[vid]) > max_vault_size:
                        max_vault_size = len(vaults_tmp[vid])
                    for pw in vaults_tmp[vid]:
                        if lencheck(pw):
                            vaults_tmp[vid].remove(pw)
                            print('remove unqualified pw =>', pw)
                testset[str(TEST_DATA_ID) +'_'+ str(id)] = vaults_tmp
                continue  # comment the code for training all
    print('max vault size in test set:', max_vault_size)
    return testset

if __name__ == '__main__':
    init_rky()
    # testset = load_testset()
    
    # # 创建输出目录（如果不存在）
    # output_dir = '/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/input_dataset'
    # os.makedirs(output_dir, exist_ok=True)
    
    # # 写入txt文件
    # output_file = os.path.join(output_dir, 'bc_50_fold_0_1.txt')
    
    # # 自定义格式：列表压缩成一行，对象保持缩进
    # def custom_json_format(data):
    #     import re
    #     # 先正常序列化
    #     json_str = json.dumps(data, indent=2, ensure_ascii=False)
    #     # 使用正则表达式将列表压缩成一行
    #     # 匹配数组格式: [\n  "item1",\n  "item2"\n]
    #     pattern = r'\[\s*\n\s*(".*?"(?:,\s*\n\s*".*?")*)\s*\n\s*\]'
    #     def compress_list(match):
    #         # 提取数组内容并压缩成一行
    #         content = match.group(1)
    #         # 移除换行和多余空格
    #         items = re.findall(r'".*?"', content)
    #         return '[' + ', '.join(items) + ']'
        
    #     return re.sub(pattern, compress_list, json_str)
    
    # with open(output_file, 'w', encoding='utf-8') as f:
    #     f.write(custom_json_format(testset))
    
    # print(f'testset已成功写入文件: {output_file}')
    # print(f'总共包含 {len(testset)} 个测试数据集')