import os

# 示例数据
metaid_histog = [10, 20, 30]
lines = ['line1', 'line2', 'line3']
write_dir = './'  # 假设你想写入的目录

# 构建完整文件路径
output_file = os.path.join(write_dir, 'test.csv')

# 自动创建目录
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# 写入文件
with open(output_file, 'w') as f:
    for line in lines:
        f.write(((line.strip() + ',') if line.strip() else '') + '\n')