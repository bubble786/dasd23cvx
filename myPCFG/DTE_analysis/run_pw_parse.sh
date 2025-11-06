#!/bin/bash

# 检查conda是否可用
if ! command -v conda &> /dev/null; then
    echo "❌ 错误: conda未找到，请确保已安装并配置conda"
    exit 1
fi

# 初始化conda环境
echo "🔧 初始化conda环境..."
eval "$(conda shell.bash hook)"

# 激活myse环境
echo "🔧 激活conda环境: myse"
conda activate myse

python test_pw_parse.py