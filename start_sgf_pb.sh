#!/bin/bash

# Bubble项目启动脚本
# 功能: 启动MSPM攻击模型测试

set -e  # 遇到错误时立即退出

# 禁用颜色输出
export NO_COLOR=1
export PYTHONUNBUFFERED=1

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_DIR="$SCRIPT_DIR/attack"

echo "🚀 启动Bubble sgf攻击测试..."
echo "脚本目录: $SCRIPT_DIR"
echo "攻击目录: $ATTACK_DIR"

# 检查attack目录是否存在
if [ ! -d "$ATTACK_DIR" ]; then
    echo "❌ 错误: attack目录不存在: $ATTACK_DIR"
    exit 1
fi

# 切换到attack目录
cd "$ATTACK_DIR"
echo "✅ 已切换到目录: $(pwd)"

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

# 检查Python是否可用
if ! command -v python &> /dev/null; then
    echo "❌ 错误: Python未找到"
    exit 1
fi

# 检查attacker.py是否存在
if [ ! -f "attacker.py" ]; then
    echo "❌ 错误: attacker.py文件不存在"
    exit 1
fi

echo "✅ 环境检查完成，开始运行攻击程序..."
echo "=========================================="

D_TIMES=2
Repeat_times=20

# 运行攻击程序
python attacker.py \
    --model_eval mspm \
    --victim sgf \
    --physical \
    --withleak \
    --softfilter \
    --logical \
    --spmdata rockyou \
    --exp_pastebinsuffix _pb \
    --pin RockYou-4-digit.txt \
    --pinlength 4 \
    --intersection \
    --version_gap 1 \
    --isallleaked 0 \
    --gpu 0 \
    --tag 1021-r$Repeat_times-pb-rdpw \
    --dtimes $D_TIMES \
    --repeat_times $Repeat_times

echo "=========================================="
echo "✅ 程序执行完成"