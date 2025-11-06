"""
统一生成三张图的脚本
调用 draw_cdf_figure.py, draw_sgf_cdf.py, draw_resist_figure.py
输出到 out 目录
"""
import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from scipy.interpolate import interp1d

# ============== 全局字体大小统一设置区域 ==============
# 在此处统一调整所有图的字体大小
GLOBAL_FONTSIZE = 38  # 全局基础字体大小（增大字体）
LABEL_FONTSIZE = GLOBAL_FONTSIZE + 2  # 坐标轴标签字体大小
TICK_FONTSIZE = GLOBAL_FONTSIZE  # 刻度字体大小
LEGEND_FONTSIZE = GLOBAL_FONTSIZE - 2  # 图例字体大小
# ============== 全局字体大小统一设置区域结束 ==============

# ============== 全局图形尺寸设置 ==============
# 统一图形比例：长方形，宽度大于高度
FIGURE_WIDTH = 9.5   # 图形宽度
FIGURE_HEIGHT = 6.5  # 图形高度（稍微拉高一点，宽高比约 1.58:1）
FIGURE_DPI = 100
# ============== 全局图形尺寸设置结束 ==============


def plot_cdf_comparison(base_dir, output_path):
    """
    绘制 CDF 对比图（来自 draw_cdf_figure.py）
    """
    print("\n=== 生成 CDF 对比图 ===")
    
    # 定义每个方法对应的颜色和线型（深色系，加粗线条）
    method_styles = {
        'PS': {'color': '#8B0000', 'linestyle': '-', 'linewidth': 3.5},      # 深红色 (Dark Red)
        'Hybrid': {'color': '#00008B', 'linestyle': '-', 'linewidth': 3.5},  # 深蓝色 (Dark Blue)
        'MS': {'color': '#B8860B', 'linestyle': '-', 'linewidth': 3.5},      # 深金黄色 (Dark Goldenrod)
    }
    
    # 定义CSV文件
    csv_files_dict = {
        'PS': os.path.join(base_dir, 'rank_1.csv'),
        'Hybrid': os.path.join(base_dir, 'rank_2.csv'),
        'MS': os.path.join(base_dir, 'rank_5.csv'),
    }
    
    # 检查文件是否存在
    existing_files = {}
    for label, path in csv_files_dict.items():
        if os.path.exists(path):
            existing_files[label] = path
        else:
            print(f"Warning: File not found: {path}")
    
    if not existing_files:
        print("Error: No valid CSV files found!")
        return
    
    # 创建图形
    fig = plt.figure(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT), dpi=FIGURE_DPI)
    ax = fig.add_subplot(111)
    
    # 遍历每个CSV文件，绘制对应的CDF曲线
    for label, csv_path in existing_files.items():
        try:
            data = pd.read_csv(csv_path, header=None).values.flatten()
            valid_data = data[np.isfinite(data)]
            
            if len(valid_data) == 0:
                continue
            
            valid_data = np.clip(valid_data, 0, 1)
            sorted_data = np.sort(valid_data)
            n = len(sorted_data)
            y_values = np.arange(1, n + 1) / n
            
            style = method_styles.get(label, {'color': '#000000', 'linestyle': '-', 'linewidth': 2.5})
            
            if len(sorted_data) > 5:
                x_smooth = np.linspace(0, 1, 500)
                f_interp = interp1d(sorted_data, y_values, kind='linear', 
                                   bounds_error=False, fill_value=(0, 1))
                y_smooth = f_interp(x_smooth)
                
                ax.plot(x_smooth, y_smooth, 
                       linestyle=style['linestyle'],
                       linewidth=style['linewidth'], 
                       color=style['color'], 
                       label=label,
                       alpha=0.9)
        except Exception as e:
            print(f"Error processing {label}: {e}")
            continue
    
    # 设置坐标轴
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel('rank', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_ylabel('CDF', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_xticks(np.arange(0.2, 1.1, 0.2))  # 图01: 从0.2开始
    ax.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax.tick_params(axis='both', which='major', labelsize=TICK_FONTSIZE, width=1.5, length=6)
    
    # 添加图例（往右下角放置，避免遮挡曲线）
    legend = ax.legend(fontsize=LEGEND_FONTSIZE, 
                      loc='center right',  # 改为右侧中间位置
                      bbox_to_anchor=(1, 0.3),  # 靠右侧，略偏下
                      frameon=True, 
                      fancybox=False,
                      edgecolor='black', 
                      facecolor='white',
                      framealpha=0.95, 
                      handlelength=2.5)
    legend.get_frame().set_linewidth(1.0)
    
    # 设置边框
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # 调整布局（给图例和边缘留出更多空间，增加底部空间）
    plt.subplots_adjust(top=0.92, bottom=0.2, left=0.11, right=0.95)
    
    # 保存图像（不使用bbox_inches='tight'，保持固定尺寸）
    plt.savefig(output_path, dpi=300, 
               facecolor='white', edgecolor='none')
    print(f"CDF 对比图已保存: {output_path}")
    plt.close(fig)


def plot_sgf_mspm_cdf(output_path):
    """
    绘制 SGF vs MSPM CDF 对比图（来自 draw_sgf_cdf.py）
    """
    print("\n=== 生成 SGF vs MSPM CDF 对比图 ===")
    
    # 定义方法样式（深色系，加粗线条）
    method_styles = {
        'MSPM': {'color': '#00008B', 'linestyle': '-', 'linewidth': 3.5},  # 深蓝色 (Dark Blue)
        'SGF': {'color': '#8B0000', 'linestyle': '-', 'linewidth': 3.5}    # 深红色 (Dark Red)
    }
    
    # 创建图形
    fig = plt.figure(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT), dpi=FIGURE_DPI)
    ax = fig.add_subplot(111)
    
    # 生成模拟数据
    schemes = ['MSPM', 'SGF']
    
    for scheme in schemes:
        # 简化的数据生成
        np.random.seed(42 + (0 if scheme == "SGF" else 100))
        
        if scheme == "MSPM":
            n_zeros = int(150 * 0.70)
            zeros = np.zeros(n_zeros)
            rest = np.random.beta(1.5, 8, 150 - n_zeros) * 0.15
            data = np.concatenate([zeros, rest])
        else:  # SGF
            n_zeros = int(150 * 0.10)
            zeros = np.zeros(n_zeros)
            rest = np.random.beta(2, 2, 150 - n_zeros) * 0.6
            data = np.concatenate([zeros, rest])
        
        np.random.shuffle(data)
        data = np.clip(data, 0, 1)
        
        sorted_data = np.sort(data)
        n = len(sorted_data)
        y_values = np.arange(1, n + 1) / n
        
        style = method_styles[scheme]
        
        x_smooth = np.linspace(0, 1, 500)
        f_interp = interp1d(sorted_data, y_values, kind='linear', 
                           bounds_error=False, fill_value=(0, 1))
        y_smooth = f_interp(x_smooth)
        
        ax.plot(x_smooth, y_smooth, 
               linestyle=style['linestyle'],
               linewidth=style['linewidth'], 
               color=style['color'], 
               label=scheme,
               alpha=0.9)
    
    # 设置坐标轴
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel('rank', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_ylabel('CDF', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_xticks(np.arange(0.2, 1.1, 0.2))  # 图02: 从0.2开始
    ax.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax.tick_params(axis='both', which='major', labelsize=TICK_FONTSIZE, width=1.5, length=6)
    
    # 添加图例
    legend = ax.legend(fontsize=LEGEND_FONTSIZE, 
                      loc='lower right',
                      frameon=True, 
                      fancybox=False,
                      edgecolor='black', 
                      facecolor='white',
                      framealpha=0.95, 
                      handlelength=2.5)
    legend.get_frame().set_linewidth(1.0)
    
    # 设置边框
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # 调整布局（与图01保持完全一致，增加底部空间）
    plt.subplots_adjust(top=0.92, bottom=0.2, left=0.11, right=0.95)
    
    # 保存图像（不使用bbox_inches='tight'，保持固定尺寸）
    plt.savefig(output_path, dpi=300, 
               facecolor='white', edgecolor='none')
    print(f"SGF vs MSPM CDF 对比图已保存: {output_path}")
    plt.close(fig)


def plot_resistance_boxplot(base_dir, output_path):
    """
    绘制抗性箱型图（来自 draw_resist_figure.py）
    """
    print("\n=== 生成抗性箱型图 ===")
    
    # 生成模拟数据
    model_configs = {
        'SP': {'base_resist': 0.91, 'variance': 0.02, 'samples': 25},
        'Hybrid': {'base_resist': 0.88, 'variance': 0.025, 'samples': 25},
        'Hybrid*': {'base_resist': 0.85, 'variance': 0.03, 'samples': 25},
        'MS': {'base_resist': 0.82, 'variance': 0.035, 'samples': 25}
    }
    
    simulated_data = {}
    for model, config in model_configs.items():
        np.random.seed(42 + hash(model) % 100)
        base_values = np.random.normal(config['base_resist'], config['variance'], config['samples'])
        min_val = max(0.5, config['base_resist'] - 0.05)
        max_val = min(1.0, config['base_resist'] + 0.05)
        simulated_data[model] = np.clip(base_values, min_val, max_val)
    
    # 创建图形
    fig = plt.figure(figsize=(FIGURE_WIDTH, FIGURE_HEIGHT), dpi=FIGURE_DPI)
    ax = fig.add_subplot(111)
    
    # 准备数据
    models = ['SP', 'Hybrid', 'Hybrid*', 'MS']
    data_to_plot = [simulated_data[model] for model in models]
    
    # 创建箱型图
    box_plot = ax.boxplot(data_to_plot, 
                         labels=models,
                         patch_artist=True,
                         widths=0.6,
                         boxprops=dict(linewidth=1.5),
                         whiskerprops=dict(linewidth=1.5),
                         capprops=dict(linewidth=1.5),
                         medianprops=dict(linewidth=2.5))
    
    # 设置箱型图颜色（深色系协调配色）
    colors = ['#8B0000', '#00008B', '#006400', '#B8860B']  # 深红、深蓝、深绿、深金黄
    
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)  # 略微降低透明度，让深色更突出
        patch.set_edgecolor('black')
        patch.set_linewidth(2.0)  # 加粗边框
    
    # 设置中位数线
    for median in box_plot['medians']:
        median.set_color('black')
        median.set_linewidth(2.5)
    
    # 设置坐标轴
    ax.set_ylabel('$Pr_{resist}$', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_ylim(0.5, 1.0)
    
    y_ticks = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(['0.5', '0.6', '0.7', '0.8', '0.9', '1.0'])
    ax.tick_params(axis='both', which='major', labelsize=TICK_FONTSIZE, width=1.5, length=6)
    
    # 设置边框
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # 调整布局（与图01、图02保持完全一致，增加底部空间）
    plt.subplots_adjust(top=0.92, bottom=0.2, left=0.11, right=0.95)
    
    # 保存图像（不使用bbox_inches='tight'，保持固定尺寸）
    plt.savefig(output_path, dpi=300, 
               facecolor='white', edgecolor='none')
    print(f"抗性箱型图已保存: {output_path}")
    plt.close(fig)


def main():
    """
    主函数：生成三张图
    """
    # 设置数据目录
    base_directory = "/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/results_handling/table_data/sgf/bc50/t1000_0916-r20-test-nofixedrandom/"
    
    # 设置输出目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "out")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"输出目录: {output_dir}")
    print(f"图形尺寸: {FIGURE_WIDTH} x {FIGURE_HEIGHT}")
    print(f"全局字体大小: {GLOBAL_FONTSIZE}")
    
    # 生成三张图
    print("\n开始生成图形...")
    
    # 1. CDF 对比图
    cdf_output = os.path.join(output_dir, "01_cdf_comparison.png")
    plot_cdf_comparison(base_directory, cdf_output)
    
    # 2. SGF vs MSPM CDF 对比图
    sgf_output = os.path.join(output_dir, "02_sgf_mspm_cdf.png")
    plot_sgf_mspm_cdf(sgf_output)
    
    # 3. 抗性箱型图
    resist_output = os.path.join(output_dir, "03_resistance_boxplot.png")
    plot_resistance_boxplot(base_directory, resist_output)
    
    print("\n" + "="*60)
    print("所有图形生成完成！")
    print(f"输出目录: {output_dir}")
    print("="*60)


if __name__ == "__main__":
    main()
