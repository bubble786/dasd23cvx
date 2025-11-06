import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from scipy.interpolate import interp1d
import os

def generate_simulated_data(scheme, n_samples=138, seed=42):
    """
    生成模拟的归一化rank数据
    
    参数:
    scheme: str, "SGF" 或 "MSPM"
    n_samples: int, 样本数量
    seed: int, 随机种子
    """
    np.random.seed(seed + (0 if scheme == "SGF" else 100))
    
    if scheme == "MSPM":
        # MSPM: 大部分rank=0 (即rank=1，归一化后为0), 整体分布在0-0.15之间
        # 70%的数据为rank=0
        n_zeros = int(n_samples * 0.70)
        zeros = np.zeros(n_zeros)
        
        # 30%的数据分布在0-0.15之间
        n_rest = n_samples - n_zeros
        # 使用Beta分布生成偏向0的数据
        rest = np.random.beta(1.5, 8, n_rest) * 0.15
        
        data = np.concatenate([zeros, rest])
        
    else:  # SGF
        # SGF: 在0-0.6之间较均匀分布
        # 10%的数据为rank=0
        n_zeros = int(n_samples * 0.10)
        zeros = np.zeros(n_zeros)
        
        # 90%的数据在0-0.6之间较均匀分布
        n_rest = n_samples - n_zeros
        # 使用Beta分布生成相对均匀的数据
        rest = np.random.beta(2, 2, n_rest) * 0.6
        
        data = np.concatenate([zeros, rest])
    
    # 打乱顺序
    np.random.shuffle(data)
    
    # 确保数据在[0,1]范围内
    data = np.clip(data, 0, 1)
    
    return data

def plot_sgf_mspm_cdf(output_path=None):
    """
    绘制SGF和MSPM的CDF对比图，风格与draw_cdf_figure.py一致
    """
    
    # ============== 字体大小统一设置区域（与draw_cdf_figure.py保持一致）==============
    GLOBAL_FONTSIZE = 20  # 全局基础字体大小
    LABEL_FONTSIZE = GLOBAL_FONTSIZE + 2  # 坐标轴标签字体大小
    TICK_FONTSIZE = GLOBAL_FONTSIZE  # 刻度字体大小
    LEGEND_FONTSIZE = GLOBAL_FONTSIZE - 2  # 图例字体大小
    # ============== 字体大小统一设置区域结束 ==============
    
    # 定义方法样式（与draw_cdf_figure.py保持一致的线宽）
    method_styles = {
        'MSPM': {'color': '#008B8B', 'linestyle': '-', 'linewidth': 2.5},  # 深青色实线
        'SGF': {'color': '#DA70D6', 'linestyle': '-', 'linewidth': 2.5}   # 紫色实线
    }
    
    # 创建图形和坐标轴（与draw_cdf_figure.py保持一致的尺寸）
    fig = plt.figure(figsize=(6.5, 6), dpi=100)
    ax = fig.add_subplot(111)
    
    # 生成并绘制每个方法的CDF曲线
    schemes = ['MSPM', 'SGF']
    
    for scheme in schemes:
        # 生成模拟数据
        data = generate_simulated_data(scheme, n_samples=150)
        
        print(f"\n{scheme} 数据统计:")
        print(f"  样本数: {len(data)}")
        print(f"  均值: {np.mean(data):.4f}")
        print(f"  中位数: {np.median(data):.4f}")
        print(f"  rank=0的比例: {(data == 0).sum() / len(data):.2%}")
        print(f"  rank<0.15的比例: {(data < 0.15).sum() / len(data):.2%}")
        
        # 排序数据用于CDF计算
        sorted_data = np.sort(data)
        n = len(sorted_data)
        y_values = np.arange(1, n + 1) / n
        
        # 获取样式设置
        style = method_styles[scheme]
        
        # 创建平滑的插值曲线
        if len(sorted_data) > 5:
            # 创建更密集的点用于平滑显示
            x_smooth = np.linspace(0, 1, 500)
            
            # 使用插值创建平滑曲线
            f_interp = interp1d(sorted_data, y_values, kind='linear', 
                               bounds_error=False, fill_value=(0, 1))
            y_smooth = f_interp(x_smooth)
            
            # 绘制平滑的CDF曲线
            ax.plot(x_smooth, y_smooth, 
                   linestyle=style['linestyle'],
                   linewidth=style['linewidth'], 
                   color=style['color'], 
                   label=scheme,
                   alpha=0.9)
        else:
            # 如果数据点太少，直接绘制原始数据
            ax.plot(sorted_data, y_values, 
                   linestyle=style['linestyle'],
                   linewidth=style['linewidth'], 
                   color=style['color'], 
                   label=scheme,
                   alpha=0.9)
    
    # 设置坐标轴（与draw_cdf_figure.py保持一致）
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel('Normalized rank', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_ylabel('CDF', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_xticks(np.arange(0.0, 1.1, 0.2))
    ax.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax.tick_params(axis='both', which='major', labelsize=TICK_FONTSIZE, width=1.5, length=6)
    
    # 去掉网格线（与draw_cdf_figure.py保持一致）
    # ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    
    # 添加图例（放在右下角，与draw_cdf_figure.py保持一致）
    legend = ax.legend(fontsize=LEGEND_FONTSIZE, 
                      loc='lower right',
                      frameon=True, 
                      fancybox=False,
                      edgecolor='black', 
                      facecolor='white',
                      framealpha=0.95, 
                      handlelength=2.5)
    legend.get_frame().set_linewidth(1.0)
    
    # 设置边框（与draw_cdf_figure.py保持一致）
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # 调整布局（与draw_cdf_figure.py保持一致，减少两侧留白）
    plt.subplots_adjust(top=0.96, bottom=0.12, left=0.14, right=0.96)
    
    # 保存或显示图像
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none', pad_inches=0.2)
        print(f"\nSGF vs MSPM CDF figure saved to: {output_path}")
    else:
        plt.show()
    
    plt.close(fig)
    return fig, ax

if __name__ == "__main__":
    # 设置输出路径
    output_directory = "/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/output_figure/"
    output_path = os.path.join(output_directory, 'sgf_mspm_cdf_comparison.png')
    
    print("Creating SGF vs MSPM CDF comparison plot...")
    plot_sgf_mspm_cdf(output_path)
