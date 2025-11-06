import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from scipy import stats
from scipy.interpolate import interp1d

def plot_rank_cdf(csv_file_path, output_path=None):
    """
    绘制rank CDF图像，包含真实数据（平滑处理）和perfect rank对角线
    """
    # 读取数据
    data = pd.read_csv(csv_file_path, header=None).values.flatten()
    print(f"Original data size: {len(data)}")
    
    # 过滤掉inf和nan值
    valid_data = data[np.isfinite(data)]
    print(f"Valid data size after filtering inf/nan: {len(valid_data)}")
    print(f"Filtered out {len(data) - len(valid_data)} invalid values")
    
    # 确保数据在[0,1]范围内
    valid_data = np.clip(valid_data, 0, 1)
    
    # 排序数据用于CDF计算
    sorted_data = np.sort(valid_data)
    n = len(sorted_data)
    y_values = np.arange(1, n + 1) / n
    
    # 设置matplotlib参数
    plt.rcParams.update({
        'font.size': 14,
        'font.family': 'serif',
        'axes.linewidth': 1.5,
        'grid.linewidth': 0.8,
        'lines.linewidth': 2.5,
        'patch.linewidth': 0.5,
        'xtick.major.width': 1.5,
        'ytick.major.width': 1.5,
        'xtick.major.size': 6,
        'ytick.major.size': 6,
    })
    
    fig, ax = plt.subplots(figsize=(8, 6), dpi=100)
    
    # 创建平滑的插值曲线用于真实数据
    if len(sorted_data) > 5:
        # 创建更密集的点用于平滑显示
        x_smooth = np.linspace(0, 1, 500)
        
        # 使用插值创建平滑曲线，扩展到整个[0,1]范围
        f_interp = interp1d(sorted_data, y_values, kind='linear', 
                           bounds_error=False, fill_value=(0, 1))
        y_smooth = f_interp(x_smooth)
        
        # 绘制平滑的真实数据曲线
        ax.plot(x_smooth, y_smooth, '-', linewidth=3, alpha=0.9,
               color='#1f77b4', label='Actual Rank', zorder=3)
    else:
        # 如果数据点太少，直接绘制原始数据
        ax.plot(sorted_data, y_values, '-', linewidth=3, alpha=0.9,
               color='#1f77b4', label='Actual Rank', zorder=3)
    
    # 绘制perfect rank对角线（理想情况）
    x_perfect = np.linspace(0, 1, 100)
    y_perfect = x_perfect
    ax.plot(x_perfect, y_perfect, '--', linewidth=2.5, alpha=0.8,
           color='#ff7f0e', label='Perfect Rank', zorder=2)
    
    # 设置坐标轴范围和标签
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel('rank', fontsize=16, fontweight='normal')
    ax.set_ylabel('CDF', fontsize=16, fontweight='normal')
    
    # 设置刻度
    ax.set_xticks(np.arange(0.0, 1.1, 0.2))
    ax.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax.tick_params(axis='both', which='major', labelsize=14)
    
    # 添加网格
    ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.8, zorder=1)
    
    # 设置图例
    legend = ax.legend(fontsize=14, loc='lower right', 
                      frameon=True, fancybox=False, 
                      edgecolor='black', facecolor='white',
                      framealpha=1.0)
    legend.get_frame().set_linewidth(1.0)
    
    # 移除上边框和右边框，保持简洁
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    plt.tight_layout()
    
    # 保存或显示图像
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        print(f"Rank CDF figure saved to: {output_path}")
    else:
        plt.show()
    
    # 打印统计信息
    print(f"\nStatistics:")
    print(f"Valid samples: {len(valid_data)}")
    print(f"Mean rank: {np.mean(valid_data):.4f}")
    print(f"Median rank: {np.median(valid_data):.4f}")
    print(f"Standard deviation: {np.std(valid_data):.4f}")
    if len(valid_data) > 100:
        print(f"25th percentile: {np.percentile(valid_data, 25):.4f}")
        print(f"75th percentile: {np.percentile(valid_data, 75):.4f}")
    
    return fig, ax

def draw_main(readdir):
    """主函数"""
    # file_dir = "/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/results_handling/table_data/sgf/bc50/t1000_v1/"
    file_dir = readdir
    csv_file = f"{file_dir}rank.csv"
    output_dir = file_dir
    
    # 绘制rank CDF图像
    print("Creating rank CDF plot...")
    plot_rank_cdf(
        csv_file_path=csv_file,
        output_path=output_dir + "rank_cdf.png"
    )
    
    print("\nVisualization completed!")

if __name__ == "__main__":
    draw_main()
