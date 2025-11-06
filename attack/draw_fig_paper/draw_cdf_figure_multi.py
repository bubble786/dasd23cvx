import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from scipy.interpolate import interp1d
import os

def plot_multiple_rank_cdf(csv_files_dict, output_path=None, title="BC50"):
    """
    在同一个图中绘制多条rank CDF曲线
    
    参数:
    csv_files_dict: dict, 键为标签名，值为CSV文件路径
    output_path: str, 输出图像路径
    title: str, 图像标题
    """
    
    # 定义每个方法对应的颜色和线型，参考原图样式
    method_styles = {
        'Single password (SP)': {'color': '#0000FF', 'linestyle': ':', 'linewidth': 2.5},  # 蓝色点线
        'Password similarity (PS)': {'color': '#DA70D6', 'linestyle': '-', 'linewidth': 2.5},  # 紫色实线
        'Hybrid': {'color': '#008B8B', 'linestyle': '-', 'linewidth': 2.5},  # 深青色实线
        'KL': {'color': '#8B4513', 'linestyle': '-', 'linewidth': 2.5},  # 棕色实线
        'List-based': {'color': '#FF8C00', 'linestyle': '-', 'linewidth': 2.5},  # 橙色实线
        'Metric similarity (MS)': {'color': '#FF8C00', 'linestyle': '-', 'linewidth': 2.5},  # 橙色实线（修改1：从灰色虚线改为橙色实线）
        'Hybrid*': {'color': '#00BFFF', 'linestyle': '-', 'linewidth': 2.5}  # 天蓝色实线
    }
    
    # ============== 字体大小统一设置区域（修改3：可在此处统一调整所有字体大小）==============
    # 设置matplotlib参数
    GLOBAL_FONTSIZE = 20  # 全局基础字体大小（可修改此值来统一调整字体）18 / 
    LABEL_FONTSIZE = GLOBAL_FONTSIZE + 2  # 坐标轴标签字体大小
    TICK_FONTSIZE = GLOBAL_FONTSIZE  # 刻度字体大小
    TITLE_FONTSIZE = GLOBAL_FONTSIZE + 2  # 标题字体大小
    LEGEND_FONTSIZE = GLOBAL_FONTSIZE - 2  # 图例字体大小
    
    plt.rcParams.update({
        'font.size': GLOBAL_FONTSIZE,
        'font.family': 'serif',
        'axes.linewidth': 1.5,
        'grid.linewidth': 0.5,
        'lines.linewidth': 2.5,
        'xtick.major.width': 1.5,
        'ytick.major.width': 1.5,
        'xtick.major.size': 6,
        'ytick.major.size': 6,
    })
    # ============== 字体大小统一设置区域结束 ==============
    
    fig, ax = plt.subplots(figsize=(6, 5), dpi=100)
    
    # 遍历每个CSV文件，绘制对应的CDF曲线
    for i, (label, csv_path) in enumerate(csv_files_dict.items()):
        try:
            # 读取数据
            data = pd.read_csv(csv_path, header=None).values.flatten()
            print(f"Processing {label}: Original data size: {len(data)}")
            
            # 过滤掉inf和nan值
            valid_data = data[np.isfinite(data)]
            print(f"{label}: Valid data size after filtering: {len(valid_data)}")
            
            if len(valid_data) == 0:
                print(f"Warning: No valid data for {label}")
                continue
                
            # 确保数据在[0,1]范围内
            valid_data = np.clip(valid_data, 0, 1)
            
            # 排序数据用于CDF计算
            sorted_data = np.sort(valid_data)
            n = len(sorted_data)
            y_values = np.arange(1, n + 1) / n
            
            # 获取当前方法的样式设置
            style = method_styles.get(label, {'color': '#000000', 'linestyle': '-', 'linewidth': 2.0})
            
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
                       alpha=0.8,
                       color=style['color'], 
                       label=label, zorder=3)
            else:
                # 如果数据点太少，直接绘制原始数据
                ax.plot(sorted_data, y_values, 
                       linestyle=style['linestyle'],
                       linewidth=style['linewidth'], 
                       alpha=0.8,
                       color=style['color'], 
                       label=label, zorder=3)
                       
        except Exception as e:
            print(f"Error processing {label}: {e}")
            continue
    
    # 设置坐标轴范围和标签
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel('rank', fontsize=LABEL_FONTSIZE, fontweight='normal')
    ax.set_ylabel('CDF', fontsize=LABEL_FONTSIZE, fontweight='normal')
    
    # 设置刻度
    ax.set_xticks(np.arange(0.0, 1.1, 0.2))
    ax.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax.tick_params(axis='both', which='major', labelsize=TICK_FONTSIZE)
    
    # 添加网格
    ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5, zorder=1)
    
    # 修改2：不再在图中绘制图例，图例将通过单独函数导出
    # legend = ax.legend(fontsize=9, loc='upper center', bbox_to_anchor=(0.5, 1.15),
    #                   ncol=4, frameon=True, fancybox=False, 
    #                   edgecolor='black', facecolor='white',
    #                   framealpha=1.0, columnspacing=1.0)
    # legend.get_frame().set_linewidth(0.8)
    
    # 设置标题（已删除，避免与rank标签重叠）
    # ax.text(0.5, -0.15, f'{title}', transform=ax.transAxes, 
    #         fontsize=TITLE_FONTSIZE, ha='center', va='top', fontweight='normal')
    
    # 移除上边框和右边框
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.0)
    ax.spines['bottom'].set_linewidth(1.0)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    plt.tight_layout()
    
    # 保存或显示图像
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        print(f"Multiple rank CDF figure saved to: {output_path}")
    else:
        plt.show()
    
    return fig, ax

def draw_cdf(dataset_name, base_dir):
    """
    绘制指定数据集的多条CDF曲线对比图

    参数:
    dataset_name: str, 数据集名称
    base_dir: str, 包含rank_0.csv到rank_6.csv文件的目录路径
    """
    
    # 定义各个rank文件对应的方法标签
    csv_files_dict = {
        # 'Single password (SP)': os.path.join(base_dir, 'rank_0.csv'), 
        'Password similarity (PS)': os.path.join(base_dir, 'rank_1.csv'),
        'Hybrid': os.path.join(base_dir, 'rank_2.csv'),
        # 'KL': os.path.join(base_dir, 'rank_3.csv'),
        # 'List-based': os.path.join(base_dir, 'rank_4.csv'),
        'Metric similarity (MS)': os.path.join(base_dir, 'rank_5.csv'),
        # 'Hybrid*': os.path.join(base_dir, 'rank_6.csv')
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
    
    # 设置输出路径
    output_path = os.path.join(base_dir, f'{dataset_name}_cdf_comparison.png')
    
    # 绘制多条CDF曲线
    print(f"Creating {dataset_name} multiple CDF comparison plot...")
    plot_multiple_rank_cdf(
        csv_files_dict=existing_files,
        output_path=output_path,
        title=dataset_name
    )

    print(f"\n{dataset_name} CDF comparison completed! Output saved to: {output_path}")

def export_legend_only(output_path=None, legend_labels=None, ncol=3, fontsize=None):
    """
    修改2：单独导出图例，用于论文中多个图共用一个图例
    
    参数:
    output_path: str, 输出图例图像路径
    legend_labels: list, 要显示的标签列表，如果为None则使用默认标签
    ncol: int, 图例的列数
    fontsize: int, 图例字体大小，如果为None则使用LEGEND_FONTSIZE
    
    示例用法:
    export_legend_only(
        output_path='legend.png',
        legend_labels=['Password similarity (PS)', 'Hybrid', 'Metric similarity (MS)'],
        ncol=3
    )
    """
    
    # 设置字体大小
    GLOBAL_FONTSIZE = 18
    LEGEND_FONTSIZE = fontsize if fontsize else (GLOBAL_FONTSIZE - 2)
    
    # 定义每个方法对应的颜色和线型（与主绘图函数保持一致）
    method_styles = {
        'Single password (SP)': {'color': '#0000FF', 'linestyle': ':', 'linewidth': 2.5},
        'Password similarity (PS)': {'color': '#DA70D6', 'linestyle': '-', 'linewidth': 2.5},
        'Hybrid': {'color': '#008B8B', 'linestyle': '-', 'linewidth': 2.5},
        'KL': {'color': '#8B4513', 'linestyle': '-', 'linewidth': 2.5},
        'List-based': {'color': '#FF8C00', 'linestyle': '-', 'linewidth': 2.5},
        'Metric similarity (MS)': {'color': '#FF8C00', 'linestyle': '-', 'linewidth': 2.5},
        'Hybrid*': {'color': '#00BFFF', 'linestyle': '-', 'linewidth': 2.5}
    }
    
    # 如果没有指定标签，使用默认标签
    if legend_labels is None:
        legend_labels = ['Password similarity (PS)', 'Hybrid', 'Metric similarity (MS)']
    
    # 创建一个小的虚拟图形
    fig, ax = plt.subplots(figsize=(10, 0.5))
    ax.axis('off')
    
    # 创建虚拟的线条用于生成图例
    lines = []
    for label in legend_labels:
        style = method_styles.get(label, {'color': '#000000', 'linestyle': '-', 'linewidth': 2.5})
        line, = ax.plot([], [], 
                       linestyle=style['linestyle'],
                       linewidth=style['linewidth'],
                       color=style['color'],
                       label=label)
        lines.append(line)
    
    # 创建图例
    legend = ax.legend(handles=lines, 
                      fontsize=LEGEND_FONTSIZE, 
                      loc='center',
                      ncol=ncol, 
                      frameon=True, 
                      fancybox=False,
                      edgecolor='black', 
                      facecolor='white',
                      framealpha=1.0, 
                      columnspacing=2.0,
                      handlelength=3.0)
    legend.get_frame().set_linewidth(1.0)
    
    # 设置背景颜色
    fig.patch.set_facecolor('white')
    
    # 保存图例
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none', pad_inches=0.1)
        print(f"Legend saved to: {output_path}")
    else:
        plt.show()
    
    plt.close(fig)
    return fig

if __name__ == "__main__":
    # 示例用法
    # used tag- t1000_0918-r20-rdpw/  t1000_0916-r20-test-nofixedrandom/
    base_directory = "/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/attack/results_handling/table_data/sgf/bc50/t1000_0916-r20-test-nofixedrandom/"
    
    # 绘制CDF图（不含图例）
    dataset_name = "bc50"
    draw_cdf(dataset_name, base_directory)
    
    # 单独导出图例
    legend_output = os.path.join(base_directory, 'legend_only.png')
    export_legend_only(
        output_path=legend_output,
        legend_labels=['Password similarity (PS)', 'Hybrid', 'Metric similarity (MS)'],
        ncol=3,  # 可以设置为3列横向排列
        fontsize=16  # 可以自定义图例字体大小
    )
    # print(f"Legend saved to: {legend_output}")