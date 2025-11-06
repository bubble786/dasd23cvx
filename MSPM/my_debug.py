from unreused_prob import *
import matplotlib
matplotlib.use('Agg')  # 设置非交互式后端
import matplotlib.pyplot as plt
import numpy as np

def get_password_reuse_probability(n):
    """
    计算第n+1个密码重用的概率
    
    Args:
        n (int): 已有密码的数量
        
    Returns:
        dict: 包含各种重用概率的字典
            - 'unreuse_prob': 第n+1个密码不重用的概率
            - 'reuse_prob': 第n+1个密码重用的概率
            - 'direct_reuse_prob': 第n+1个密码直接重用的概率（完全相同）
            - 'modified_reuse_prob': 第n+1个密码修改重用的概率（相似但不同）
    """
    if n <= 0:
        return {
            'unreuse_prob': 1.0,  # 第一个密码必然不重用
            'reuse_prob': 0.0,
            'direct_reuse_prob': 0.0,
            'modified_reuse_prob': 0.0
        }
    
    # 使用拟合的unreuse_p函数计算不重用概率
    unreuse_probability = unreuse_p(n)
    
    # 重用概率 = 1 - 不重用概率
    reuse_probability = 1 - unreuse_probability
    
    # 如果发生重用，计算直接重用和修改重用的概率
    if reuse_probability > 0:
        # 根据代码中的公式：alpha参数影响直接重用的概率
        # 使用代码中的ALPHA值（如果已定义）或默认值
        alpha = getattr(sys.modules[__name__], 'ALPHA', 0.192)  # 默认alpha值
        
        # 直接重用概率 = 重用概率 × (n * alpha) / (n * alpha + 1 - alpha)
        direct_reuse_conditional_prob = (n * alpha) / (n * alpha + 1 - alpha)
        direct_reuse_prob = reuse_probability * direct_reuse_conditional_prob
        
        # 修改重用概率 = 重用概率 - 直接重用概率
        modified_reuse_prob = reuse_probability - direct_reuse_prob
    else:
        direct_reuse_prob = 0.0
        modified_reuse_prob = 0.0
    
    return {
        'unreuse_prob': unreuse_probability,
        'reuse_prob': reuse_probability,
        'direct_reuse_prob': direct_reuse_prob,
        'modified_reuse_prob': modified_reuse_prob
    }

def get_cumulative_reuse_probabilities(max_n):
    """
    计算从第1个到第max_n个密码的累积重用概率
    
    Args:
        max_n (int): 最大密码数量
        
    Returns:
        dict: 包含各种概率的numpy数组
    """
    results = {
        'positions': np.arange(1, max_n + 1),
        'unreuse_probs': np.zeros(max_n),
        'reuse_probs': np.zeros(max_n),
        'direct_reuse_probs': np.zeros(max_n),
        'modified_reuse_probs': np.zeros(max_n)
    }
    
    for i in range(max_n):
        prob_dict = get_password_reuse_probability(i)
        results['unreuse_probs'][i] = prob_dict['unreuse_prob']
        results['reuse_probs'][i] = prob_dict['reuse_prob']
        results['direct_reuse_probs'][i] = prob_dict['direct_reuse_prob']
        results['modified_reuse_probs'][i] = prob_dict['modified_reuse_prob']
    
    return results

def plot_reuse_probabilities_simple(max_n=50):
    """
    绘制密码重用概率曲线（简化版，无中文）
    
    Args:
        max_n (int): 最大密码数量
    """
    results = get_cumulative_reuse_probabilities(max_n)
    
    # 单个大图
    plt.figure(figsize=(10, 6))
    plt.plot(results['positions'], results['reuse_probs'], 'r-', linewidth=2, label='Reuse Probability')
    plt.plot(results['positions'], results['unreuse_probs'], 'b-', linewidth=2, label='No-Reuse Probability')
    
    plt.xlabel('Password Position')
    plt.ylabel('Probability')
    plt.title('Password Reuse Probability Analysis')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # 添加一些数值标注
    for i in [5, 10, 15, 20]:
        if i < len(results['reuse_probs']):
            plt.annotate(f'{results["reuse_probs"][i]:.3f}', 
                        xy=(i+1, results['reuse_probs'][i]), 
                        xytext=(5, 5), textcoords='offset points',
                        fontsize=8, alpha=0.7)
    
    plt.tight_layout()
    # 保存到文件而不是显示
    plt.savefig('password_reuse_analysis.png', dpi=300, bbox_inches='tight')
    print("图表已保存到: password_reuse_analysis.png")
    plt.close()

# 使用示例
if __name__ == '__main__':
    # 示例1：计算第10个密码重用的概率
    prob_10 = get_password_reuse_probability(9)  # 输入9表示已有9个密码，计算第10个
    print("第10个密码的重用概率分析:")
    print(f"  不重用概率: {prob_10['unreuse_prob']:.4f}")
    print(f"  重用概率: {prob_10['reuse_prob']:.4f}")
    print(f"  直接重用概率: {prob_10['direct_reuse_prob']:.4f}")
    print(f"  修改重用概率: {prob_10['modified_reuse_prob']:.4f}")
    
    # 示例2：批量计算前20个密码的重用概率
    print("\n前20个密码的重用概率:")
    for i in range(1, 21):
        prob = get_password_reuse_probability(i-1)
        print(f"第{i}个密码重用概率: {prob['reuse_prob']:.4f}")
    
    # 示例3：绘制概率曲线
    print("\n绘制概率曲线...")
    plot_reuse_probabilities_simple(50)