# SGF配置文件
# 为SGF编码器提供配置参数

# SubGrammar相关配置
SEED_LEN = 100
TRUE_PASSWORD_COUNT = 6
FALSE_PASSWORD_COUNT = 12
SG_INPUT_PASSWORD_COUNT = 6

# 默认密码集（如果没有找到数据文件）
DEFAULT_PASSWORD_SET = [
    'password123', 'admin123', 'qwerty123', '123456789', 'password1',
    'welcome123', 'football123', 'baseball123', 'princess123', 'dragon123',
    'sunshine123', 'iloveyou123', 'purple123', 'monkey123', 'shadow123',
    'master123', 'freedom123', 'whatever123', 'secret123', 'jennifer123',
    'password', 'admin', 'qwerty', '123456', 'letmein',
    'welcome', 'monkey', 'dragon', 'princess', 'shadow'
]

# 物理扩展参数
DEFAULT_T = 20
DEFAULT_BATCH_SIZE = 10

# 攻击参数
SGF_ATTACK_MPW_CANDIDATES = 100  # MPW候选数量
SGF_ATTACK_TIMEOUT = 300  # 攻击超时时间（秒）

# 结果保存参数
SGF_RESULTS_DIR = 'results/sgf'
SGF_MAX_RESULTS_PER_TEST = 10  # 每个测试保存的最大结果数量
