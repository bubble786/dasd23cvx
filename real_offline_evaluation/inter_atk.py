import os
import sys
# 添加父目录到Python模块搜索路径 这里为了导入/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MSPM.incre_pw_coding import Incremental_Encoder
from MSPM.unreused_prob import unreuse_p
from MSPM.SSPM.pcfg import RulePCFGCreator
from MSPM.utils import random, gen_gilst
from Vault.utils import set_crypto
import struct
import logging
import numpy as np
from MSPM.mspm_config import *
import os
import json
numba_logger = logging.getLogger('numba')
numba_logger.setLevel(logging.WARNING)
#from Golla.configs.configure import *
#from Golla.ngram_creator import NGramCreator
from numba import cuda
from MSPM.SPM.configs.configure import Configure
from MSPM.SPM.ngram_creator import NGramCreator
#from numba import jit
from opts import opts
args = opts().parse()

def real_inter_atk_test():
    vault = {}
    flst = os.listdir(SOURCE_PATH + '/data/pastebin/fold2_pb')
    for fname in flst:
        f = open(os.path.join(SOURCE_PATH + '/data/pastebin/fold2_pb', fname))
        vault.update(json.load(f))
    selected_vault = vault[0]
    incre_encoder = Incremental_Encoder()

if __name__ == '__main__':
    real_inter_atk_test()