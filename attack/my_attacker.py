import sys
# 模拟命令行参数
sys.argv = [
    'my_attacker.py',  # 脚本名称
    '--model_eval', 'mspm',
    '--victim', 'sgf',
    '--physical',
    '--withleak',
    '--softfilter',
    '--logical',
    '--spmdata', 'rockyou',
    '--exp_pastebinsuffix', '_bc50',
    '--pin', 'RockYou-4-digit.txt',
    '--pinlength', '4',
    '--intersection',
    '--version_gap', '1',
    '--isallleaked', '0',
    '--gpu', '0',
    '--tag', 'test-noleak',
    '--dtimes', '2',
    '--repeat_times', '1'
]
import os
# 添加父目录到Python模块搜索路径 这里为了导入/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['CUPY_DUMP_CUDA_SOURCE_ON_ERROR'] = '0'

import pickle
from multiprocessing import Process, Manager
from linecache import getline
from random import seed, randint, random, choice
from multiprocessing.pool import ThreadPool as Pool
import resource
from time import time
import numpy as np
import pickle as cPickle
import json
import gc
import logging
numba_logger = logging.getLogger('numba')
numba_logger.setLevel(logging.WARNING)

# 计算总执行时间时,包括导入模块初始化工具类的时间
attack_start_time = time()

from metric import Measure
from weapons import spmattack, sspmattack, decoys, mspmattack
from MSPM.mspm_config import *
from MSPM.incre_pw_coding import Incremental_Encoder
from myPCFG.pcfg.pcfg import TrainedGrammar
from para import decoymspmgen_para, decoygenspm_para, assemble_mspm
from Vault.vault import Vault
from weight import Weight
from opts import opts
args = opts().parse()

specified_testset = {'0_1':
                        {'116923':['23022008kis', 'Kis45706', 'Kisv200', 'kis23022008', 'kis4570', 'kis45706', 'kisv200', 'Kis45706', 'Kisv200', 'kis45706', 'kisv200'],
                         '3093224':['BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'BA06111990', 'BA06111990123', 'BA0611199015', 'BA06111990a', 'BA06111990d', 'BA06111990e', 'BA06111990q', 'BA06111990qwerty', 'BA06111990s', 'BA06111990w', 'ba06111990'],
                         '513':['1q2w3e', '2Kem', '2kem', 'rrjvfhjd', '1q2w3e'],
                         '24175':['hR68534', 'hr68534', 'hR68534', 'hr68534', 'hR68534', 'hr68534', 'hR68534', 'hR68534', 'hr68534']
                        }
                    }

class Attacker:
    def __init__(self, T=1, dic_size=12000):
        self.args = args
        self.T = T
        self.dic_size = dic_size
        self.true_mpw = ""
        self.true_pin = 0
        vault = Vault('admin', 123456, log_exp=LOGICAL) # init global dte for attacker
        self.dte = vault.dte 
        self.weight = Weight() # load rockyou-withcount as train set
        self.measure = Measure()
        self.cipher_dict = {}
        self.record = []
        self.concat = []
        self.dm_list = []
        with open(SOURCE_PATH + "/data/domain_hash.txt", 'r') as rf:
            for line in rf:
                self.dm_list.append(int(line.strip(), 16))
        self.pws = []
        self.crack_times = 0
        # self._load_testset() # load bc/pc as vault test set
        self.testset = {}
        
        self.incre_encoder = None
        self.repeat_times = 1 # repeat times for mspm attack
        self.btg = None
        if args.victim == 'sgf':
            self.incre_encoder = Incremental_Encoder()
            self.btg = TrainedGrammar()
            
    def add_specified_testset(self, testset):
        self.testset = testset
        
    def _load_testset(self):
        # return self.testset
        if self.args.model_eval == 'spm':
            with open(ROCKY_PATH_TEST, 'rb') as f:
                lines = cPickle.load(f)
            random.shuffle(lines)
            self.testset = []
            while len(self.testset) < REAL_PW_NUM:
                pw = lines.pop(0).lstrip().strip('\r\n').split(' ')[1]
                if lencheck(pw) or (not_in_alphabet(pw)):
                    continue
                self.testset.append(pw)
            if self.args.predecoys:
                print('reading pre-decoys =>', PRE_DECOYS)
                with open(PRE_DECOYS, 'rb') as f:
                    self.decoypws = pickle.load(f)
        else: # self.args.model_eval == 'sspm' or 'mspm'
            self.testset = {}
            max_vault_size = 0
            flst = os.listdir(PASTB_PATH+args.exp_pastebinsuffix)
            for id in TEST_FOLD:
                for fname in flst:
                    if str(TEST_DATA_ID)+'_'+str(id) in fname:
                        print('train w/o test file:', fname)
                        f = open(os.path.join(PASTB_PATH+args.exp_pastebinsuffix, fname))
                        vaults_tmp = json.load(f)
                        for vid in vaults_tmp:
                            if len(vaults_tmp[vid]) > max_vault_size:
                                max_vault_size = len(vaults_tmp[vid])
                            for pw in vaults_tmp[vid]:
                                if lencheck(pw):
                                    vaults_tmp[vid].remove(pw)
                                    print('remove unqualified pw =>', pw)
                        self.testset[str(TEST_DATA_ID) +'_'+ str(id)] = vaults_tmp
                        continue  # comment the code for training all
            print('max vault size in test set:', max_vault_size)

    def sample_pw(self):
        return getline(SOURCE_PATH + '/data/password_dict.txt', randint(1, self.dic_size)).strip()

    def get_cipher(self):
        for x in range(self.T):
            dic = cPickle.load(open(SOURCE_PATH + "/data/vault_data/vault_{}".format(x), "rb"))
            self.cipher_dict[x] = dic['cipher_list']

    def run(self):
        manager = Manager()
        Q = manager.Queue()
        print(f'start attack! tag: {self.args.tag}, repeat times: {self.repeat_times}, process num: {PROCESS_NUM}, dte: {self.args.victim}, d/r ratio: {self.args.dtimes}')
        print(f'testset_0_1 size:{len(self.testset.get("0_1", []))}')
        # print("true mpw: {}, true pin: {}".format(self.true_mpw, self.true_pin))
        workers = []
        pool = Pool(int(PROCESS_NUM / SCALE_PROCESSOR))
        start_time = time()
        if self.args.model_eval == 'mspm':
            outputdir = 'results/' + self.args.victim + '/bc50/onefold_testset/' + ('_expanded' if args.expandtestset else '') + '/attack_result' + '_' + str(N_EXP_VAULTS) + '_testdataid' + str(TEST_DATA_ID) + '_cons' + (('2_Nitv' + str(Nitv)) if args.fixeditv and args.fixeditvmode == 1 else '1') + '_pin' + args.pinlength + '_' + args.tag + '/'
            # check the file exists or not
            if not os.path.exists(outputdir):
                os.makedirs(outputdir)
            print('writing to =>', outputdir)
            print('parameter setting, T=', REFRESH_RATE, '; PIN space=', PIN_SAMPLE, '; Nitv=', Nitv if args.fixeditv and args.fixeditvmode == 1 else 'None', '; Version gap=', args.version_gap, '; isallleaked=', args.isallleaked)
            # test rounds setting
            for repnum in range(0, self.repeat_times): # repeat times 10-20
                for vtested, testid in enumerate(self.testset): # self.testset is a dict with single element,which countains 138 vaults
                    start_time_epoch = time()
                    self.dte.sspm.load(testid) # trained on complementary data set for testid
                    self.weight._init_dataset(testid) # trained on complementary data set for testid, load all vaults in ; load all vaults in bc/pb
                    testset = self.testset[testid] # test set from testid
                    batch = int(np.ceil(len(testset) / PROCESS_NUM))
                    for x in range(PROCESS_NUM): # 伪多线程,每个线程并行执行一batch mspmattack
                        if batch * x >= len(testset):
                            break
                        test_dic = []
                        vids = list(testset.keys())[x * batch: (x + 1) * batch]
                        for vid_ in vids:
                            test_dic.append(testset[vid_])  # a list of password vaults
                        print(f"mspm attack for process {x}")
                        mspmattack(repnum, outputdir, 
                                   self.T, 1, x, test_dic, 
                                   decoygenspm_para, self.dte, 
                                   self.weight, self.measure, 
                                   decoymspmgen_para, 
                                   assemble_mspm, vids, 
                                   self.incre_encoder, 
                                   self.args.dtimes, self.btg)
                print(f'using time epoch {repnum}: {time() - start_time_epoch:.4f}s')
            print('finish writing')

        end_time = time()
        print('using time:', end_time - start_time)
        print(f'finished attack! tag: {self.args.tag}, repeat times: {self.repeat_times}, process num: {PROCESS_NUM}, dte: {self.args.victim}, d/r ratio: {self.args.dtimes}')


if __name__ == '__main__':
    
    atk = Attacker(T=T_PHY)
    atk.add_specified_testset(specified_testset)
    atk.run()
    attack_end_time = time()
    # 总时长，单位s
    print('total attack time:', attack_end_time - attack_start_time, 's')

