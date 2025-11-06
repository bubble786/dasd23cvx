import os
import sys
# 添加父目录到Python模块搜索路径 这里为了导入/home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['CUPY_DUMP_CUDA_SOURCE_ON_ERROR'] = '0'

# 导入外部模块和解析参数args
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


# 导入自定义模块
from MSPM.mspm_config import *
from opts import opts
args = opts().parse()
print(f'start attack! tag: {args.tag}, repeat times: {args.repeat_times}, process num: {PROCESS_NUM}, dte: {args.victim}, d/r ratio: {args.dtimes}')
print(f'testset: {args.exp_pastebinsuffix}, PASTB_PATH={PASTB_PATH}')
attack_start_time = time()
# 计算总执行时间时,包括导入模块初始化工具类的时间
from metric import Measure
from weapons import spmattack, sspmattack, decoys, mspmattack
from MSPM.incre_pw_coding import Incremental_Encoder
from myPCFG.pcfg.pcfg import TrainedGrammar
from para import decoymspmgen_para, decoygenspm_para, assemble_mspm
from Vault.vault import Vault
from weight import Weight

class Attacker:
    def __init__(self, T=1, dic_size=12000):
        self.args = args
        self.T = T
        self.repeat_times = args.repeat_times # repeat times for mspm attack
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
        self._load_testset() # load bc/pc as vault test set
        self.incre_encoder = None
        self.btg = None # base trained grammar for sgf dte construction
        if args.victim == 'sgf':
            self.incre_encoder = Incremental_Encoder()
            self.btg = TrainedGrammar()

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
        
        print(f'testset_0_1 size:{len(self.testset.get("0_1", []))}')
        workers = []
        pool = Pool(int(PROCESS_NUM / SCALE_PROCESSOR))
        start_time = time()
        if self.args.model_eval == 'spm':
            assert len(self.testset) % PROCESS_NUM == 0
            batch = int(len(self.testset) / PROCESS_NUM / SCALE_PROCESSOR)
            for x in range(int(PROCESS_NUM * SCALE_PROCESSOR)):
                workers.append(pool.apply_async(spmattack, (Q, str(((x+1)/(PROCESS_NUM*SCALE_PROCESSOR))*100), self.T, batch, x, self.testset, self.decoygen_para, self.dte, self.weight, )))
        elif self.args.model_eval == 'mspm':
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
                                   self.args.dtimes, btg=self.btg, mpwset=self.weight.rockyou)
                print(f'using time epoch {repnum}: {time() - start_time_epoch:.4f}s')
            print('finish writing')
        # else: # 'sspm'
        #     batch = int(np.ceil(len(self.testset) / PROCESS_NUM))
        #     for x in range(PROCESS_NUM):
        #         if batch * x >= len(self.testset):
        #             break
        #         test_dic = []
        #         for vid_ in list(self.testset.keys())[x*batch: (x+1)*batch]:
        #             test_dic.append(self.testset[vid_]) # a list
        #         for _ in range(REPEAT_NUM):
        #             workers.append(pool.apply_async(sspmattack, (Q, str(((x+1)/PROCESS_NUM)*100), \
        #                                              self.T, 1, x, test_dic, self.sample_pw, self.dte,
        #                                              self.weight, self.decoysspmgen_para, self.assemble_sspm)))
        end_time = time()
        # 再打印使用了多少h
        print(f'using time : {(end_time - start_time)/3600:.4f}h ({end_time - start_time:.4f}s)')
        print(f'finished attack! tag: {self.args.tag}, repeat times: {self.repeat_times}, process num: {PROCESS_NUM}, dte: {self.args.victim}, d/r ratio: {self.args.dtimes}')


if __name__ == '__main__':
    atk = Attacker(T=T_PHY)
    atk.run()
    attack_end_time = time()
    # 总时长，单位s
    print('total attack time:', attack_end_time - attack_start_time, 's')

    # ==== test correctness of spm para =====
    '''seed = []
    seed.extend(atk.dte.spm.encode_pw('1d1f32345')[0])
    seed.extend([0])
    seed.extend(atk.dte.spm.encode_pw('sji2oo9')[0])
    seed.extend([0])
    seed.extend(atk.dte.spm.encode_pw('sji31ds12oo9')[0])
    seed.extend([0])
    seed.extend(atk.dte.spm.encode_pw('sji2d32!oo9')[0])
    seed.extend([0])
    seed.extend(atk.dte.spm.encode_pw('sji2oo9fwe')[0])
    seed.extend([0])
    seed.extend(atk.dte.spm.encode_pw('sj/Si2ooAS9')[0])
    seed.extend([0])
    print(len(seed))
    seed, prob = decoygen_para_test(6, np.array(seed), atk.dte.spm)
    print(seed)
    print(prob)'''

    # ==== test correctness of the mspm para =====
    '''vault = {}
    flst = os.listdir(SOURCE_PATH + '/data/pastebin/fold5')
    for fname in flst:
        f = open(os.path.join(SOURCE_PATH + '/data/pastebin/fold5', fname))
        vault.update(json.load(f))
    incre_ecoder = Incremental_Encoder()
    for vault_id in vault:
        print(vault[vault_id])
        conca = []
        for pw in vault[vault_id]:
            if lencheck(pw):
                print('dropping => pw of length', len(pw))
                vault[vault_id].remove(pw)
        for i in range(len(vault[vault_id])):
            conca = incre_ecoder.encode_pw_testunit(conca, vault[vault_id][i], vault[vault_id][:i])

        v = decoymspmgen_para_testunit(len(conca)//SEED_LEN-1, 1, incre_ecoder, np.array(conca[SEED_LEN:]), vault[vault_id])
        print(v[0])
        assert v[0] == vault[vault_id]'''