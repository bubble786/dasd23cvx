import sys
# 模拟命令行参数
sys.argv = [
    'my_debug.py',  # 脚本名称
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
    '--gpu', '0'
]
import os
import json
import copy
from time import time
import tqdm
import random
import subprocess
import math
from multiprocessing import Pool
from linecache import getline
# from attack.para import check_logical
from para import check_logical
import numpy as np
import pickle
from opts import opts
from utils import Digit_Vault, grouprandom_fixeditv
from tqdm import tqdm
import cupy as cp
args = opts().parse()
from MSPM.mspm_config import *
from myPCFG.my_vaultsys import *
from myPCFG.my_vaultsys.offline_guess import sgf
from myPCFG.my_vaultsys.setup_vault import generate_random_mpw
from MSPM.incre_pw_coding import Incremental_Encoder, gen_n_password
from Vault.vault import Vault
from weight import Weight
from metric import Measure
from para import decoymspmgen_para, decoygenspm_para, assemble_mspm

from MSPM.unreused_prob import unreuse_p

def mspmattack(rn, outputdir, T, batch, x, testset, decoygen, dte, weight, measure, vaultgen, assem_pws, vids):
    """
    str(x * (repeat_id + 1)), self.T, batch, x, self.testset, self.decoygen, self.dte,
    :param data: decoy pws list with length (N_EXP_VAULTS-1)*batch
    :param T: physical expansion
    :param dte: sspm
    :param testset: single pw vault
    :param weight:
    :param assem_pws: args (num, length, pws, pwrules, basepw)
    :return: [[threa1], [threa2], ..., [threan]]
    """
    unique_vids = list(range(len(testset))) # [vss.index(vs) for vs in unique_vss]
    expansion_rate = [1] * len(testset) # [(i+3) for i in range(len(testset))]
    decoy_num = REFRESH_RATE + PS_DECOYSIZE # number of decoy vaults that will be generated
    for n_, tset in enumerate(tqdm(testset)): # tset is a password vault (list of passwords) from dataset
        print(f"n_: {n_}, tset: {tset}")
        #tset = decoy_vaults[0] # test only
        if n_ not in unique_vids:
            continue

        '''if rn < 0:
            continue
        elif rn == 0 and n_ < 26:
            continue'''

        batch_bundle = [] # each element is [[results_avault_aiter, pin_frequency_lists], softs_aiter, reshuedidx]
        results_avault_aiter = [] # list with N_EXP_VAULTS vault "results", starting from real to the rest of fake
        softs_aiter = []
        feat_tmp = weight.features[0] # random.randint(0, len(weight.features) - 1)
        DV = Digit_Vault(tset, int(vids[n_]), int(len(tset)/expansion_rate[n_]) if args.expandtestset else None) # represent vualt as a digit vault for ease of experiment
        pin_gt = random_pin() # randomly drawn from test set
        mpw_gt = random_mpw()
        #print('Reak mpw: ', mpw_gt, 'Real pin: ', pin_gt)
        if not args.intersection:
            dvlist = list(grouprandom_fixeditv(DV.create_dv(tset)[0]).keys()) if args.fixeditv else None
            scrambled_idx = list_shuffle(mpw_gt, pin_gt, len(tset), existing_list=dvlist)
        else:
            assert args.version_gap > 0 and len(tset) > args.version_gap
            seed_ = random.randint(0, MAX_INT)
            # get leaked versions based on setting "--version_gap" and "--isallleaked"
            dvlist_versions = [list(grouprandom_fixeditv(DV.create_dv(tset[:(len(tset)-vg)])[0], seedconst=seed_).keys()) if args.fixeditv else None for vg in range(args.version_gap+1)]
            scrambled_idx = [list_shuffle(mpw_gt, pin_gt, len(tset)-vg, existing_list=dvlist_versions[vg]) for vg in range(args.version_gap+1)]
            if args.isallleaked == 0:
                scrambled_idx = [scrambled_idx[0], scrambled_idx[-1]]

        reshuedidx = getshuffledidx(scrambled_idx, tset, pin_gt, gpuid=args.gpu) # reshuffled mapping in the shape of (PIN_REFRESH, PADDED_TO*PIN_SAMPLE)

        pin_frequency_lists = [] # list of pin freq list for each candidate vault (mpw)
        #ts = time()
        for threa in range(N_EXP_VAULTS if not args.withleak else T_PHY):
            results = {}
            if threa % REFRESH_RATE == 0:
                # one for each vault; probs are log-summed only (without /4)                
                if args.victim == 'sgf':
                    print(f"sgf start")
                    # 1-init dte
                    sgf_T = T
                    real_pws = tset
                    incre_encoder = Incremental_Encoder()
                    # gen by MSPM encoder with random seeds, size 2n
                    len_real = len(real_pws)
                    dummy_pws, new_vault = gen_n_password(real_pws, incre_encoder, len_real*2)

                    sgf_dte = sgf(T=sgf_T, real_pws = real_pws, dummy_pws=dummy_pws)
                    
                    # 步骤1: 构造vault system并收集MPW
                    sgf_dte.setup_vault_system(sgf_T)
                    # 步骤2: 设计MPW到SubGrammar的映射
                    sgf_dte.design_mpw_to_sg_mapping()
                    # 2-get real vault mpw and random mpw
                    vaultseed = sgf_dte.acquire_realvault_seed(real_pws)
                    real_vault_mpw = [sgf_dte.real_mpw]

                    randommpws = []
                    for i in range((REFRESH_RATE+PS_DECOYSIZE)*2):
                        randommpws.append(generate_random_mpw(16))
                        
                    # 3-gen decoyvaults
                    decoyvaults, probs_spm_mspm = sgf_dte.gen_decoyvaults(real_vault_mpw)
                    decoyvaults_, probs_spm_mspm_ = sgf_dte.gen_decoyvaults(randommpws)
                    
                probs_spm_mspm.extend(probs_spm_mspm_)
                decoyvaults.extend(decoyvaults_)

                if threa == 0 and (args.victim == 'MSPM' or args.victim == 'Golla'):
                    vault = tset
                    results['psp'] = additionw(weight.singlepass(vault, dte.spm), vault, DV.leakpw, DV.leakmetaid)
                    kl = additionw(weight.kl(vault, dte.spm), vault, DV.leakpw, DV.leakmetaid)
                    wang_singlepass = additionw(weight.wang_singlepass(vault, dte), vault, DV.leakpw, DV.leakmetaid)
                elif threa == 0 and (args.victim == 'PCFG' or args.victim == 'sgf'):
                    vault = decoyvaults[threa % REFRESH_RATE]
                    prob_tmp = probs_spm_mspm[(threa % REFRESH_RATE) * len(tset): (threa % REFRESH_RATE) * len(tset) + len(tset)]
                    results['psp'] = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                    kl = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                    wang_singlepass = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                    if results['psp'] == 0:
                        results['psp'] = weight.singlepass(vault, dte.spm, prob_tmp)
                        kl = weight.kl(vault, dte.spm, prob_tmp)
                        wang_singlepass = weight.wang_singlepass(vault, dte, prob_tmp)
            if threa > 0:
                # PS_DECOYSIZE decoy vaults used for similarity weight calculation
                #s_ = time()
                vault = decoyvaults[threa % REFRESH_RATE]#assem_pws((PS_DECOYSIZE + 1) * (threa % REFRESH_RATE), 1, len(tset) - 1, pws, dte=dte, newpws=path1newpws)[0]
                #print('waepons: assemble a vault using', time() - s_)
                prob_tmp = probs_spm_mspm[(threa % REFRESH_RATE) * len(tset): (threa % REFRESH_RATE) * len(tset) + len(tset)]
                results['psp'] = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                kl = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                wang_singlepass = additionw(0, vault, DV.leakpw, DV.leakmetaid)
                if results['psp'] == 0:
                    results['psp'] = weight.singlepass(vault, dte.spm, prob_tmp)
                    kl = weight.kl(vault, dte.spm, prob_tmp)
                    wang_singlepass = weight.wang_singlepass(vault, dte, prob_tmp)
            if args.logical:
                pin_frequency_lists.append([vault, DV])
            #s_ = time()
            results['pps'] = additionw(0, vault, DV.leakpw, DV.leakmetaid)
            if results['pps'] == 0:
                decoy_draws = list(np.random.randint(PS_DECOYSIZE, size=30) + REFRESH_RATE)
                decoys = [decoyvaults[draw_id] for draw_id in decoy_draws]
                decodic = {dvid:decoys[dvid] for dvid in range(len(decoys))}
                # assem_pws((PS_DECOYSIZE + 1) * (threa % REFRESH_RATE) + 1, PS_DECOYSIZE, len(vault) - 1, pws, dte, newpws=path1newpws)
                results['pps'] = weight.passsimi(vault, dte, decodic, feat_tmp, weight.p_real)
            #print('waepons: assemble PS_DECOYSIZE vaults using', time() - s_)
            # start, num, length, pws, basepw, dte, probs=None, p=False
            results['phybrid'] = additionw(results['psp'] * results['pps'], vault, DV.leakpw, DV.leakmetaid)
            results['kl'] = kl
            results['wang_single'] = wang_singlepass[0] if isinstance(wang_singlepass, list) else wang_singlepass
            results['wang_similar'] = 1 if kl != -np.inf else -np.inf # placeholder, will be modified in func 'addition_weight'
            results['wang_hybrid'] = wang_singlepass
            results['vault'] = vault
            if DV.leakpw in vault and args.softfilter:
                softs_aiter.append(1)
            else:
                softs_aiter.append(1)
            results_avault_aiter.append(results)

        batch_bundle.append([[results_avault_aiter, pin_frequency_lists], softs_aiter, reshuedidx])
        # addition_weight(batch_bundle)
        worker = measure.rank_r([batch_bundle[0][0]], [batch_bundle[0][1]], '4' in args.pin, batch_bundle[0][2], args.gpu, rn*len(testset)+n_)
        with open(outputdir + 'results_' + 'v' + str(n_) + '_shot' + str(rn) + '.data', 'wb') as f:
            pickle.dump(worker, f)

def getthreshold(dte, pw_lst, problst, pw): # get the probability of independent encoding of pw
    ith = len(pw_lst) # starting from 1 for f(ith)
    prob = dte.spm.encode_pw(pw)[1]
    thre = 1.
    if ith > 0:
        prob_lst = [np.log(np.array(prob)).sum() + np.log(unreuse_p(ith))]
        for i in range(ith):
            prob = dte.sspm.encode_pw(pw_lst[i], pw, ith)[1]
            prob = np.log(np.array(prob)).sum() + problst[i] + np.log((1 - unreuse_p(ith)) / ith) if len(prob) != 0 else -np.inf
            prob_lst.append(prob)
        thre = np.exp(prob_lst[0]/4.) / np.exp(np.array(prob_lst)/4.).sum()
    return thre

def addition_weight(batch_bundle):
    # add weights to each vault in results (dict) by calling aother python script using subprocess
    # step1: write unique password of each vault into a txt file (each pw a row) 'credtweak/credTweakAttack/test_files/dataset_ts.txt'
    # step2: call another python script to predict score for each pw (which then will write reults into 'credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts.predictions')
    # step3: read the file and update into additional weight for each vault

    # step1
    pws = []
    for i, vault_digitvault in enumerate(batch_bundle[0][0][1]):
        pws_avault_ = list(set(vault_digitvault[0]))
        pws_avault = [pw for pw in pws_avault_ if len(pw)>5]
        pws.extend(pws_avault)
    pws = list(set(pws))
    sfx = '_' + str(T_PHY) + args.pinlength + str(args.gpu) + (str(Nitv) if args.fixeditv else '') + str(args.version_gap) + args.exp_pastebinsuffix + args.victim # avoid conflict
    with open(SOURCE_PATH + '/attack/credtweak/credTweakAttack/test_files/dataset_ts' + sfx + '.txt', 'w') as f:
        for pw in pws:
            f.write(pw + '\n')

    # step2 /home/beeno/Dropbox/research_project/pycharm/credtweak/credTweakAttack/score_eachvault.py
    # /home/zzp/miniconda3/envs/path2path/bin/python
    # /home/beeno/anaconda3/envs/pass2path/bin/python
    # /home/zzp/lab/bubble/credtweak/credtweak/credTweakAttack/score_eachvault.py
    # /home/beeno/Dropbox/research_project/pycharm/credtweak/credTweakAttack/score_eachvault.py
    subprocess.call(['/home/zzp/miniconda3/envs/path2path/bin/python',
                     '/home/zzp/lab/bubble/credtweak/credtweak/credTweakAttack/score_eachvault.py',
                     '-gpu', str(args.gpu), '-sfx', sfx])

    # step3 results file '/home/beeno/Dropbox/research_project/pycharm/credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts.pkl'
    # /home/zzp/lab/bubble/credtweak/credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts_1000401_bc50MSPM.pkl
    with open('/home/zzp/lab/bubble/credtweak/credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts'+sfx+'.pkl', 'rb') as f:
        pws_pws2score = pickle.load(f)
    for i, scores_avault in enumerate(batch_bundle[0][0][0]):
        vault_ = scores_avault['vault']
        get_hybridwang(vault_, pws_pws2score, scores_avault)

def get_hybridwang(vault, pws_pws2score, scores_avault):
    # for each pw_i in set(vault), get score of pw_j in pws_pws2score[pw_i] for all pw_j in vault\{pw_i}
    # then get the average of the scores and use it to divide scores_avault['wang_hybrid']
    if not isinstance(scores_avault['wang_hybrid'], list):
        return
    score_wanghybrid = scores_avault['wang_hybrid'][0]
    wang_denom = []
    for pwi in list(set(vault)):
        pws_remaining = [pw for pw in vault if pw != pwi]
        i_pws2score = pws_pws2score[pwi]
        for pwj in pws_remaining:
            if pwj in i_pws2score:
                wang_denom.append(i_pws2score[pwj])
    if len(wang_denom) > 0:
        scores_avault['wang_similar'] = scores_avault['wang_hybrid'][1] / np.mean(np.array(wang_denom)) * len(vault) / (len(vault)+1)
        scores_avault['wang_hybrid'] = score_wanghybrid * scores_avault['wang_similar'] # scores_avault['wang_hybrid'][1] / np.mean(np.array(wang_denom)) * len(vault) / (len(vault)+1)
    else:
        scores_avault['wang_hybrid'] = score_wanghybrid # if args.victim == 'MSPM' else 0

def decoys(seq, decoygen):
    print('already => '+seq+'%')
    return decoygen(N_EXP_VAULTS)

def additionw(value, vault, leakpw, leakmetaid):
    if not args.withleak:
        return value
    if leakpw in vault:
        if args.fixeditv:
            if leakpw in vault[leakmetaid // Nitv * Nitv: (leakmetaid // Nitv + 1) * Nitv]:
                return value
            else:
                return -np.inf
        return value
    else:
        return -np.inf

def softpriority(vault, leakpw, dte):
    ith = len(vault)  # starting from 1 for f(ith)
    prob_lst = []
    sim = 0
    for i in range(ith):
        _, prob = dte.sspm.encode_pw(vault[i], leakpw, ith)
        if len(prob) != 0 and vault[i] != leakpw:
            prob = np.log(np.array(prob)).sum() + np.log((1 - unreuse_p(ith)) / ith) # get the probability
            sim += 1
        prob_lst.append(prob)
    return 1 - sim/len(vault) # -np.array(prob_lst).sum()/20 #1 - 1 / (1 + math.exp(-np.array(prob_lst).sum()/6))

def list_shuffle(mpw, pin, vault_size, recover=False, existing_list=None):
    """
    passed unit test function 'tes_list_shuffle()'
    shuffle in direct or fixed interval way
    :param mpw:
    :param pin:
    :param vault_size:
    :param recover:
    :return:
    """
    itvsize = Nitv if args.fixeditv else vault_size
    shuffled_list = []
    if existing_list is not None:
        assert len(existing_list) == vault_size
    for ith in range(math.ceil(vault_size / itvsize)):
        shuffled_list_tmp = list(np.arange(0, itvsize)) if existing_list is None else copy.deepcopy(existing_list)[ith*itvsize:(ith+1)*itvsize]
        if args.fixeditv and args.fixeditvmode == 1 and ith==vault_size//itvsize and vault_size%itvsize != 0: # requires no padding
            shuffled_list_tmp = shuffled_list_tmp[:vault_size % itvsize]
        rng = random.Random(hash(pin + str(ith))) if args.fixeditv else random.Random(hash(pin)) # random.Random(hash(mpw + pin))
        rolls = [rng.randint(0, len(shuffled_list_tmp)-1) for _ in range(len(shuffled_list_tmp))] # vault_size
        if not recover:
            for i in range(len(shuffled_list_tmp)-1, -1, -1):
                shuffled_list_tmp[i], shuffled_list_tmp[rolls[i]] = shuffled_list_tmp[rolls[i]], shuffled_list_tmp[i]
        else:
            for i in range(len(shuffled_list_tmp)):
                shuffled_list_tmp[i], shuffled_list_tmp[rolls[i]] = shuffled_list_tmp[rolls[i]], shuffled_list_tmp[i]
        sub_list = list(np.array(shuffled_list_tmp) + ith * itvsize) if existing_list is None else shuffled_list_tmp
        shuffled_list.extend(sub_list)
    return shuffled_list

def getshuffledidx(scrambled_idx, vault, pin, gpuid):
    if args.logical:
        # (PIN_REFRESH, PADDED_TO*PIN_SAMPLE)
        # get "reshuedidx" as reshuffled mapping in the shape of (PIN_REFRESH, PADDED_TO*PIN_SAMPLE)
        if not args.intersection:
            reshuedidx = check_logical(scrambled_idx, PIN_REFRESH, len(vault), gpuid, seed_=random.Random(hash(pin)).randint(0, MAX_INT))
        else:
            reshuedidx = [[] for _ in range(1)]
            shuffle_idx = None
            for i, si in enumerate(scrambled_idx):
                if args.fixeditv:
                    rsidx, shuffle_idx = check_logical(si, PIN_REFRESH, len(si), gpuid, seed_=random.Random(hash(pin)).randint(0, MAX_INT), reshuidx_whole=shuffle_idx, depth=i)
                else:
                    rsidx = check_logical(si, PIN_REFRESH, len(si), gpuid, seed_=random.Random(hash(pin)).randint(0, MAX_INT))
                for i_, rs in enumerate(rsidx):
                    reshuedidx[i_].append(rs)
        return reshuedidx
    return None

def random_mpw(mpw_gt=None, seed_=1):
    pw = str()
    i = 0
    while len(pw) < 10 or pw == mpw_gt:
        pw = getline(SOURCE_PATH + "/data/password_dict.txt", random.Random(seed_+i).randint(0, 120000)).strip()
        i += 1
    return pw

def random_pin(seed_=1):
    # random select a pin from path '/data/'+args.pin
    size = int(1780588*0.199) if '4' in args.pin else int(0.199*2758491)
    return getline(SOURCE_PATH + "/data/pin/" + args.pin.split('.')[0]+'_test.'+args.pin.split('.')[1], random.Random(seed_).randint(1, size)).strip()

def load_testset():
# self.args.model_eval == 'sspm' or 'mspm'
    testset = {}
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
                testset[str(TEST_DATA_ID) +'_'+ str(id)] = vaults_tmp
                continue  # comment the code for training all
    print('max vault size in test set:', max_vault_size)
    return testset

def main():
    outputdir = 'results/' + args.victim + '/bc50/onefold_testset/' + ('_expanded' if args.expandtestset else '') + '/attack_result' + '_' + str(N_EXP_VAULTS) + '_testdataid' + str(TEST_DATA_ID) + '_cons' + (('2_Nitv' + str(Nitv)) if args.fixeditv and args.fixeditvmode == 1 else '1') + '_pin' + args.pinlength + '/'
    testset = load_testset()
    vault = Vault('admin', 123456, log_exp=LOGICAL)
    dte = vault.dte
    weight = Weight()
    measure = Measure()
    used_T = REFRESH_RATE
    # check the file exists or not
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    print('writing to =>', outputdir)
    print('parameter setting, T=', used_T, '; PIN space=', PIN_SAMPLE, '; Nitv=', Nitv if args.fixeditv and args.fixeditvmode == 1 else 'None', '; Version gap=', args.version_gap, '; isallleaked=', args.isallleaked)
    # test rounds setting
    for repnum in range(0, 1): #([4] + list(range(6, 20)))
        for vtested, testid in enumerate(testset):
            start_time_epoch = time()
            dte.sspm.load(testid) # trained on complementary data set for testid
            weight._init_dataset(testid) # trained on complementary data set for testid
            testset = testset[testid] # test set from testid
            batch = int(np.ceil(len(testset) / PROCESS_NUM))
            for x in range(PROCESS_NUM):
                if batch * x >= len(testset):
                    break
                test_dic = []
                vids = list(testset.keys())[x * batch: (x + 1) * batch]
                for vid_ in vids:
                    test_dic.append(testset[vid_])  # a list of password vaults
                print(f"mspm attack for process {x}")
                mspmattack(repnum, outputdir, used_T, 1, x, test_dic, decoygenspm_para, dte, weight, measure, decoymspmgen_para, assemble_mspm, vids)
            print('using time (epoch):', time() - start_time_epoch)

if __name__ == '__main__':
    main()