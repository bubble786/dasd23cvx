#from numba import jit
from time import time
from multiprocessing import Pool
from linecache import getline
# from attack.para import check_logical
from attack.para import check_logical
from opts import opts
from utils import Digit_Vault, grouprandom_fixeditv
from tqdm import tqdm
import json
import os
import random
import hashlib
import subprocess
import numpy as np
try:
    import cPickle
except ImportError:
    import pickle as cPickle

args = opts().parse()
from MSPM.mspm_config import *
if args.victim == 'Golla':
    from Golla.markov_coding import generate_batchdecoys
elif args.victim == 'PCFG':
    from PCFG.pcfg.pcfg import TrainedGrammar
    from PCFG.dte.honey_enc import DTE
    pcfg = TrainedGrammar()
elif args.victim == 'sgf':
    from attack.sgf_encoder import SGF_Encoder

from MSPM.unreused_prob import unreuse_p

def getthreshold(dte, pw_lst, problst, pw): # get the probability of independent encoding of pw
    ith = len(pw_lst) # starting from 1 for f(ith)
    if args.victim == 'sgf':
        prob = dte.encode_pw(pw)[1]
    else:
        prob = dte.spm.encode_pw(pw)[1]
    thre = 1.
    if ith > 0:
        thre *= (1. - unreuse_p[ith - 1])
    return prob * thre


def sgfattack(test_pw, T, dte, weight):
    """
    SGF (SubGrammar Family) 攻击函数
    """
    start_time = time()
    
    # 生成测试MPW候选
    mpw_candidates = []
    for i in range(50):  # 生成50个候选MPW
        candidate_mpw = f"test_mpw_{i}"
        mpw_candidates.append(candidate_mpw)
    
    # 评估每个MPW候选
    results = []
    for mpw in mpw_candidates:
        try:
            # 获取该MPW对应的SubGrammar ID
            sg_id = dte.mpw_to_subgrammar(mpw) if hasattr(dte, 'mpw_to_subgrammar') else 0
            
            # 尝试编码测试密码
            encoded_result = dte.encode_pw(test_pw)
            seed = encoded_result[0]
            prob = encoded_result[1]
            
            results.append({
                'mpw': mpw,
                'sg_id': sg_id,
                'score': prob,
                'probability': prob
            })
            
        except Exception as e:
            results.append({
                'mpw': mpw,
                'sg_id': -1,
                'score': 0.0,
                'probability': 0.0,
                'error': str(e)
            })
    
    # 按分数排序
    results.sort(key=lambda x: x['score'], reverse=True)
    
    end_time = time()
    
    return {
        'test_password': test_pw,
        'attack_time': end_time - start_time,
        'total_candidates': len(mpw_candidates),
        'top_results': results[:10],
        'success': results[0]['score'] > 0 if results else False
    }

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
    for n_, tset, in enumerate(tqdm(testset)):        
        #vs = list(testset.keys())[n_] 
        vs = tset
        vsid = unique_vids[n_]
        print('checking vault {}/{} (id: {})'.format(n_, len(testset), vsid))
        vault = list(testset[vs])
        # data_per_vault, problst = decoygen(num=(N_EXP_VAULTS-1)*expansion_rate[n_], ori=vault, ori_num=expansion_rate[n_])
        if args.fixeditv and args.fixeditvmode == 1:
            group_rand = grouprandom_fixeditv(Nitv=Nitv)
        else:
            group_rand = None
        
        data_per_vault, problst = vaultgen(num=decoy_num*expansion_rate[n_], ori=vault, ori_num=expansion_rate[n_], vsid=vsid, group_rand=group_rand)
        data_per_vault = assem_pws(*assem_pws, data_per_vault, args.pinlength, vault)
        batch_bundle = [([], data_per_vault)]
        bundle = measure.mp_spm_vault(batch_bundle, problst, weight, vault, n_)
        
        if args.withleak and (args.isallleaked or (hasattr(args, 'noleak_vaultid') and n_ not in getattr(args, 'noleak_vaultid', []))):
            addition_weight(bundle, vault, testset[vs], vsid)
        
        # adding file  exp_pastebinsuffix + victim
        cPickle.dump(bundle, open(outputdir + 'results_v' + str(vids[0]) + '_shot0.data', 'wb'))
    return []

def addition_weight(batch_bundle):
    # add weights to each vault in results (dict) by calling aother python script using subprocess
    # step1: write unique password of each vault into a txt file (each pw a row) 'credtweak/credTweakAttack/test_files/dataset_ts.txt'
    # step2: call another python script to predict score for each pw (which then will write reults into 'credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts.predictions')
    # step3: read the file and update into additional weight for each vault

    # step1
    pws = []
    for i, vault_digitvault in enumerate(batch_bundle[0][0][1]):
        for dv in vault_digitvault:
            pws.extend(dv.plain_pws)
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
        pws2score = cPickle.load(f)
    for i, scores_avault in enumerate(batch_bundle[0][0][0]):
        get_hybridwang(batch_bundle[0][0][1][i], pws2score, scores_avault)

def get_hybridwang(vault, pws_pws2score, scores_avault):
    # for each pw_i in set(vault), get score of pw_j in pws_pws2score[pw_i] for all pw_j in vault\{pw_i}
    # then get the average of the scores and use it to divide scores_avault['wang_hybrid']
    if not isinstance(scores_avault['wang_hybrid'], list):
        scores_avault['wang_hybrid'] = [scores_avault['wang_hybrid']]
    score_wanghybrid = scores_avault['wang_hybrid'][0]
    wang_denom = []
    for pwi in list(set(vault)):
        pw_scores = []
        if pwi in pws_pws2score:
            for pwj in list(set(vault)):
                if pwj != pwi and pwj in pws_pws2score[pwi]:
                    pw_scores.append(pws_pws2score[pwi][pwj])
        if len(pw_scores) > 0:
            wang_denom.append(np.mean(pw_scores))
    if len(wang_denom) > 0:
        scores_avault['wang_hybrid'][0] = score_wanghybrid / np.mean(wang_denom)
    else:
        scores_avault['wang_hybrid'][0] = score_wanghybrid


def spmattack(Q, seq, T, batch, x, testset, decoygen, dte, weight):
    """
    Q, str(x * (repeat_id + 1)), self.T, batch, x, self.testset, self.decoygen, self.dte,
    :param Q:
    :param seq:
    :param data: decoy pws list with length (N_EXP_VAULTS-1)*batch
    :param T: physical expansion
    :param dte: mspm
    :param pw_lst: pw list with length batch
    :param weight:
    :return: [[threa1], [threa2], ..., [threan]]
    """
    print('already => '+seq+'%')
    batch_results = []
    pw_lst = testset[x * batch: (x + 1) * batch]
    data, probs = decoygen(num=(N_EXP_VAULTS - 1)*batch*REPEAT_NUM, pre=args.predecoys)
    assert len(probs) == len(data) == (N_EXP_VAULTS - 1) * batch * REPEAT_NUM
    with open('ana.data1', 'wb') as f:
        cPickle.dump(probs, f)
    for threa in tqdm(range(len(pw_lst)), miniters=int(len(pw_lst)/10), unit="attack_pw"):
        pw_cur = pw_lst[threa]
        start = threa * (N_EXP_VAULTS - 1) * REPEAT_NUM
        end = (threa + 1) * (N_EXP_VAULTS - 1) * REPEAT_NUM
        data_per_pw = data[start:end]
        prob_per_pw = probs[start:end]
        thres, _ = weight.spm_vault(pw_cur, data_per_pw, prob_per_pw, dte.spm)
        batch_results.append(thres)
    with open('ana.data2', 'wb') as f:
        cPickle.dump(batch_results, f)
    #Q.put(batch_results)
    #print('eval =>', time() - s)
    return batch_results

def sspmattack(Q, seq, T, batch, x, testset, decoygen, dte, weight, vaultgen, assem_pws):
    """
    Q, str(x * (repeat_id + 1)), self.T, batch, x, self.testset, self.decoygen, self.dte,
    :param Q:
    :param seq:
    :param data: decoy pws list with length (N_EXP_VAULTS-1)*batch
    :param T: physical expansion
    :param dte: sspm
    :param testset: single pw vault
    :param weight:
    :param assem_pws: args (num, length, pws, pwrules, basepw)
    :return: [[threa1], [threa2], ..., [threan]]
    """
    print('already => '+seq+'%')
    batch_results = []
    #data, _ = decoygen(num=N_EXP_VAULTS, pre=args.predecoys)
    '''with open('ana.data1', 'wb') as f:
        pickle.dump(probs, f)'''
    for n_, tset in enumerate(testset):
        vs = tset
        print('checking vault {}/{}'.format(n_, len(testset)))
        vault = list(testset[vs])
        data_per_vault, _ = vaultgen(num=N_EXP_VAULTS-1, ori=vault, ori_num=1)
        data_per_vault = assem_pws(*assem_pws, data_per_vault, args.pinlength, vault)
        thres = weight.sspm_vault(vault, data_per_vault, dte.sspm)
        batch_results.append(thres)
    with open('ana.data2', 'wb') as f:
        cPickle.dump(batch_results, f)
    #Q.put(batch_results)
    #print('eval =>', time() - s)
    return batch_results

def decoys(seq, decoygen):
    print('already => '+seq+'%')
    return decoygen(N_EXP_VAULTS)

def additionw(value, vault, leakpw, leakmetaid):
    if not args.withleak:
        return value
    # the leaked pw can help distinguish real from fake, priority in order
    if leakpw not in vault:
        return value
    else:
        leakmetaid = [leakmetaid] if isinstance(leakmetaid, int) else leakmetaid
        if len(leakmetaid) == 1:
            return value + 0.01
        elif len(leakmetaid) == 2:
            return value + 0.01
        else:
            return value + 0.1

def softpriority(vault, leakpw, dte):
    # in prioritized search, smaller weight will be searched first
    vault_set = set(vault)
    prob_independents = [dte.spm.encode_pw(pw)[1] for pw in vault_set]
    # return np.log(pw / (1-pw)) * (-1) # inv logit, smaller for common pw
    return np.mean(prob_independents) * (-1)

def list_shuffle(mpw, pin, vault_size, recover=False, existing_list=None):
    seq_len = vault_size
    h = hashlib.sha256()
    h.update(str(mpw+str(pin)).encode())
    random.seed(int(h.hexdigest()[:16], 16) % 2147483647)
    rolls = [random.randint(0, vault_size-1) for x in range(seq_len)]
    if existing_list == None:
        permute_list = list(range(vault_size))
    else:
        permute_list = existing_list

    if not recover:
        for i in range(vault_size - 1, -1, -1):
            permute_list[i], permute_list[rolls[i]] = permute_list[rolls[i]], permute_list[i]
    else:
        for i in range(vault_size):
            permute_list[i], permute_list[rolls[i]] = permute_list[rolls[i]], permute_list[i]
    return permute_list

def getshuffledidx(scrambled_idx, vault, pin, gpuid):
    # GPU function replaced with CPU version
    mpw_gt = None
    seed_ = scrambled_idx + gpuid * 233
    new_mpw = random_mpw(mpw_gt, seed_)
    list_shuffled = list_shuffle(new_mpw, pin, len(vault))
    return new_mpw, list_shuffled

def random_mpw(mpw_gt=None, seed_=1):
    if mpw_gt != None:
        return mpw_gt
    else:
        random.seed(seed_)
        return ''.join([chr(random.randint(33, 126)) for x in range(32)])

def random_pin(seed_=1):
    random.seed(seed_)
    return random.randint(0, 9999)
