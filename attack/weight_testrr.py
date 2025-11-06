import copy
import math
from tqdm import tqdm
from multiprocessing import Pool
import numpy as np
import pylcs
import os
import json
from linecache import getline
import random
#from numba import jit
from data.data_processing import find_clusters, find_max_edit_distance
import pickle as cPickle
from opts import opts
from collections import defaultdict
args = opts().parse()
from MSPM.mspm_config import *


def obtain_vaultmetrics(i, vault):
    # for now, return rr and cmr of a vault
    rr_v = len(set(vault)) / len(vault) # 1/rr for range 0 to 1
    clst = find_clusters(vault, 0)[0]
    cmr_v = np.array([find_max_edit_distance(c) / np.array([len(pw) for pw in c]).mean() for c in clst])
    if (cmr_v > 0).sum() == 0:
        cmr_v = 0
    else:
        cmr_v = cmr_v[cmr_v > 0].mean()
    return i, np.array([rr_v, cmr_v])

def obtain_vaultmetrics_multiprocess(vaultlist):
    # return dict: {i: metrics}, i is the index of vault in vaultlist
    workers = []
    pool = Pool(6)
    for i, vault in enumerate(vaultlist):
        workers.append(pool.apply_async(obtain_vaultmetrics, (i, vault)))
    pool.close()
    pool.join()
    results = {}
    for w in workers:
        i, metrics = w.get()
        #assert np.absolute(obtain_vaultmetrics(0, vaultlist[i])[1] - metrics).sum() == 0
        results[i] = metrics
    return results

def obtain_metricdifference(metric_gt, vault, metric_v=None):
    '''metrics_selected, n_select = [], 100 if 'bc' in args.exp_pastebinsuffix else 32 # 32 for pb; 100 for bc
    i = 0
    while len(metrics_selected) < n_select:
        if i == 0:
            metrics_selected.extend(self.learned_vaultmetric[len(vault)])
        else:
            metrics_selected.extend(self.learned_vaultmetric[len(vault)+i])
            metrics_selected.extend(self.learned_vaultmetric[len(vault)-i])
        i += 1
    metrics_selected = metrics_selected[:n_select]
    learned_avg = np.array(metrics_selected).mean(axis=0)'''

    metric_v = obtain_vaultmetrics(0,vault)[1] if metric_v is None else metric_v
    return -1 * np.sum(np.absolute(metric_v-metric_gt))

class Weight:
    """
    most are the derivations from eq  p_real(V_i)/p_decoy(V_i)
    """
    def __init__(self):
        self.rockyou = {} # k-v => word-count
        self.n = None # total number of passwords in self.rockyou
        self.learned_vaultmetric = None # acquire rr and cmr from the train set
        self.f = Feature()
        # self.features are lists of M and I (i.e., each list with two functions)
        # levenshtein has divisionbyzero (results look fine)
        self.features = [[[self.f.lcsstr, self.f.lcs], [self.f.lcs, self.f.lcsstr]] if args.victim == 'MSPM' else [[self.f.gm, self.f.lcsstr], [self.f.lcsstr, self.f.gm]],
                         [[self.f.lcsstr, self.f.levenshtein], [self.f.levenshtein, self.f.lcsstr]],
                         [[self.f.lcsstr, self.f.manhattan], [self.f.manhattan, self.f.lcsstr]],
                         [[self.f.lcsstr, self.f.overlap], [self.f.overlap, self.f.lcsstr]]]
        self._init_rky()
    def _init_dataset(self, i):
        """
            step1:
                load dataset for statistics
            step2:
                pre-compute proportion of every feature within pastebin
        :return:
        """
        # step1
        self.pastebin = {}
        flst = os.listdir(PASTB_PATH+args.exp_pastebinsuffix)
        for fname in flst:
            train_name = i[:2] + '2'
            if train_name in fname:
                with open(os.path.join(PASTB_PATH+args.exp_pastebinsuffix, fname)) as f:
                    self.pastebin.update(json.load(f))
        #self.pastebin = {k:self.pastebin[k] for k in list(self.pastebin.keys())[:100]}# debug only

        print('loaded'+args.exp_pastebinsuffix, len(self.pastebin), 'vaults, except', i, 'th vault')

        # step2
        self.p_real = {} # k - v (feature - true proportion)
        for i in range(len(self.features)):
            for fpair in self.features[i]:
                self.p_real[self.dicname(fpair)] = self.pfeature4vault(self.pastebin, fpair)

        # learn metrics from training set
        self.vaultsmetric = defaultdict(list) # key as vaultsize, v as list of [rr,cmr]
        vaultlist = list(self.pastebin.values())
        vaultidx2metrics = obtain_vaultmetrics_multiprocess(vaultlist)
        for i in range(len(vaultlist)):
            self.vaultsmetric[len(vaultlist[i])].append(list(vaultidx2metrics[i]))

        n_select = 100 if 'bc' in args.exp_pastebinsuffix else 32  # 32 for pb; 100 for bc
        self.learned_vaultmetric = defaultdict(list)
        for vaultsize in range(2,201):
            i = 0
            metrics_selected = []
            while len(metrics_selected) < n_select:
                if i == 0:
                    metrics_selected.extend(self.vaultsmetric[vaultsize])
                else:
                    metrics_selected.extend(self.vaultsmetric[vaultsize + i])
                    metrics_selected.extend(self.vaultsmetric[vaultsize - i])
                i += 1
            metrics_selected = metrics_selected[:n_select]
            learned_avg = np.array(metrics_selected).mean(axis=0)
            self.learned_vaultmetric[vaultsize] = learned_avg

    def _init_rky(self):
        pky = ROCKY_PATH + args.spmdata + '-withcount'
        print('loading test file (weight.py):', pky)
        with open(pky, 'rb') as f:
            lines = cPickle.load(f)
            for line in lines:
                contents = line.strip().split()  # in the format of 'count password'
                if len(contents) != 2:
                    continue
                # print(contents.strip().split())
                if lencheck(contents[1]) or not_in_alphabet(contents[1]):
                    continue
                self.rockyou[contents[1]] = int(contents[0])
        print('loaded', len(self.rockyou), 'pws')
        self.n = np.array(list(self.rockyou.values())).sum()

    def dicname(self, fpair):
        # set name for the proportion dictionary key
        assert len(fpair) == 2
        return fpair[0].__name__ + '/' + fpair[1].__name__

    def singlepass(self, vault, spm, decoy_probs=None, a_s=1, f_d=0): # f_d:0
        """
            calculate
                p_decoy(pw) through single password model
                p_real(pw) with statistic upon rockyou
        :param vault: list of passwords
        :param spm: dte single password model
        :param a_s:
        :param f_d:
        :return: priority weight(vault)  a scalar
        """
        sp_probs = []
        for i, pw in enumerate(vault):
            if decoy_probs == None:
                p_decoy = np.log(np.array(spm.encode_pw(pw)[1])).sum() / 4.
            else:
                p_decoy = decoy_probs[i][0] / 4.
                #print(decoy_probs, p_decoy)
            #p_decoy = p_decoy.prod() #np.clip(np.array(p_decoy).prod(), a_min=1e-10, a_max=np.inf)
            if pw in self.rockyou:
                fq = self.rockyou[pw]
            else:
                fq = 0
            if fq <= f_d and p_decoy / self.freq(fq, a_s) > 0.6: #original 0.6 the use of log(.) in representing probability demands to put decoy in the numerator and the real in the denominator. self.freq(fq, a_s) / p_decoy
                sp_probs.append(0.6) # original 0.6
            else:
                sp_probs.append(p_decoy / self.freq(fq, a_s)) # self.freq(fq, a_s) / p_decoy
        return np.array(sp_probs).mean()

    def kl(self, vault_, spm, decoy_probs_=None):
        vault = [pw for pw in vault_ if len(pw) > 5 and len(pw) < MAX_PW_LENGTH]
        if len(vault) == 0:
            return -10 #-1 * np.inf
        decoy_probs = [decoy_probs_[i] for i in range(len(vault_)) if len(vault_[i]) > 5 and len(vault_[i]) < MAX_PW_LENGTH] if decoy_probs_ is not None else None
        kl_probs = []
        vaultset = list(set(vault))
        for i, pw in enumerate(vault):
            if pw in vaultset:
                vaultset.remove(pw)
            else:
                continue
            if decoy_probs == None:
                p_decoy = np.log(np.array(spm.encode_pw(pw)[1])).sum() / 4.
            else:
                p_decoy = decoy_probs[i][0] / 4.

            fj = self.freq(vault.count(pw), smoo=1)
            frac = vault.count(pw) / len(vault)
            if p_decoy == 0:
                continue
            kl_probs.append(frac * np.log(p_decoy / fj))

        if np.array(kl_probs).sum() == -1 * np.inf:
            print('kl_probs:', kl_probs)
        return np.array(kl_probs).sum()

    def wang_singlepass(self, vault, dte, decoy_probs=None):
        """
            calculate
                p_decoy(pw) through single password model
                p_real(pw) with statistic upon rockyou
        :param vault: list of passwords
        :param spm: dte single password model
        :param a_s:
        :param f_d:
        :return: priority weight(vault)  a scalar
        """
        sp_probs = []
        for i, pw in enumerate(vault):
            if decoy_probs == None:
                p_decoy = np.log(np.array(dte.spm.encode_pw(pw)[1])).sum() / 4.
            else:
                p_decoy = decoy_probs[i][0] / 4.
                #print(decoy_probs, p_decoy)
            #p_decoy = p_decoy.prod() #np.clip(np.array(p_decoy).prod(), a_min=1e-10, a_max=np.inf)
            if pw in self.rockyou:
                fq = self.rockyou[pw]
            else:
                fq = 0
            sp_probs.append(p_decoy / (2*self.freq(fq, 1))) # self.freq(fq, a_s) / p_decoy
        sp_prob = np.array(sp_probs).mean() # if args.victim == 'MSPM' else 1

        vault_leng5 = [pw for pw in vault if len(pw) > 5 and len(pw) < MAX_PW_LENGTH]
        if len(vault_leng5) == 0:
            return sp_prob
        decoy_probs_leng5 = [decoy_probs[i][1] for i in range(len(vault)) if len(vault[i]) > 5 and len(vault[i]) < MAX_PW_LENGTH] if decoy_probs != None else None
        if decoy_probs_leng5 is not None:
            vault_decoyprob = decoy_probs_leng5
        elif args.victim == 'MSPM':
            vault_decoyprob = [dte.encode_pw_frompriorpws(vault_leng5[:i], vault_leng5[i])[3] for i in range(len(vault_leng5))]
        elif args.victim == 'Golla':
            vault_decoyprob = dte.encode_pw(vault_leng5)[2]
        vault_decoyprob = np.array(vault_decoyprob).mean()
        return [sp_prob, vault_decoyprob] #sp_prob #

    def freq(self, fq, smoo):
        return math.log((fq + smoo) / (self.n + smoo*len(self.rockyou)))
        #return (fq + smoo) / (self.n + smoo*len(self.rockyou))

    def passsimi(self, vi, dte, decoy_sets, feat_tmp, p_real): # not that certain!
        """
            calculate
                p_decoy(F=x)
                    step1: encoding vi and encrypt it with one mpw
                    step2: decrypt-then-decode vi with different mpws,
                        creating e.g., 100 decoy vaults, which gonna used for probability calculation
                also
                brewed with p_real(F=x) with statistic upon pastebin. NOTE: which has been pre-computed!
        :param vi: a password vault (a list)
        :param dte: vola!
        :return:
        """
        # step1
        psms = 1.
        records = []
        for fpair in feat_tmp:
            vi_true = self.hasfeature(vi, fpair)
            pd = vi_true - self.pfeature4vault(decoy_sets, fpair)
            pr = vi_true - p_real[self.dicname(fpair)]
            psms *= ((pr / pd) if pd != 0 else np.abs(pr)*1e4)
            records.append([pr, pd])
        assert psms >= 0, print(psms, records)
        return psms

    def hasfeature(self, vault, feature):
        """
            calculate proportion of vaults with corresponding feature (actually considering password pair)
        :param vaults: a list containing pws
        :param feature: certain feature: a function list (two feature function)
        :return:
        """
        v_unique = list(set(vault))
        for i in range(len(v_unique) - 1):
            for j in range(i + 1, len(v_unique)):
                if feature[0](v_unique[i], v_unique[j]) * (1 - feature[1](v_unique[i], v_unique[j])) == 1:
                    return 0
        return 1

    def pfeature4vault(self, vaults, feature):
        """
            calculate proportion of vaults with corresponding feature (actually considering password pair)
        :param vaults: a dict containing lists as items, for statistic
        :param feature: certain feature: a function list (two feature function)
        :return: proportion of vaults hold the feature
        """
        yep = 0
        flag = 0
        for vault in vaults:
            vault = list(set(vaults[vault]))
            for i in range(len(vault) - 1):
                for j in range(i + 1, len(vault)):
                    if feature[0](vault[i], vault[j]) * (1 - feature[1](vault[i], vault[j])) == 1:
                        yep += 1
                        flag = 1
                        break
                if flag == 1:
                    flag = 0
                    break
        return yep / len(vaults)

class Feature:
    def __init__(self):
        pass

    def lcsstr(self, pw1, pw2):
        return int(pylcs.lcs_string_length(pw1, pw2) >= max(len(pw1), len(pw2))/2)

    def gm(self, pw1, pw2):
        minlength = min(len(pw1), len(pw2))
        if pw2[:minlength-1] != pw1[:minlength-1]:
            return False
        if pylcs.edit_distance(pw1, pw2) > 4:
            return False
        return True

    def levenshtein(self, pw1, pw2):
        return int(pylcs.edit_distance(pw1, pw2) <= max(len(pw1), len(pw2)) / 2)

    def lcs(self, pw1, pw2):
        return int(pylcs.lcs_sequence_length(pw1, pw2) >= max(len(pw1), len(pw2)) / 1.5)

    def manhattan(self, pw1, pw2):
        vec1, vec2 = self.pw2vec(pw1, pw2)
        return int(sum([np.abs(a - b) for a, b in zip(vec1, vec2)]) <= len(pw1+pw2)/2.5)

    def overlap(self, pw1, pw2): # change a little, not certain!
        return int(len(set(pw1) - (set(pw1) - set(pw2))) >= len(set(pw1+pw2))/2)

    def pw2vec(self, pw1, pw2):
        x = pw1
        y = pw2
        set1 = set()
        for a in range(0, len(x)):
            set1.add(x[a])
        for a in range(0, len(y)):
            set1.add(y[a])
        vec1 = [None] * len(set1)
        vec2 = [None] * len(set1)
        for counter, each_char in enumerate(set1):
            vec1[counter] = x.count(each_char)
            vec2[counter] = y.count(each_char)
        return vec1, vec2

if __name__ == '__main__':
    weight = Weight()
    #import pickle
    #with open('/home/beeno/Dropbox/research_project/pycharm/credtweak/credTweakAttack/data/pass2path_1667500_dataset_ts_1000301_pbPCFG.pkl', 'rb') as f:
        #pws_pws2score = pickle.load(f)
    #pws_pws2score = pws_pws2score