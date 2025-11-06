import copy
from MSPM.mspm_config import SOURCE_PATH
from data_processing import find_clusters, find_max_edit_distance
import pylcs
import numpy as np
import json
from tqdm import tqdm
import time

def find_clusters_new(pws_, progress):
    def rulematch(pw1, pw2):
        # 1.identical
        if pw1 == pw2:
            return True
        # 2. substring or 3. capitalization
        if pw1.lower() in pw2.lower() or pw2.lower() in pw1.lower():
            return True
        # 5. reversal
        if pw1[::-1] == pw2:
            return True
        # 7. common substring
        if pylcs.lcs_string_length(pw1.lower(), pw2.lower()) >= int(max(len(pw1), len(pw2)) / 2):
            return True
        # 4. l33t
        if leet_match(pw1, pw2) or leet_match(pw2, pw1):
            return True
        return False
    def leet_match(pw, pw2leet):
        # transform pw2leet into leet form
        # return True if pw is a substring of pw2leet or vice versa
        leet_charset = {'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!', '¡'], 'l': ['1'], 'o': ["0"], 's': ['$', '5'],
                        'b': ['8'], 't': ['7'], 'c': ['('], '9': ['6'], 'z': ['2']}
        new_wordlist = [pw2leet] # to be leeted
        record_wordlist = [] # make sure no redundant words to be leeted
        cnt = 0
        while len(new_wordlist) > 0:
            w = new_wordlist.pop()
            for i, char in enumerate(w):
                if char.lower() in list(leet_charset.keys()):
                    for leeted_char in leet_charset[char.lower()]:
                        leeted_word = w[:i] + leeted_char + w[i + 1:]
                        if leeted_word not in record_wordlist:
                            cnt += 1
                            new_wordlist.append(leeted_word)
                            record_wordlist.append(leeted_word)
                        if pw.lower() in leeted_word.lower() or leeted_word.lower() in pw.lower():
                            return True
                        if cnt > 100:
                            return False

    # input paasswords from a vault
    # output grouped passwords
    # print(progress)
    pws = pws_.copy()
    s_pws = len(set(pws))
    vs = len(pws)
    #  passwords will be groupeed if they follow at least one of the following rules: 1.identical; 2. substring; 3. capitalization; 4. l33t; 5. reversal; 6. common substring
    groups = [[pws.pop()]]
    for pw in pws:
        matched = 0
        for i, group in enumerate(groups):
            for pw_trg in list(set(group)):
                if rulematch(pw, pw_trg):
                    groups[i].append(pw)
                    matched = 1
                    break
            if matched == 1:
                break
        if matched == 0:
            groups.append([pw])
    assert sum([len(g) for g in groups]) == (len(pws) + 1)
    return groups, s_pws, vs


def obtain_vaultmetrics(vault):
    clst = find_clusters(vault, 0)[0]
    cmr_v = np.array([find_max_edit_distance(c) / np.array([len(pw) for pw in c]).mean() for c in clst])
    if (cmr_v > 0).sum() == 0:
        cmr_v = 0
    else:
        cmr_v = cmr_v[cmr_v > 0].mean()
    return cmr_v

def obtain_vaultmetrics_new(vault):
    clst = find_clusters_new(vault, 0)[0]
    cmr_v = np.array([find_max_edit_distance(c) / np.array([len(pw) for pw in c]).mean() for c in clst])
    if (cmr_v > 0).sum() == 0:
        cmr_v = 0
    else:
        cmr_v = cmr_v[cmr_v > 0].mean()
    return cmr_v

def main():
    with open(SOURCE_PATH + '/data/breachcompilation/fold2_bc200/fold_0_2.json') as f:
        bc = json.load(f)
    bc_g100 = [v for v in list(bc.values()) if len(v)>=185]

    cmr_slow = []
    ts = time.time()
    for v_ in tqdm(bc_g100):
        cmr_slow.append(obtain_vaultmetrics(v_))
    print('slow cmr takes:', time.time()-ts)

    cmr_quick = []
    ts = time.time()
    for v_ in tqdm(bc_g100):
        cmr_quick.append(obtain_vaultmetrics_new(v_))
    print('quick cmr takes:', time.time() - ts)
    print('Are results equal:', cmr_slow == cmr_quick)
    print('different:', np.mean(np.absolute(np.array(cmr_quick)-np.array(cmr_slow))/(np.array(cmr_slow)+1e-8)))


if __name__ == '__main__':
    main()