## Screen manage

* screen -S atk1 -L -Logfile /home/zzp/lab/bubble/bubble-v2/Bubble-fixed2/lab_log/screen1.log

## 改动

* TrainedGrammar.pad_y1_PCFG() # 改进:填充Y1缺失规则
  * missing_chars = ['"', '|', '}']

## 待办

* ```
  # T=1000,n=6,6000 copy A1
  # typeI 6000 A1,typeII(10*mpws) 6000 A1
  # sg 10% 至少还原出1个real pw
  # 10^6 mpw,10^5 result A1（找原文出处，可能是25'security）
  # bubble T个候选,阈值100
  # new 无限个候选,阈值100 离线猜11m次,在线验证n次,m取多少
  根据实际应用中
  ```
* vault_seed和random_seed合并,改decode_decoyvaults方法输出decoyvaults和probs
* pcfgdte实例化为sgf
