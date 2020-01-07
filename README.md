# sensor setup

## resources to care about
### disk
- fielbeat - read
- google steno
- suricata
- kafka
- elastic
- FSF - zeek

### CPU
- zeek - 100 cpu
- suricata
- FSF
- elastic

### memory
- zeek - 6g/core
- logstash
- elastic

## misc info
### edge router
- ip: 192.168.2.1

### pfsense
 - ip: 10.0.30.1/172.16.30.1

### sensor
 - ip: 172.16.30.100


## setup os
click automatically configure pationing radio button > done
reclaim space
  - delete all
  - reclaim space
#### configure partions
  - click i will configure partions (all drives selected)
  - click done
  create volume group  
  data - 500g  
  os - 32g  
  - delete swap
  - change / to 16 g
  - home 10g - os
  - var 10g - os
  - var/log 2g - os
  - tmp 2 g - os
  - data/suricata 1g - data
  - data/elasticsearch 1g - data
  - data/steno 1g - data
  - data/kafka 1g - data
  - data/fsf 1g - data
