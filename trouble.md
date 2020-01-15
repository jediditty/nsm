no communicative services? check firewall port openings

no route - firewalld
conn refused - selinux


### no data in logstash or elasticsearch
zeekctl status
ll /data/zeek/current/
* zeek works
/opt/fsf/fsf-client/fsf_client.py --full ~/Bro-cheatsheet.pdf
/usr/share/kafka/bin/kafka-topics.sh --list --bootstrap-server 172.16.30.102:9092
/usr/share/kafka/bin/kafka-topics.sh --describe --bootstrap-server 172.16.30.102:9092 --topic zeek-raw
/usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.30.102:9092 --topic zeek-raw --from-beginning
* kafka works
```curl 172.16.30.102:9200/_cat/indices```
* elasticsearch works
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/100-input-zeek.conf -t
* will check logstash conf files
