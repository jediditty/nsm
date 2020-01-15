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
  - data/suricata 50g - data
  - data/elasticsearch 50g - data
  - data/steno 50g - data
  - data/kafka 50g - data
  - data/fsf 50g - data
#### enable interfaces
networking > enable an interface

### switch port
9
#### setup dhcp
ip dhcp exclude-address 10.0.30.0 10.0.30.1
ip dhcp pool SG30
network 10.0.30.0 255.255.255.252
default-router 10.0.30.1
dns-server 192.168.2.1
exit
#### setup vlans
vlan 30
name SG30
state active
no shutdown
exit
#### add interfaces
interface GigabitEthernet 1/0/9
switchport
switchport access vlan 30
no shutdown
exit
interface vlan sg30ip address 10.0.30.1 255.255.255.252
no shutdown
exit
#### enable static routes
ip routing
ip route 172.16.30.0 255.255.255.0 10.0.30.2
#### assign interfaces
lan4=em3
lan3=em2
lan2=em1
lan1=em0
com=local

1. 1 - assign interfaces
2. skip vlan setup
3. em0 wan interfaces
4. em1 lan interfaces
5. nothing to finish
6. y - mto finish

#### set interface ips

1. 2 - set interface ips
2. wan interfaces
3. y dhcp
4. n dhcp6
5. none for ipv6 setup
6. y - http webconfig protocol

7. 2 - lan int
8. 172.16.301/24
9. none
10. none disable ipv6
11. y - enable dhcp
12. 172.16.30100 - range start
13. 127.16.30.254 - range end
14. y - http webconfig protocol

#### sensor ip
ip a (to get interface name)
ip link set xxx up

#### firewalld
sudo firewall-cmd --zone=public --add-port=5601/tcp --permanent
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
sudo firewall-cmd --zone=public --remove-port=5601/tcp --permanent

#### yum/ setup local repo
yum clean all
yum makechache fast
yum provides
yum search

copy local.repo to laptop home folder
scp over to sensor
move to repo folder on the sensor
#### replace repo in file with ip address
:%s/repo/192.168.2.224/g

sudo yum clean all
sudo yum makechache fast

instll yum-utils for some tools that we will need
yum install yum-utils
create new directory to host repo on laptop
sudo mkdir /srv/repos
sync the repo to the laptop, need to do it for all the local repos
1. reposync -l --repoid=local-base --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-rocknsm-2.5 --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-elasticsearch-7.x --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-epel --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-extras --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-updates --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-zerotier --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-virtualbox --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=local-WANdisco-git --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=localstuff --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata && \
reposync -l --repoid=fsf --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata
#### createrpo
yum install createrepo
createrepo /repo/<repo_name>
createrepo /repo/<repo_name>
createrepo -g comps.xml local-base/
createrepo -g comps.xml local-epel/

### setup nginx
yum install nginx
vi /etc/nginx/conf.d/repo.conf
```.conf
server {
  listen 8008;

  location / {
    root /srv/repos;
    autoindex on;
    index index.html index.htm;
  }

  error_page 500 502 503 504 /50x.html;
  location = /50x.html {
    root /usr/share/nginx/html;
  }
}

```
#### reverse proxy
```.configure
server {
  listen 80;
  server_name sg301 sg301.local.lan

  proxy_max_temp_file_size 0;

  location / {
    proxy_set_header X-Real_IP $remote_addr;
    proxy_set_header Host $http_host;
    proxy_pass http://127.0.0.1:8008;
  }
}
```

sudo systemctl enable nginx

#### allow for remote access
sudo firewall-cmd --add-port=8008/tcp --permanent
sudo firewall-cmd --reload
sudo chcon -R -u system_u -t httpd_sys_content_t repos/
curl <ip>:8008

### setuo dns
pfsense > services > dns resolver > host over ride
or
/etc/hosts

### more space
mkdir /home/srv
mv /srv/* /home/srv/.
mount -o bind /home/srv/ /srv/

## INstalling Rocknsm
### stenographer
sudo yum install stenographer
#### config files
/etc/stenographer/config
```.config
{
  "Threads": [
    { "PacketsDirectory": "/data/steno/thread0/packets/"
    , "IndexDirectory": "/data/steno/thread0/index/"
    , "MaxDirectoryFiles": 30000
    , "DiskFreePercentage": 10
    }
  ]
  , "StenotypePath": "/usr/bin/stenotype"
  , "Interface": "enp2s0"
  , "Port": 1234
  , "Host": "127.0.0.1"
  , "Flags": []
  , "CertPath": "/etc/stenographer/certs"
}
```
(change "PacketsDirectory": to the: to the data/steno/thread0....... we make when installing centos)

(change "interface": enp2s0 ( inet ........)

stenokeys.sh stenographer stenographer

ll /data/

chown -R stenographer: /data/steno/

systemctl start stenographer

systemctl status stenographer (make sure stenographer is running)

###     Troubleshooting step

journalctl -xew stenographer (look for exit)

ll /etc/stenographer/cert  (look for certificate gernerated, will be empty if no cert)



Stop steno

systemctl stop stenographer

##     ethtool


Manually run ethtool

ethtool -K enp2s0 tso off gro  off lro off  gso off rx off tx  off sg off rxvlan off txvlan off

ethtool -N enp2s0 rx-flow-hash udp4 sdfn

ethtool -N enp2s0 rx-flow-hash udp6 sdfn

ethtool -C enp2s0 adaptive-rx off

ethtool -C  enp2s0 rx-usecs 1000

ethtool -G enp2s0 rx 4096




script version

#!/bin/bash


for var in $@
do

echo "turning off affloading on $var"

ethtool -K  $var tso off gro  off lro off  gso off rx off tx  off sg off rxvlan off txvlan off

ethtool -N  $var rx-flow-hash udp4 sdfn

ethtool -N  $var rx-flow-hash udp6 sdfn

ethtool -C $var adaptive-rx off

ethtool -C $var rx-usecs 1000

ethtool -G $var rx 4096

done

exit 0


##     Install Suricata


yum install suricata

yum install tcpdump

tcpdump -i enp2s0

vi /etc/suricata/suricata.yaml

:set nu


line 76   enabled: no

line 404 enabled: no


/enabled:yes (for search in vi)

default-log-dir  ( change to location)

outputs

rule-files


cd /etc/suricata


cd /var/lib/suricata/rules

suricata-update

usr/share/local/suricata/rules

/var/lib/suricata/rules

vi /etc/sysconfig/suricata

```
# The following parameters are the most commonly needed to configure
# suricata. A full list can be seen by running /sbin/suricata --help
# -i <network interface device>
# --user <acct name>
# --group <group name>

# Add options to be passed to the daemon
OPTIONS="--af-packet=enp2s0 --user suricata "
```


sudo cat /proc/cpuinfo | egrep -e 'processor|physical id|core id' | xargs -l3



cd /usr/share/suricata/rules/  ( copy link from share site )

curl -L -O https://192.168.2.11:8009/suricata-5.0/emerging.rules.tar.gz

ls





cp /usr/share/suricata/classification.config  /etc/suricata/.


cp /usr/share/suricata/reference.config  /etc/suricata/.

### zeek
yum install zeek zeek-plugin-af_packet zeek-plugin-kafka
mkdir /data/zeek
#### config files
* networks.cfg
  * used to tell zeek the ip space using cidr notation
```
172.16.39.0/24
```
* zeekctl.cfg
  * log-dir directory location
  * ```lb_custom.InterfacePrefix=af_packet::``` not there by default and need to tell zeek to use af packet
```
LogDir = /data/zeek
```

``` /etc/zeek/node.cfg
# Example ZeekControl node configuration.
#
# This example has a standalone node ready to go except for possibly changing
# the sniffing interface.

# This is a complete standalone configuration.  Most likely you will
# only need to change the interface.
#[zeek]
#type=standalone
#host=localhost
#interface=eth0

## Below is an example clustered configuration. If you use this,
## remove the [zeek] node above.

[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost
pin_cpus=3

[proxy-1]
type=proxy
host=localhost

[interface-enp2s0]
type=worker
host=localhost
interface=enp2s0
lb_method=custom
lb_procs=2
pin_cpu=1,2
env_vars=fanout_id=99

#[worker-]
#type=worker
#host=localhost
#interface=eth0
```
* local zeek files
  * cd /usr/share/zeek/site/
  * vi local.zeek
  * uncomment these lines
    * heartbleed
    * vlan-logging
    * mac-logging
  * add the following lines
    * @load scripts/json
    * @load scripts/af_packet
    * @load scripts/kafka

#### create above scripts
* mkdir scripts/
* afpacket.zeek
```
redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
```
* kafka.zeek
```
redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;
redef Kafka::kafka_conf = table(["metadata.broker.list"] = "172.16.30.102:9092");
```
* json.zeek
```
redef LogAscii::use_json=T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
```
* ```zeekctl check #ensures that the scripts are good to go```

#### zeek trouable Troubleshooting
* zeekctl stop
* zeekctl cleanup all
* zeekctl deploy

### FSF
* yum install fsf
* configuration updates
* vi /opt/fsf/fsf-server/conf/config.py
```.py
#!/usr/bin/env python
#
# Basic configuration attributes for scanner. Used as default
# unless the user overrides them.
#

import socket

SCANNER_CONFIG = { 'LOG_PATH' : '/data/fsf/logs',
                   'YARA_PATH' : '/var/lib/yara-rules/rules.yara',
                   'PID_PATH' : '/run/fsf/scanner.pid',
                   'EXPORT_PATH' : '/data/fsf/files',
                   'TIMEOUT' : 60,
                   'MAX_DEPTH' : 10,
                   'ACTIVE_LOGGING_MODULES' : ['scan_log', 'rockout'],
                   }

SERVER_CONFIG = { 'IP_ADDRESS' : "172.16.30.102",
                  'PORT' : 5800 }
```

* vi /opt/fsf/fsf-client/conf/config.py
```.py
#!/usr/bin/env python
#
# Basic configuration attributes for scanner client.
#

# 'IP Address' is a list. It can contain one element, or more.
# If you put multiple FSF servers in, the one your client chooses will
# be done at random. A rudimentary way to distribute tasks.
SERVER_CONFIG = { 'IP_ADDRESS' : ['172.16.30.102',],
                  'PORT' : 5800 }

# Full path to debug file if run with --suppress-report
CLIENT_CONFIG = { 'LOG_FILE' : '/tmp/client_dbg.log' }
```
* mkdir /data/fsf/{logs,file}
* chown -R fsf: /data/fsf/
* firewall-cmd --add-port=5800/tcp --permanent
* firewall-cmd --reload # no work no more
* /opt/fsf/fsf-client/fsf_client.py --full ~/Bro-cheatsheet.pdf

### kafka
* yum install zookeeper kafka
* vi /etc/zookeeper/zoo.cfg
```.cfg
# The number of milliseconds of each tick
tickTime=2000
# The number of ticks that the initial
# synchronization phase can take
initLimit=10
# The number of ticks that can pass between
# sending a request and getting an acknowledgement
syncLimit=5
# the directory where the snapshot is stored.
# do not use /tmp for storage, /tmp here is just
# example sakes.
dataDir=/var/lib/zookeeper
# the port at which the clients will connect
clientPort=2181
# the maximum number of client connections.
# increase this if you need to handle more clients
#maxClientCnxns=60
#
# Be sure to read the maintenance section of the
# administrator guide before turning on autopurge.
#
# http://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_maintenance
#
# The number of snapshots to retain in dataDir
#autopurge.snapRetainCount=3
# Purge task interval in hours
# Set to "0" to disable auto purge feature
#autopurge.purgeInterval=1
```
* sudo systemctl start zookeeper

#### ZOOKEEPER MUST BE RUNNING BEFORE KAFKA

* vi /etc/kafka/server.properties
  * line 30: add sensor ip Address
  * line 36: uncomment add sensor address
  * line 60: log.dirs=/data/kafka
  * line 103: log.retention.hours=168 # keep default, hours before it deletes
  * line 107: log.retention.bytes=##### # keep default, size kept before deletes
  * line 123: zookeeper.connect=localhost:2181 # keep default, where to get the seed list of zookeepers

* chown -R kafka: /data/kafka

* github rocknsm/rock-scripts/plugin/kafka.bro line 20 and down
* vi /usr/share/zeek/site/scripts/kafka.zeek append below to file
```
redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;
redef Kafka::kafka_conf = table(
     ["metadata.broker.list"] = "172.16.30.102:9092"
);
# Enable bro logging to kafka for all logs
event bro_init() &priority=-5
{
    for (stream_id in Log::active_streams)
    {
        if (|Kafka::logs_to_send| == 0 || stream_id in Kafka::logs_to_send)
        {
            local filter: Log::Filter = [
                $name = fmt("kafka-%s", stream_id),
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["stream_id"] = fmt("%s", stream_id))
            ];

            Log::add_filter(stream_id, filter);
        }
    }
}

```

### Filebeat
* yum install filebeat
* cd /etc/filebeat/
* vi filebeat.yaml
  * line 17: enabled: true
  * add paths to files to be read
    * saved a copy in filebeats/filebeat.yml
```.yml
  paths:
    - /data/suricata/eve.json
    - /data/fsf/logs/rockout.log
  fields:
    student: student-1
    anything: data
    sensor: student-sensor
```

### Elasticsearch
* yum install elasticsearch
* vi etc/elasticsearch/elasticsearch.yml
```.yml
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
#
cluster.name: student30
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
#
node.name: student30-node-1
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /data/elasticsearch
#
# Path to log files:
#
path.logs: /var/log/elasticsearch
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):
#
network.host: _local:ipv4_
#
# Set a custom port for HTTP:
#
http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
#discovery.seed_hosts: ["host1", "host2"]
#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#
# For more information, consult the discovery and cluster formation module documentation.
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
#
#gateway.recover_after_nodes: 3
#
# For more information, consult the gateway module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Require explicit names when deleting indices:
#
#action.destructive_requires_name: true

```

* vi /etc/elasticsearch/jvm.options
* min and max get the same number (Xms8g)
```
## JVM configuration

################################################################
## IMPORTANT: JVM heap size
################################################################
##
## You should always set the min and max JVM heap
## size to the same value. For example, to set
## the heap to 4 GB, set:
##
## -Xms4g
## -Xmx4g
##
## See https://www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html
## for more information
##
################################################################

# Xms represents the initial size of total heap space
# Xmx represents the maximum size of total heap space

-Xms8g
-Xmx8g

################################################################
## Expert settings
################################################################
##
## All settings below this section are considered
## expert settings. Don't tamper with them unless
## you understand what you are doing
##
################################################################

## GC configuration
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly

## G1GC Configuration
# NOTE: G1GC is only supported on JDK version 10 or later.
# To use G1GC uncomment the lines below.
# 10-:-XX:-UseConcMarkSweepGC
# 10-:-XX:-UseCMSInitiatingOccupancyOnly
# 10-:-XX:+UseG1GC
# 10-:-XX:G1ReservePercent=25
# 10-:-XX:InitiatingHeapOccupancyPercent=30

## JVM temporary directory
-Djava.io.tmpdir=${ES_TMPDIR}

## heap dumps

# generate a heap dump when an allocation from the Java heap fails
# heap dumps are created in the working directory of the JVM
-XX:+HeapDumpOnOutOfMemoryError

# specify an alternative path for heap dumps; ensure the directory exists and
# has sufficient space
-XX:HeapDumpPath=/var/lib/elasticsearch

# specify an alternative path for JVM fatal error logs
-XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log

## JDK 8 GC logging
8:-XX:+PrintGCDetails
8:-XX:+PrintGCDateStamps
8:-XX:+PrintTenuringDistribution
8:-XX:+PrintGCApplicationStoppedTime
8:-Xloggc:/var/log/elasticsearch/gc.log
8:-XX:+UseGCLogFileRotation
8:-XX:NumberOfGCLogFiles=32
8:-XX:GCLogFileSize=64m

# JDK 9+ GC logging
9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m
```

* tell systemd that elastic can lock memory
* mkdir /etc/systemd/system/elasticsearch.service.d
* vi /etc/systemd/system.elasticsearch.service.d/overrie.conf
```.conf
[Service]
LimitMEMLOCK=infinity
```

* chown -R elasticsearch: /etc/elasticsearch/
* chown -R elasticsearch: /data/elasticsearch/
* firewall-cmd --zone=public --add-port=9200/tcp --permanent
* firewall-cmd --zone=public --add-port=9300/tcp --permanent

### kibana
* yum install kibana
* vi /etc/kibana/kibana.yml
* elasticsearch.hosts: ["http://localhost:9200"]
```
# Kibana is served by a back end server. This setting specifies the port to use.
#server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.
server.host: "172.16.30.102"

# Enables you to specify a path to mount Kibana at if you are running behind a proxy.
# Use the `server.rewriteBasePath` setting to tell Kibana if it should remove the basePath
# from requests it receives, and to prevent a deprecation warning at startup.
# This setting cannot end in a slash.
#server.basePath: ""

# Specifies whether Kibana should rewrite requests that are prefixed with
# `server.basePath` or require that they are rewritten by your reverse proxy.
# This setting was effectively always `false` before Kibana 6.3 and will
# default to `true` starting in Kibana 7.0.
#server.rewriteBasePath: false

# The maximum payload size in bytes for incoming server requests.
#server.maxPayloadBytes: 1048576

# The Kibana server's name.  This is used for display purposes.
#server.name: "your-hostname"

# The URLs of the Elasticsearch instances to use for all your queries.
elasticsearch.hosts: ["http://localhost:9200"]

# When this setting's value is true Kibana uses the hostname specified in the server.host
# setting. When the value of this setting is false, Kibana uses the hostname of the host
# that connects to this Kibana instance.
#elasticsearch.preserveHost: true

# Kibana uses an index in Elasticsearch to store saved searches, visualizations and
# dashboards. Kibana creates a new index if the index doesn't already exist.
#kibana.index: ".kibana"

# The default application to load.
#kibana.defaultAppId: "home"

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "kibana"
#elasticsearch.password: "pass"

# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.enabled: false
#server.ssl.certificate: /path/to/your/server.crt
#server.ssl.key: /path/to/your/server.key

# Optional settings that provide the paths to the PEM-format SSL certificate and key files.
# These files validate that your Elasticsearch backend uses the same key files.
#elasticsearch.ssl.certificate: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key

# Optional setting that enables you to specify a path to the PEM file for the certificate
# authority for your Elasticsearch instance.
#elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]

# To disregard the validity of SSL certificates, change this setting's value to 'none'.
#elasticsearch.ssl.verificationMode: full

# Time in milliseconds to wait for Elasticsearch to respond to pings. Defaults to the value of
# the elasticsearch.requestTimeout setting.
#elasticsearch.pingTimeout: 1500

# Time in milliseconds to wait for responses from the back end or Elasticsearch. This value
# must be a positive integer.
#elasticsearch.requestTimeout: 30000

# List of Kibana client-side headers to send to Elasticsearch. To send *no* client-side
# headers, set this value to [] (an empty list).
#elasticsearch.requestHeadersWhitelist: [ authorization ]

# Header names and values that are sent to Elasticsearch. Any custom headers cannot be overwritten
# by client-side headers, regardless of the elasticsearch.requestHeadersWhitelist configuration.
#elasticsearch.customHeaders: {}

# Time in milliseconds for Elasticsearch to wait for responses from shards. Set to 0 to disable.
#elasticsearch.shardTimeout: 30000

# Time in milliseconds to wait for Elasticsearch at Kibana startup before retrying.
#elasticsearch.startupTimeout: 5000

# Logs queries sent to Elasticsearch. Requires logging.verbose set to true.
#elasticsearch.logQueries: false

# Specifies the path where Kibana creates the process ID file.
#pid.file: /var/run/kibana.pid

# Enables you specify a file where Kibana stores log output.
#logging.dest: stdout

# Set the value of this setting to true to suppress all logging output.
#logging.silent: false

# Set the value of this setting to true to suppress all logging output other than error messages.
#logging.quiet: false

# Set the value of this setting to true to log all events, including system usage information
# and all requests.
#logging.verbose: false

# Set the interval in milliseconds to sample system and process performance
# metrics. Minimum is 100ms. Defaults to 5000.
#ops.interval: 5000

# Specifies locale to be used for all localizable strings, dates and number formats.
# Supported languages are the following: English - en , by default , Chinese - zh-CN .
#i18n.locale: "en"

```
* systemctl start kibana
* if elastic already made a cluster before seeds were up delete the elastic data folder: ```rm -rf /data/elasticsearch/*```

### logstash
* yum install logstash
* vi /etc/logstash/jvm.properties: can change heap size
* pipeline configurations
  * /etc/logstash/conf.d/
#### logstash pipelines
* vi /etc/logstash/conf.d/100-input-zeek.conf
```.conf
input {
  kafka {
    topics => ["zeek-raw"]
    add_field => { "[@metadata][stage]" => "zeek-raw" }
    bootstrap_servers => "172.16.30.102:9092"
    #can not have more consumers than partitions
    #consumer_threads => 4
    group_id => "bro_logstash"
    codec => json
    auto_offset_reset => "earliest"
  }
}
```

* vi /etc/logstash/conf.d/500-filter-zeek.conf
```.conf
filter{
   if [@metadata][stage] == "zeek-raw" {
      mutate {
           add_field => { "processed_time" => "@timestamp"}
      }
      date { match => ["ts", "ISO8601" ] }
      mutate {
        add_field => {"orig_host" => "%{id.orig_h}"}
        add_field => {"resp_host" => "%{id.resp_h}"}
        add_field => {"src_ip" => "%{id.orig_h}"}
        add_field => {"dst_ip" => "%{id.resp_h}"}
        add_field => {"related_ips" => []}
      }
      mutate {
        merge => {"related_ips" => "id.orig_h"}
      }

      mutate {
        merge => {"related_ips" => "id.resp_h"}
     }
   }
}
```

* vi /etc/logstash/conf.d/999-output-zeek.conf
```.conf
output {
  if [@metadata][stage] == "zeek-raw" {
    elasticsearch {
      hosts => ["172.16.30.102:9200"]
      index => "zeek-%{+YYYY.MM.dd}"
      template => "/etc/logstash/bro-index-template.json"
    }
  }
}
```

* check to see if logstash can run with these cahnges to make debuggin easier
  * systemctl start logstash
  * if errors: tail -f /var/log/logstash/logstash-plain.log

* vi /etc/logstash/bro-index-template.json
* place below in the kibana dev tools gui
```
look in elasticsearch/mappings
```
* vi /etc/logstash/conf.d/100-input-fsf.conf
```
input {
  kafka {
    topics => ["fsf-raw"]
    add_field => { "[@metadata][stage]" => "fsf-raw" }
    bootstrap_servers => "172.16.30.102:9092"
    #can not have more consumers than partitions
    #consumer_threads => 4
    group_id => "fsf_logstash"
    codec => json
    auto_offset_reset => "earliest"
  }
}
```
* vi /etc/logstash/conf.d/999-output-fsf.conf
```
output {
  if [@metadata][stage] == "fsf-raw" {
    elasticsearch {
      hosts => ["172.16.30.102:9200"]
      index => "fsf-%{+yyyy.MM.dd}"
      #template => "/etc/logstash/bro-index-template.json"
  }
 }
}
```
* vi /etc/logstash/conf.d/100-input-suricata.conf
```
input {
  kafka {
    topics => ["suricata-raw"]
    add_field => { "[@metadata][stage]" => "suricata-raw" }
    bootstrap_servers => "172.16.30.102:9092"
    #can not have more consumers than partitions
    #consumer_threads => 4
    group_id => "suricata_logstash"
    codec => json
    auto_offset_reset => "earliest"
  }
}
```
* vi /etc/logstash/conf.d/999-output-suricata.conf
```
output {
  if [@metadata][stage] == "suricata-raw" {
    elasticsearch {
      hosts => ["172.16.30.102:9200"]
      index => "suricata-%{+yyyy.MM.dd}"
      #template => "/etc/logstash/bro-index-template.json"
  }
 }
}
```

### restart all
* systemctl stop logstash suricata stenographer fsf kafka zookeeper elasticsearch
* if you want to clear kafka
  * rm -rf /var/lib/zookeeper/varsion-2/
  * rm -rf /data/kafka/*
* if you want to clear elasticsearch
  * delete indices from within kibana, this will keep mappings, or if you want to clear everything see next
  * rm -rf /data/elasticsearch/*
* clear fsf
  * rm -f /data/fsf/logs/rockout.log
* clear suricata
  * rm -f /data/suricata/eve.log
* clear pcap
  * rm -f /data/steno/thread0/packets/*
  * rm -f /data/steno/thread0/index/*
* systemctl start elastcisearch
* systemctl start suricata stenographer zookeeper kafka logstash fsf
