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
sudo firewall-cmd --zone-public --add-port=5601/tcp --permanent
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
reposync -l --repoid=localstuff --download_path=/srv/repos/ --newest-only --downloadcomps --download-metadata
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
