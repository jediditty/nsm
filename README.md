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

### spanning and tapping
