#!/bin/bash

apt-get update -y
apt-get upgrade -y
apt-get install libpcap-dev gcc 

wget https://go.dev/dl/go1.18.1.linux-amd64.tar.gz

rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc

