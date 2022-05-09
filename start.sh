#!/bin/bash

cd /tmp
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install openjdk-11-jre openjdk-11-jdk -y
sudo apt install snapd -y
sudo snap install prospect-mail
sudo snap install teams
sudo snap install chromium
sudo snap install krdc
sudo apt-get install libnss3-tools openssl xterm libpam0g:i386 libx11-6:i386 libstdc++6:i386 libstdc++5:i386 unzip -y
wget -c https://github.com/2mesistemas/vaivendo/raw/master/snx_install.sh
chmod +x snx_install.sh
sudo ./snx_install.sh
wget -c https://github.com/2mesistemas/vaivendo/raw/master/cshell_install.sh
chmod +x cshell_install.sh 
sudo ./cshell_install.sh
wget https://github.com/2mesistemas/vaivendo/raw/master/CSHELL.zip
wget https://github.com/2mesistemas/vaivendo/raw/master/cshell.zip
sudo rm -R /tmp/CSHELL
sudo rm -R /usr/bin/cshell
unzip CSHELL.zip
unzip cshell.zip
sudo cp -R cshell /usr/bin/
sudo rm -R cshell
sudo rm cshell.zip
sudo rm CSHELL.zip
sudo wget -c -P /usr/bin/ https://github.com/2mesistemas/vaivendo/raw/master/vpn
sudo chmod +x /usr/bin/vpn
sudo apt autoremove -y
sudo apt-get update
cd ~
echo 'alias vpn="/usr/bin/vpn"' >> ~/.bashrc
sudo reboot 


