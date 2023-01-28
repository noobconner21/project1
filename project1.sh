#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
ENDCOLOR="\e[0m"
WHITE="\e[0;37m"


#public ip

pub_ip=$(wget -qO- https://ipecho.net/plain ; echo)


#root check

if ! [ $(id -u) = 0 ]; then
   echo -e "${RED}Plese run the script with root privilages!${ENDCOLOR}"
   exit 1
fi

########################################################################
###                                                                  ###
###                       SETUP FUNCTIONS                            ###
###                                                                  ###
########################################################################

clear
spinner()
{
    #Loading spinner
    local pid=$!
    local delay=0.75
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

install_dependency()
{
	apt-get update -y && apt-get upgrade -y
	apt install -y unzip cmake build-essential nodejs dropbear git
}


pre_dropbear()
{
#configuring dropbear
mkdir /etc/Sslablk
mv /etc/default/dropbear /etc/default/dropbear.backup
cat << EOF > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=444
DROPBEAR_EXTRA_ARGS=
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF
}
#Adding the banner

add_banner()
{
cat << EOF > /etc/banner
<h1 style="text-align:center;"><span style="color:#8b00ff">====================<span style="color:#ffffff"></span></span></h1><h2 style="text-align:center;"><span style="color:red">&#9733;| XOR-SERVERS&trade; |&#9733;<span style="color:#ffffff"></span></span></h2><h1 style="text-align:center;"><span style="color:#8b00ff">====================<span style="color:#ffffff"></span></span></h1>
EOF
}

pre_badvpn()
{

cd $HOME
wget https://github.com/ambrop72/badvpn/archive/master.zip
unzip master.zip
cd badvpn-master
mkdir build
cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd $HOME
}

pre_Proxy()
{
#Proxy JavaScript Install

cat << EOF > /etc/systemd/system/nodews1.service
[Unit]
Description=P7COM-nodews1
Documentation=https://p7com.net/
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=node /etc/Sslablk/proxy3.js -dhost 127.0.0.1 -dport 444 -mport 80
Restart=on-failure
RestartPreventExitStatus=1

[Install]
WantedBy=multi-user.target
EOF

#proxy java

cat << EOF > /etc/Sslablk/proxy3.js
/*
* Proxy Bridge
* Copyright PANCHO7532 - P7COMUnications LLC (c) 2021
* Dedicated to Emanuel Miranda, for giving me the idea to make this :v
*/
const net = require('net');
const stream = require('stream');
const util = require('util');
var dhost = "127.0.0.1";
var dport = "8080";
var mainPort = "8888";
var outputFile = "outputFile.txt";
var packetsToSkip = 0;
var gcwarn = true;
for(c = 0; c < process.argv.length; c++) {
    switch(process.argv[c]) {
        case "-skip":
            packetsToSkip = process.argv[c + 1];
            break;
        case "-dhost":
            dhost = process.argv[c + 1];
            break;
        case "-dport":
            dport = process.argv[c + 1];
            break;
        case "-mport":
            mainPort = process.argv[c + 1];
            break;
        case "-o":
            outputFile = process.argv[c + 1];
            break;
    }
}
function gcollector() {
    if(!global.gc && gcwarn) {
        console.log("[WARNING] - Garbage Collector isn't enabled! Memory leaks may occur.");
        gcwarn = false;
        return;
    } else if(global.gc) {
        global.gc();
        return;
    } else {
        return;
    }
}
function parseRemoteAddr(raddr) {
    if(raddr.toString().indexOf("ffff") != -1) {
        //is IPV4 address
        return raddr.substring(7, raddr.length);
    } else {
        return raddr;
    }
}
setInterval(gcollector, 1000);
const server = net.createServer();
server.on('connection', function(socket) {
    var packetCount = 0;
    //var handshakeMade = false;
    socket.write("HTTP/1.1 101 By Project SSLaB LK\r\nContent-Length: 1048576000000\r\n\r\n");
    console.log("[INFO] - Connection received from " + socket.remoteAddress + ":" + socket.remotePort);
    var conn = net.createConnection({host: dhost, port: dport});
    socket.on('data', function(data) {
        //pipe sucks
        if(packetCount < packetsToSkip) {
            //console.log("---c1");
            packetCount++;
        } else if(packetCount == packetsToSkip) {
            //console.log("---c2");
            conn.write(data);
        }
        if(packetCount > packetsToSkip) {
            //console.log("---c3");
            packetCount = packetsToSkip;
        }
        //conn.write(data);
    });
    conn.on('data', function(data) {
        //pipe sucks x2
        socket.write(data);
    });
    socket.once('data', function(data) {
        /*
        * Nota para mas tarde, resolver que diferencia hay entre .on y .once
        */
    });
    socket.on('error', function(error) {
        console.log("[SOCKET] - read " + error + " from " + socket.remoteAddress + ":" + socket.remotePort);
        conn.destroy();
    });
    conn.on('error', function(error) {
        console.log("[REMOTE] - read " + error);
        socket.destroy();
    });
    socket.on('close', function() {
        console.log("[INFO] - Connection terminated for " + socket.remoteAddress + ":" + socket.remotePort);
        conn.destroy();
    });
});
server.listen(mainPort, function(){
    console.log("[INFO] - Server started on port: " + mainPort);
    console.log("[INFO] - Redirecting requests to: " + dhost + " at port " + dport);
});

EOF
}

pre_Proxy_start()
{

systemctl enable nodews1
systemctl start nodews1
}

#stunnel

post_Stunnel()
{
cd /etc/stunnel
cat << EOF > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/Sslablk/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[https]
accept = 443
connect = 127.0.0.1:80
EOF

systemctl stop nodews1.service # port 80 free
read -p "Please provide a valid email address: " zerossl_email
read -p "Please provide the domain name: " zerossl_domain


mkdir /etc/Sslablk/certs; pushd /etc/Sslablk/certs
git clone https://github.com/acmesh-official/acme.sh.git
cd acme.sh
read -p "Enter"

#curl https://get.acme.sh | sh -s email="$zerossl_email" --issue -d "$zerossl_domain" --standalone --server letsencrypt --staging --test


bash acme.sh --register-account -m "$zerossl_email" 
bash acme.sh --issue --standalone -d "$zerossl_domain" --force --staging --test
bash acme.sh --installcert -d "$zerossl_domain" --fullchainpath /etc/Sslablk/certs/bundle.cer --keypath /etc/Sslablk/certs/private.key

read -p "enter"

cat /etc/Sslablk/certs/private.key /etc/Sslablk/certs/bundle.cer > /etc/Sslablk/stunnel.pem

systemctl start nodews1.service

#### download zerossl zipfile
###
###mkdir zerossl && cd zerossl
###read -p "What's your zerossl zip file link? (Dropbox): " zerofileslink
###
###wget $zerofileslink
###
####unzip_zerossl_zipfile
###
###unzip *
###
###cat private.key certificate.crt ca_bundle.crt > /etc/stunnel/stunnel.pem
###
###cd ..
###rm -rf zerossl
###clear

}

install_stunnel()
{
	apt install stunnel4 -y
}

start_stunnel()
{
sudo systemctl enable stunnel4
systemctl start stunnel4
}


#creating badvpn systemd service unit

creating_badvpn()
{

cat << 'EOF' > /etc/systemd/system/badvpn.service
[Unit]
Description=BadVPN UDPGW Service

[Service]
ExecStart=/bin/bash -c '$$(which badvpn-udpgw) --listen-addr 127.0.0.1:7300 --max-clients 250 --max-connections-for-client 3'
ExecStop=/bin/bash -c '$$(pkill) badvpn-udpgw'

[Install]
WantedBy=multi-user.target
EOF
}

start_badvpn()
{
systemctl enable badvpn
systemctl start badvpn
}

#install Panel
install_panel()
{
cd /etc/Sslablk
wget https://github.com/noobconner21/project1/raw/main/etc.zip
unzip etc
cd /etc/Sslablk/etc
mv menu /usr/local/bin
wget -O speedtest-cli https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
chmod +x ChangeUser.sh
chmod +x UserManager.sh
chmod +x Banner.sh
chmod +x DelUser.sh
chmod +x ListUsers.sh
chmod +x RemoveScript.sh
chmod +x speedtest-cli
cd /usr/local/bin
chmod +x menu

}


#enabling and starting all services

restart_system()
{
systemctl restart nodews1
systemctl restart stunnel4
sudo systemctl restart udpgw
sudo systemctl restart badvpn
#configure user shell to /bin/false
echo /bin/false >> /etc/shells
clear
}


########################################################################
###                                                                  ###
###                       INSTALL PROCESS                            ###
###                                                                  ###
########################################################################


echo -ne "\n${BLUE} SCRIPT BY PROJECT SSLAB LK"
echo -ne "\n${WHITE}............. ⍟ Installing Dependencies ⍟ ............."
install_dependency >/dev/null 2>&1 &
spinner
echo -ne "\tdone"

echo -ne "\n${WHITE}............. ⍟ Compiling and installing Dropbear ⍟ ............."
pre_dropbear >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}............. ⍟ Add SSL Banner ⍟ ............."
add_banner >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}............. ⍟ Compiling and installing Badvpn ⍟ ............."
#pre_badvpn >/dev/null 2>&1 &
pre_badvpn  >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}............. ⍟ Proxy JavaScript Install ⍟ ............."
pre_Proxy >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}Starting Proxy JavaScript............."
pre_Proxy_start >/dev/null 2>&1 &
spinner
echo -ne "\tdone"

echo -ne "\n${WHITE}............. ⍟ Compiling And Installing Stunnel ⍟ ............"
install_stunnel >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -e "${ENDCOLOR}"


post_Stunnel



echo -ne "\tdone"
echo -ne "\n${WHITE}Starting Stunnel ............."
start_stunnel >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}Compiling and installing Badvpn UDP Gateway ............."
creating_badvpn >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}Starting Badvpn ............."
start_badvpn >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -ne "\n${WHITE}Installing Panel............."
install_panel >/dev/null 2>&1 &
spinner
echo -ne "\n${WHITE}Restart All  Services ............."
restart_system >/dev/null 2>&1 &
spinner
echo -ne "\tdone"
echo -e "${ENDCOLOR}"



#Adding the default user
echo -ne "${GREEN}Enter the default username : "; read username
while true; do
    read -p "Do you want to genarate a random password ? (Y/N) " yn
    case $yn in
        [Yy]* ) password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-9};echo;); break;;
        [Nn]* ) echo -ne "Enter password (please use a strong password) : "; read password; break;;
        * ) echo "Please answer yes or no.";;
    esac
done
echo -ne "Enter No. of Days till expiration : ";read nod
exd=$(date +%F  -d "$nod days")
useradd -e $exd -M -N -s /bin/false $username && echo "$username:$password" | chpasswd &&
clear &&
echo -e "${GREEN}Default User Details" &&
echo -e "${RED}--------------------" &&
echo -e "${GREEN}\nUsername :${YELLOW} $username" &&
echo -e "${GREEN}\nPassword :${YELLOW} $password" &&
echo -e "${GREEN}\nExpire Date :${YELLOW} $exd ${ENDCOLOR}" ||
echo -e "${RED}\nFailed to add default user $username please try again.${ENDCOLOR}"

#exit script
echo -e "\n${CYAN}Script installed. You can access the panel using 'menu' command. ${ENDCOLOR}\n"
echo -e "\nPress Enter key to exit"; read

reboot
