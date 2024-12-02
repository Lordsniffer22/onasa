

print_blue() {
    echo -e "\e[1;34m$1\e[0m"
}
print_blu() {
    echo -e "\e[34m$1\e[0m"
}
print_yellow() {
    echo -e "\e[1;33m$1\e[0m"
}
print_pink() {
    echo -e "\e[1;95m$1\e[0m"
}
print_viola() {
    echo -e "\e[1;35m$1\e[0m"
}



banner_install() {
    source <(curl -sSL 'https://raw.githubusercontent.com/TeslaSSH/Tesla_UDP_custom-/main/module/module')
    clear
    print_pink " _____ _____ ____  _        _      ____ ____  _   _ "
    print_pink "|_   _| ____/ ___|| |      / \    / ___/ ___|| | | |"
    print_blue "  | | |  _| \___ \| |     / _ \   \___ \___ \| |_| |"
    print_yellow "  | | | |___ ___) | |___ / ___ \   ___) |__) |  _  |"
    print_yellow "  |_| |_____|____/|_____/_/   \_\ |____/____/|_| |_|" 
    echo ""
    echo ""
    msg -bar
    print_center -ama ' WireGuard Premium V1.0'
    print_center -ama ' Client App : WireGuard VPN'
    msg -bar0
    echo ""
    echo ""
    print_center -ama " Installation in Progress"
    msg -bar3

}

progres() {
comando[0]="$1"
comando[1]="$2"
 (
[[ -e $HOME/fim ]] && rm $HOME/fim
${comando[0]} -y > /dev/null 2>&1
${comando[1]} -y > /dev/null 2>&1
touch $HOME/fim
 ) > /dev/null 2>&1 &
 tput civis
echo -ne "  \033[1;33mWAIT \033[1;37m- \033[1;33m["
while true; do
   for((i=0; i<18; i++)); do
   echo -ne "\033[1;31m#"
   sleep 0.1s
   done
   [[ -e $HOME/fim ]] && rm $HOME/fim && break
   echo -e "\033[1;33m]"
   sleep 1s
   tput cuu1
   tput dl1
   echo -ne "  \033[1;33mWAIT \033[1;37m- \033[1;33m["
done
echo -e "\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
tput cnorm
}




function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		print_yellow "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		print_pink "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}





function installparams() {
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi

    SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"

    SERVER_WG_NIC="wg0"
    SERVER_WG_IPV4="10.66.66.1"
    SERVER_WG_IPV6="fd42:42:42::1"
    # SERVER_PORT=$(shuf -i49152-65535 -n1)
    SERVER_PORT="9201"
    CLIENT_DNS_1="1.1.1.1"
    CLIENT_DNS_2="1.0.0.1"
    ALLOWED_IPS="0.0.0.0/0,::/0"


}

function newClient() {
    # Check for IPv6 brackets in SERVER_PUB_IP
    if [[ ${SERVER_PUB_IP} =~ .*:.* && ${SERVER_PUB_IP} != *"["* ]]; then
        SERVER_PUB_IP="[${SERVER_PUB_IP}]"
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

 
    # Ask for client name
    CLIENT_NAME="teslassh"
    
    # Assign IPv4 and IPv6
    for DOT_IP in {2..254}; do
        if ! grep -q "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
            CLIENT_WG_IPV4="${SERVER_WG_IPV4::-1}${DOT_IP}"
            break
        fi
    done
    if [[ -z ${CLIENT_WG_IPV4} ]]; then
        echo "Error: No available IPv4 address found."
        return 1
    fi

    BASE_IP=$(echo "${SERVER_WG_IPV6}" | awk -F '::' '{ print $1 }')
    for DOT_IP in {2..254}; do
        if ! grep -q "${BASE_IP}::${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
            CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
            break
        fi
    done
    if [[ -z ${CLIENT_WG_IPV6} ]]; then
        echo "Error: No available IPv6 address found."
        return 1
    fi

    # Generate keys
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=$(wg genpsk)

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    CLIENT_CONFIG="${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # Write client config
    {
        echo "[Interface]"
        echo "PrivateKey = ${CLIENT_PRIV_KEY}"
        echo "Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128"
        echo "DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}"
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${SERVER_PUB_KEY}"
        echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}"
        echo "Endpoint = ${ENDPOINT}"
        echo "AllowedIPs = ${ALLOWED_IPS}"
    } >"${CLIENT_CONFIG}"

    # Update server config
    {
        echo -e "\n### Client ${CLIENT_NAME}"
        echo "[Peer]"
        echo "PublicKey = ${CLIENT_PUB_KEY}"
        echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}"
        echo "AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128"
    } >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

    # Apply configuration
    wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	
    print_pink "Scan the QrCode below using WireGuard App or any you might be using as long as it supports WireGuard Protocol."
    # QR code
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 <"${CLIENT_CONFIG}"
    fi

	print_pink "To see the menu, Type: 'menu' and press enter"
	msg -bar3
    exit
}


function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}





function installWireGuard() {
	# Run setup questions first
	installparams

	function now_install() {
		# Install WireGuard tools and module
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
			apt-get update && apt-get install -y wireguard iptables resolvconf qrencode
		elif [[ ${OS} == 'debian' ]]; then
			if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
				echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
				apt-get update
			fi
			apt update
			apt-get install -y iptables resolvconf qrencode
			apt-get install -y -t buster-backports wireguard
		elif [[ ${OS} == 'fedora' ]]; then
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf install -y dnf-plugins-core
				dnf copr enable -y jdoss/wireguard
				dnf install -y wireguard-dkms
			fi
			dnf install -y wireguard-tools iptables qrencode
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			if [[ ${VERSION_ID} == 8* ]]; then
				yum install -y epel-release elrepo-release
				yum install -y kmod-wireguard
				yum install -y qrencode # not available on release 9
			fi
			yum install -y wireguard-tools iptables
		elif [[ ${OS} == 'oracle' ]]; then
			dnf install -y oraclelinux-developer-release-el8
			dnf config-manager --disable -y ol8_developer
			dnf config-manager --enable -y ol8_developer_UEKR6
			dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
			dnf install -y wireguard-tools qrencode iptables
		elif [[ ${OS} == 'arch' ]]; then
			pacman -S --needed --noconfirm wireguard-tools qrencode
		fi


		# Make sure the directory exists (this does not seem the be the case on fedora)
		mkdir /etc/wireguard >/dev/null 2>&1

		chmod 600 -R /etc/wireguard/

		SERVER_PRIV_KEY=$(wg genkey)
		SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

		# Save WireGuard settings
		echo "SERVER_PUB_IP=${SERVER_PUB_IP}
	SERVER_PUB_NIC=${SERVER_PUB_NIC}
	SERVER_WG_NIC=${SERVER_WG_NIC}
	SERVER_WG_IPV4=${SERVER_WG_IPV4}
	SERVER_WG_IPV6=${SERVER_WG_IPV6}
	SERVER_PORT=${SERVER_PORT}
	SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
	SERVER_PUB_KEY=${SERVER_PUB_KEY}
	CLIENT_DNS_1=${CLIENT_DNS_1}
	CLIENT_DNS_2=${CLIENT_DNS_2}
	ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params


		# Add server interface
		echo "[Interface]
	Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
	ListenPort = ${SERVER_PORT}
	PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

		if pgrep firewalld; then
			FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
			FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
			echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
	PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		else
			echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
	PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
	PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
	PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
	PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
	PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
	PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
	PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
	PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
	PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
	PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
	PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		fi

		# Enable routing on the server
		echo "net.ipv4.ip_forward = 1
	net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

		sysctl --system
		systemctl daemon-reload
		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	}

	progres "now_install"

	wget -O /usr/bin/menu "https://raw.githubusercontent.com/Lordsniffer22/onasa/refs/heads/main/menu.sh" > /dev/null 2>&1
 
	chmod +x /usr/bin/menu
	echo "menu" >> ~/.bashrc
	
	echo ""
    print_center -ama " Generat.. Default QrCode"
    msg -bar3
	echo ""
	newClient



}

initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /usr/bin/menu ]]; then
	rm -rf /usr/bin/menu
else
    banner_install
    installWireGuard
fi
