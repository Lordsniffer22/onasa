

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


banner() {
    source <(curl -sSL 'https://raw.githubusercontent.com/TeslaSSH/Tesla_UDP_custom-/main/module/module')
    clear
    print_pink " _____ _____ ____  _        _      ____ ____  _   _ "
    print_pink "|_   _| ____/ ___|| |      / \    / ___/ ___|| | | |"
    print_blue "  | | |  _| \___ \| |     / _ \   \___ \___ \| |_| |"
    print_yellow "  | | | |___ ___) | |___ / ___ \   ___) |__) |  _  |"
    print_yellow "  |_| |_____|____/|_____/_/   \_\ |____/____/|_| |_|" 
    echo ""
    print_center -ama ' Version: 1.0'
    print_center -ama ' WireGuard Premium'
    print_center -ama ' Client App : WireGuard VPN'

    ram=$(printf '%-8s' "$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')")
    cpu=$(printf '%-1s' "$(top -bn1 | awk '/Cpu/ { cpu = "" 100 - $8 "%" }; END { print cpu }')")
    # print_center -ama " $(msg -verd 'IP:') $(msg -azu "$request_public_ip")  $(msg -verd 'Ram:') $(msg -azu "$ram") $(msg -verd 'CPU:') $(msg -azu "$cpu")"
    echo " $(msg -verd ' ⇢  IP:') $(msg -azu "$request_public_ip")  $(msg -verd 'Ram:') $(msg -azu "$ram") $(msg -verd 'CPU:') $(msg -azu "$cpu")"
    msg -bar3

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


function newClient() {
    # Check for IPv6 brackets in SERVER_PUB_IP
    if [[ ${SERVER_PUB_IP} =~ .*:.* && ${SERVER_PUB_IP} != *"["* ]]; then
        SERVER_PUB_IP="[${SERVER_PUB_IP}]"
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    print_pink "The client name must consist of alphanumeric characters (underscores/dashes allowed) and max length is 15 chars."

    # Ask for client name
    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "Client name: " CLIENT_NAME
        CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

        if [[ ${CLIENT_EXISTS} -ne 0 ]]; then
            echo "Error: Client name '${CLIENT_NAME}' already exists. Please choose another name."
        fi
    done

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

    # QR code
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 <"${CLIENT_CONFIG}"
    fi

    echo "Client config written to: ${CLIENT_CONFIG}"
    exit
}





function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done



	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
    menu
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS
		rm -rf /usr/bin/menu

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# Reload sysctl
		sysctl --system

		# Check if WireGuard is running
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function menu() {
    banner 
    print_center -ama "${a12:-CHOOSE AN OPTION}"
    msg -bar3
    echo " $(msg -verd "[1]") $(msg -verm2 '>') $(msg -teal "${a6:-Create User♞}")"
    echo " $(msg -verd "[2]") $(msg -verm2 '>') $(msg -ama "${a8:-List Users}")"
    echo " $(msg -verd "[3]") $(msg -verm2 '>') $(msg -teal "${a11:-Kick User⚡}")"
    echo " $(msg -verd "[4]") $(msg -verm2 '>') $(msg -teal "${a10:-Remove Wireguard🌦️}")"
    echo " $(msg -verd "[0]") $(msg -verm2 '>') $(msg -teal "${a10:-Exit Menu}")"
    echo ""
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	0)
		exit 0
		;;
	esac
}


source "/etc/wireguard/params"
menu

