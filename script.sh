#!/bin/bash

# Définition du fichier de log
LOG_FILE="/home/$USER/lorelei-$(date '+%H-%M-%d-%m-%Y').log"

# Fonction pour logger les messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Vérifier si l'utilisateur est root
if [ "$(id -u)" != "0" ]; then
   log_message "Ce script doit être exécuté en tant que root"
   exit 1
fi

# Variables globales pour l'IP et le port du serveur
SERVER_IP=""
SERVER_PORT=""

# Demande à l'utilisateur d'entrer l'IP et le port du serveur
demander_ip_port() {
    read -p "Entrer l'adresse IP du serveur OpenVPN (ex: 172.16.246.10) : " SERVER_IP
    read -p "Entrer le port du serveur OpenVPN (ex: 1194) : " SERVER_PORT
    log_message "Adresse IP du serveur configurée : $SERVER_IP, Port : $SERVER_PORT"
}

# Demander l'IP et le port du serveur dès le début
demander_ip_port

# Fonction pour vérifier si un paquet est installé
is_package_installed() {
    dpkg -l | grep "^ii" | grep -w "$1" > /dev/null
    return $?
}

# Fonction pour désinstaller un paquet
uninstall_package() {
    log_message "Désinstallation de $1..."
    apt-get purge -y $1
    apt-get autoremove -y
}

# Fonction pour installer OpenVPN et easy-rsa
installer_openvpn() {
    # Vérifie si Easy-RSA est installé
    if is_package_installed "easy-rsa"; then
        read -p "Easy-RSA est installé. Voulez-vous le désinstaller ? (o/n) " choice
        if [[ $choice == "o" ]]; then
            uninstall_package "easy-rsa"
        fi
    fi

    # Vérifie si OpenVPN est installé
    if is_package_installed "openvpn"; then
        read -p "OpenVPN est installé. Voulez-vous le désinstaller ? (o/n) " choice
        if [[ $choice == "o" ]]; then
            uninstall_package "openvpn"
        fi
    fi

    log_message "Installation d'OpenVPN et easy-rsa..."
    apt-get update
    apt-get install -y openvpn easy-rsa
    cp -r /usr/share/easy-rsa /opt
}

# Fonction pour configurer la PKI et les certificats
configurer_pki() {
    log_message "Configuration de la PKI et des certificats..."

    cd /opt/easy-rsa
    ./easyrsa init-pki

    echo "Entrer le nom de domaine pour la CA (ex: pki-eval.local) :"
    read ca_name
    ./easyrsa build-ca nopass --batch --req-cn="$ca_name"

    log_message "Génération des clés et certificats pour le serveur..."
    ./easyrsa gen-req server nopass --batch
    ./easyrsa sign-req server server --batch

    log_message "Génération de la clé Diffie-Hellman..."
    ./easyrsa gen-dh

    log_message "PKI et certificats configurés."
}

# Fonction pour configurer OpenVPN
configurer_openvpn() {
    log_message "Configuration d'OpenVPN..."

    echo "Entrer le nom du serveur OpenVPN (ex: monserveur) :"
    read server_name

    cat > /etc/openvpn/server/${server_name}_server.conf <<EOF
    port $SERVER_PORT
    proto udp
    dev tun
    ca /opt/easy-rsa/pki/ca.crt
    cert /opt/easy-rsa/pki/issued/${server_name}.${CA_NAME}.crt
    key /opt/easy-rsa/pki/private/${server_name}.${CA_NAME}.key
    dh /opt/easy-rsa/pki/dh.pem
    server 10.8.0.0 255.255.255.0
    ifconfig-pool-persist ipp.txt
    push "redirect-gateway def1 bypass-dhcp"
    push "dhcp-option DNS 8.8.8.8"
    keepalive 10 120
    cipher AES-256-CBC
    user nobody
    group nogroup
    persist-key
    persist-tun
    status openvpn-status.log
    verb 3
EOF

    log_message "Configuration du serveur OpenVPN '${server_name}' terminée."
}

# Fonction pour créer un client
creer_client() {
    echo "Création d'un client OpenVPN..."

    echo "Entrer le nom du client (ex: client1) :"
    read client_name

    # Génération du certificat et de la clé pour le client
    ./easyrsa gen-req $client_name nopass
    ./easyrsa sign-req client $client_name

    # Création du fichier de configuration client avec les certificats et clés intégrés
    cat > /srv/${client_name}_client.conf <<EOF
    client
    dev tun
    proto udp
    remote $SERVER_IP $SERVER_PORT
    resolv-retry infinite
    nobind
    user nobody
    group nogroup
    persist-key
    persist-tun
    # CA
    <ca>
    $(cat /opt/easy-rsa/pki/ca.crt)
    </ca>
    # Cert
    <cert>
    $(cat /opt/easy-rsa/pki/issued/${client_name}.crt)
    </cert>
    # Key
    <key>
    $(cat /opt/easy-rsa/pki/private/${client_name}.key)
    </key>
    remote-cert-tls server
    cipher AES-256-CBC
    verb 3
EOF

    echo "Configuration du client '${client_name}' terminée."
}


    log_message "Configuration du client '${client_name}' terminée."
}

# Activer IP forwarding de manière persistante
activer_ip_forwarding() {
    log_message "Activation de l'IP Forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
    sysctl -p
    log_message "IP Forwarding activé."
}

# Installer et configurer iptables
configurer_iptables() {
    log_message "Configuration d'iptables..."

    # Vérifier si iptables est installé
    if ! is_package_installed "iptables"; then
        log_message "Installation d'iptables..."
        apt-get install -y iptables
    else
        log_message "iptables déjà installé. Réinitialisation des règles existantes..."
        iptables -t nat -F
    fi

    # Demander la plage IP avec CIDR
    default_cidr="10.8.0.0/24"
    read -p "Entrer la plage IP avec CIDR pour les règles iptables (défaut: $default_cidr) : " cidr
    cidr=${cidr:-$default_cidr}
    log_message "Plage IP avec CIDR sélectionnée : $cidr"

    # Demander à l'utilisateur de choisir l'interface réseau
    log_message "Interfaces réseau disponibles :"
    ip link show
    read -p "Entrer le nom de l'interface réseau pour la sortie (ex: enp1s0) : " network_interface
    log_message "Interface réseau sélectionnée : $network_interface"

    # Appliquer la règle iptables
    iptables -t nat -A POSTROUTING -s $cidr -o $network_interface -j MASQUERADE
    log_message "Règle iptables appliquée pour la plage IP $cidr sur l'interface $network_interface."

    # Installer iptables-persistent pour conserver les règles
    log_message "Installation d'iptables-persistent..."
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y iptables-persistent
}

# Menu de sélection
while true; do
    echo "Choisissez une option:"
    echo "1) Installer OpenVPN et easy-rsa"
    echo "2) Configurer la PKI et les certificats"
    echo "3) Créer un client"
    echo "4) Configurer OpenVPN"
    echo "5) Activer IP Forwarding et configurer iptables"
    echo "6) Quitter"
    read -p "Entrez un numéro: " choix

    log_message "Option sélectionnée : $choix"

    case $choix in
        1)
            installer_openvpn
            ;;
        2)
            configurer_pki
            ;;
        3)
            creer_client
            ;;
        4)
            configurer_openvpn
            ;;
        5)
            activer_ip_forwarding
            configurer_iptables
            ;;
        6)
            log_message "Fin du script."
            break
            ;;
        *)
            echo "Sélection invalide. Veuillez réessayer."
            ;;
    esac
done

log_message "Script terminé."