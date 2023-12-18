#!/bin/bash

#Définition du fichier de log
LOG_FILE="/home/$USER/lorelei-$(date '+%H-%M-%d-%m-%Y').log"

#Fonction pour logger les messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Vérifier si l'utilisateur est root
if [ "$(id -u)" != "0" ]; then
   log_message "Ce script doit être exécuté en tant que root"
   exit 1
fi
# Fonction pour initialiser les dossiers PKI si nécessaire
initialiser_dossiers_pki() {
    local dossier_pki="/opt/easy-rsa/pki"
    
    # Créer le dossier principal de la PKI
    creer_dossier_si_necessaire "$dossier_pki"

    # Créer les sous-dossiers nécessaires pour les certificats et clés
    creer_dossier_si_necessaire "$dossier_pki/issued"
    creer_dossier_si_necessaire "$dossier_pki/private"

    log_message "Dossiers PKI initialisés."
}

#Variables globales pour l'IP et le port du serveur, le nom du serveur et le nom de la CA
SERVER_IP=""
SERVER_PORT=""
CA_NAME=""
server_name="""

#Demande à l'utilisateur d'entrer l'IP et le port du serveur
demander_ip_port() {
    read -p "Entrer l'adresse IP du serveur OpenVPN (ex: 172.16.246.10) : " SERVER_IP
    read -p "Entrer le port du serveur OpenVPN (ex: 1194) : " SERVER_PORT
    log_message "Adresse IP du serveur configurée : $SERVER_IP, Port : $SERVER_PORT"
}

# Demander l'IP et le port du serveur dès le début
demander_ip_port

#Fonction pour vérifier si un paquet est installé
is_package_installed() {
    dpkg -l | grep "^ii" | grep -w "$1" > /dev/null
    return $?
}

#Fonction pour désinstaller un paquet
uninstall_package() {
    log_message "Désinstallation de $1..."
    apt-get purge -y $1
    apt-get autoremove -y
}
    # Demande du nom de domaine pour la CA
    echo "Entrer le nom de domaine pour la CA (ex: pki-eval.local) :"
    read CA_NAME
    log_message "Nom de domaine pour la CA défini : $CA_NAME"

#Fonction pour installer OpenVPN et easy-rsa
installer_openvpn() {
    # Vérifie si Easy-RSA est installé
    if is_package_installed "easy-rsa"; then
        read -p "Easy-RSA est installé. Voulez-vous le désinstaller ? (o/n) " choice
        if [[ $choice == "o" ]]; then
            uninstall_package "easy-rsa"
        fi
    fi

    #Vérifie si OpenVPN est installé
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

#Fonction pour configurer la PKI et les certificats
configurer_pki() {
    log_message "Configuration de la PKI et des certificats..."
     # Initialiser les dossiers PKI
    initialiser_dossiers_pki
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

configurer_openvpn() {
    #Demande du nom du serveur OpenVPN
    echo "Entrer le nom du serveur OpenVPN (ex: monserveur) :"
    read server_name
    log_message "Nom du serveur OpenVPN défini : $server_name"

    #Vérification si CA_NAME est défini
    if [ -z "$CA_NAME" ]; then
        echo "Nom de domaine pour la CA non défini. Veuillez configurer la PKI d'abord."
        return
    fi

    #Configuration du fichier du serveur OpenVPN
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

    #Demander à l'utilisateur s'il souhaite activer l'IP Forwarding et configurer iptables
    read -p "Voulez-vous activer l'IP Forwarding et configurer iptables maintenant ? (o/n) : " choix_forwarding
    if [[ $choix_forwarding == "o" ]]; then
        activer_ip_forwarding
        configurer_iptables
    else
        log_message "Retour au menu principal."
    fi
}

#Fonction pour créer un client
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

#Activer IP forwarding de manière persistante
activer_ip_forwarding() {
    log_message "Activation de l'IP Forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
    sysctl -p
    log_message "IP Forwarding activé."
}

#Installer et configurer iptables
configurer_iptables() {
    log_message "Configuration d'iptables..."

    #Vérifier si iptables est installé
    if ! is_package_installed "iptables"; then
        log_message "Installation d'iptables..."
        apt-get install -y iptables
    else
        log_message "iptables déjà installé. Réinitialisation des règles existantes..."
        iptables -t nat -F
    fi

    #Demander la plage IP avec CIDR
    default_cidr="10.8.0.0/24"
    read -p "Entrer la plage IP avec CIDR pour les règles iptables (défaut: $default_cidr) : " cidr
    cidr=${cidr:-$default_cidr}
    log_message "Plage IP avec CIDR sélectionnée : $cidr"

    # Demander à l'utilisateur de choisir l'interface réseau
    log_message "Interfaces réseau disponibles :"
    ip link show
    read -p "Entrer le nom de l'interface réseau pour la sortie (ex: enp1s0) : " network_interface
    log_message "Interface réseau sélectionnée : $network_interface"

    #Appliquer la règle iptables
    iptables -t nat -A POSTROUTING -s $cidr -o $network_interface -j MASQUERADE
    log_message "Règle iptables appliquée pour la plage IP $cidr sur l'interface $network_interface."

    #Installer iptables-persistent pour conserver les règles
    log_message "Installation d'iptables-persistent..."
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y iptables-persistent
}

#Fonction pour vérifier et installer Wget si nécessaire
verifier_et_installer_wget() {
    if ! is_package_installed "wget"; then
        log_message "Installation de Wget..."
        apt-get install -y wget
    fi
}

#Fonction pour récupérer et configurer un client VPN distant
recuperer_et_configurer_client_distant() {
    verifier_et_installer_wget

    #Demander l'URL du fichier de configuration client VPN distant
    echo "Entrer l'URL du fichier de configuration client OpenVPN distant :"
    read client_conf_url
    wget -O temp_client.conf "$client_conf_url" || { echo "Erreur lors du téléchargement"; return; }

    #Demander à l'utilisateur de nommer le fichier de configuration
    echo "Nommer le fichier de configuration (défaut: catheram.conf) :"
    read client_conf_name
    client_conf_name=${client_conf_name:-catheram.conf}

    #Demander le répertoire de destination pour le fichier de configuration
    echo "Répertoire de destination pour le fichier de configuration (défaut: /etc/openvpn/client) :"
    read client_conf_dir
    client_conf_dir=${client_conf_dir:-/etc/openvpn/client}

    #Déplacer le fichier de configuration dans le répertoire spécifié
    mv temp_client.conf "$client_conf_dir/$client_conf_name"

    #Afficher les interfaces réseau et leurs adresses IP pour aider à choisir l'interface
    echo "Interfaces réseau disponibles :"
    ip -4 addr show | grep -E '^[0-9]+: ' | cut -d' ' -f2,3

    #Demander l'interface réseau
    read -p "Entrer le nom de l'interface réseau (défaut: eth0) : " network_interface
    network_interface=${network_interface:-eth0}

    #Demander les plages IP pour la règle iptables
    echo "Entrer la plage IP locale du serveur VPN (ex: 10.8.0.0/24) :"
    read local_vpn_range
    echo "Entrer la plage IP du client VPN distant (ex: 10.9.0.0/24) :"
    read remote_vpn_range

    #Configurer la règle iptables
    iptables -A FORWARD -i $network_interface -o tun1 -s $local_vpn_range -d $remote_vpn_range -j ACCEPT
    log_message "Règle iptables configurée pour le routage entre $local_vpn_range et $remote_vpn_range."

    #Demander confirmation avant de démarrer la configuration client VPN
    echo "Êtes-vous sûr de vouloir démarrer la configuration client ? (o/n)"
    read confirmation
    if [[ $confirmation == "o" ]]; then
        systemctl start openvpn-client@$client_conf_name
        ip a show tun1
    fi
    # Redémarrer la configuration client VPN pour appliquer les changements
    log_message "Redémarrage de la configuration client VPN pour appliquer les changements."
    systemctl stop openvpn-client@$client_conf_name
    systemctl start openvpn-client@$client_conf_name
    log_message "Configuration du client VPN '${client_conf_name}' redémarrée et appliquée."

    #Vérification de l'état du tunnel VPN
    ip a show tun1
}

#Menu de sélection
while true; do
    echo "Choisissez une option:"
    echo "1) Installer OpenVPN et easy-rsa"
    echo "2) Configurer la PKI et les certificats"
    echo "3) Créer un client"
    echo "4) Configurer le Serveur OpenVPN"
    echo "5) Activer IP Forwarding et configurer iptables"
    echo "6) Récupérer et configurer un client VPN distant"
    echo "7) Quitter"
    read -p "Entrez un numéro: " choix

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
            recuperer_et_configurer_client_distant
            ;;
        7)
            log_message "Fin du script."
            break
            ;;
        *)
            echo "Sélection invalide. Veuillez réessayer."
            ;;
    esac
done

log_message "Script terminé."