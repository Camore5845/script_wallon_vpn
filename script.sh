#!/bin/bash

# Vérifier si l'utilisateur est root
if [ "$(id -u)" != "0" ]; then
   echo "Ce script doit être exécuté en tant que root" 1>&2
   exit 1
fi

# Variables globales pour l'IP et le port du serveur
SERVER_IP=""
SERVER_PORT=""

# Demande à l'utilisateur d'entrer l'IP et le port du serveur
demander_ip_port() {
    read -p "Entrer l'adresse IP du serveur OpenVPN (ex: 192.168.1.1) : " SERVER_IP
    read -p "Entrer le port du serveur OpenVPN (ex: 1194) : " SERVER_PORT
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
    echo "Désinstallation de $1..."
    sudo apt-get purge -y $1
    sudo apt-get autoremove -y
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

    echo "Installation d'OpenVPN et easy-rsa..."
    apt-get update
    apt-get install -y openvpn easy-rsa
    cp -r /usr/share/easy-rsa /opt
}

# Fonction pour configurer la PKI et les certificats
configurer_pki() {
    echo "Configuration de la PKI et des certificats..."

    cd /opt/easy-rsa
    ./easyrsa init-pki

    echo "Entrer le nom de domaine pour la CA (ex: pki-eval.local) :"
    read ca_name
    ./easyrsa build-ca nopass --batch --req-cn="$ca_name"

    echo "Génération des clés et certificats pour le serveur..."
    ./easyrsa gen-req server nopass --batch
    ./easyrsa sign-req server server --batch

    echo "Génération de la clé Diffie-Hellman..."
    ./easyrsa gen-dh

    echo "PKI et certificats configurés."
}

# Fonction pour configurer OpenVPN
configurer_openvpn() {
    echo "Configuration d'OpenVPN..."

    echo "Entrer le nom du serveur OpenVPN (ex: monserveur) :"
    read server_name

    cat > /etc/openvpn/server/${server_name}_server.conf <<EOF
    port $SERVER_PORT
    proto udp
    dev tun
    ca /opt/easy-rsa/pki/ca.crt
    cert /opt/easy-rsa/pki/issued/server.crt
    key /opt/easy-rsa/pki/private/server.key
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

    echo "Configuration du serveur OpenVPN '${server_name}' terminée."
}

# Fonction pour créer un client
creer_client() {
    echo "Création d'un client OpenVPN..."

    echo "Entrer le nom du client (ex: client1) :"
    read client_name

    # Génération du certificat et de la clé pour le client
    ./easyrsa gen-req $client_name nopass
    ./easyrsa sign-req client $client_name

    # Création du fichier de configuration client
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
    ca ca.crt
    cert issued/${client_name}.crt
    key private/${client_name}.key
    remote-cert-tls server
    cipher AES-256-CBC
    verb 3
EOF

    echo "Configuration du client '${client_name}' terminée."
}

# Menu de sélection
while true; do
    echo "Choisissez une option:"
    echo "1) Installer OpenVPN et easy-rsa"
    echo "2) Configurer la PKI et les certificats"
    echo "3) Créer un client"
    echo "4) Configurer OpenVPN"
    echo "5) Quitter"
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
            break
            ;;
        *)
            echo "Sélection invalide. Veuillez réessayer."
            ;;
    esac
done

echo "Script terminé."
