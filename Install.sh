#!/bin/bash

# Fonction pour vérifier si le système d'exploitation est Linux
is_linux() {
    if [ "$(uname)" == "Linux" ]; then
        return 0
    else
        return 1
    fi
}

# Vérifier si le système est Linux
if ! is_linux; then
    echo "Ce script est uniquement compatible avec les systèmes Linux."
    exit 1
fi

# Mettre à jour les paquets de la machine
echo "Mise à jour des paquets..."
sudo apt-get update && sudo apt-get upgrade -y

# Vérifier et installer Python3 si nécessaire
if ! command -v python3 &> /dev/null; then
    echo "Installation de Python3..."
    sudo apt-get install -y python3
else
    echo "Python3 est déjà installé."
fi

# Vérifier et installer pip pour Python3 si nécessaire
if ! command -v pip3 &> /dev/null; then
    echo "Installation de pip pour Python3..."
    sudo apt-get install -y python3-pip
else
    echo "pip pour Python3 est déjà installé."
fi

# Installer la bibliothèque psutil
echo "Installation de la bibliothèque psutil..."
sudo apt install python3-psutil

echo "Installation terminée."
