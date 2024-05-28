---

# Crowdsec-Mini

### Surveillance et Détection de Processus en Cybersécurité

Dans le contexte actuel de la cybersécurité, il est essentiel de surveiller en permanence les activités des processus sur les systèmes informatiques. Les cyberattaques deviennent de plus en plus sophistiquées, exploitant souvent des processus légitimes pour mener des actions malveillantes. Pour répondre à ce besoin, nous avons développé un script Python capable de surveiller en continu la liste des processus, de détecter des patterns caractéristiques d'une attaque et d'alerter l'utilisateur en cas de détection de comportements suspects.

## Pré-requis

Pour pouvoir exécuter le script sans soucis, assurez-vous d'avoir les éléments suivants :

- **Un accès internet**
- **Une debian 12**
- **Des droits root administrateurs pour exécuter les scripts**

## Installation et Exécution

Pour installer notre script Python, suivez ces étapes :

**1. Clonez le repository :**
   ```bash
   git clone https://github.com/JardinierBorgne/Crowdsec-Mini.git
   ```

**2. Accédez au répertoire cloné :**
   ```bash
   cd Crowdsec-Mini
   ```

**3. Installer les dépendances requises :**
Installez les dépendances nécessaires en utilisant le script d'installation nommé Install.sh. Assurez-vous que ce script a les droits d'exécution :
   ```bash
   chmod +x Install.sh
   ./Install.sh
   ```
   Alternativement, vous pouvez installer les dépendances manuellement avec pip :
   ```bash
   pip install psutil
   ```
   **OU**
   ```bash
   apt install python3-psutil
   ```

**4. Exécutez le script :**
   ```bash
   python3 Crowdsec-Mini.py
   ```
   
## Exemple d'Utilisation

1. **Lancement du script d'installation (Install.sh)** :
   ```bash
   ./install_script.sh
   ```
   ![Capture du lancement du script](path/to/your/image.png)

2. **Exécuter le script Python** :
   ```bash
   python3 crowdsec_mini.py
   ```
   ![Capture du script en cours d'exécution](path/to/your/image.png)

3. **Simuler une attaque** :
   Montrez une attaque en exemple et les alertes générées par le script. Les alertes seront renvoyées dans le fichier `alerts.log`.

## Version

**Version 1.1**

## Auteurs

- **Kylian** & **Nathan**
---
