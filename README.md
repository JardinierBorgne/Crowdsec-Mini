---

# Crowdsec-Mini

### Surveillance et Détection de Processus en Cybersécurité

Dans le contexte actuel de la cybersécurité, il est essentiel de surveiller en permanence les activités des processus sur les systèmes informatiques. Les cyberattaques deviennent de plus en plus sophistiquées, exploitant souvent des processus légitimes pour mener des actions malveillantes. Pour répondre à ce besoin, nous avons développé un script Python capable de surveiller en continu la liste des processus, de détecter des patterns caractéristiques d'une attaque et d'alerter l'utilisateur en cas de détection de comportements suspects.

## Pré-requis

Pour pouvoir exécuter le script sans soucis, assurez-vous d'avoir les éléments suivants :

- **Un accès internet**
- **Une debian (12/Bookworm de préférence)**
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
   ![installsh](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/57b3ff15-a998-4676-a605-0ad4ae4890f8)


3. **Exécuter le script Python** :
   ```bash
   python3 crowdsec_mini.py
   ```
   ![image](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/5326e66c-1f3e-46a5-8ac1-34944c8ea2fd)

   Différents fichiers où sont renvoyées les alertes sont dans le dossier (ce sont les différents.txt):
   ![image](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/beb1d041-4e24-42dd-b7df-72e29dfa4c56)


5. **Simuler une attaque** :
   L'un des scripts créés fait volontairement monter le CPU à 100% :
   ![image](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/50b23423-c6fc-4154-b420-72550b072827)
   ![image](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/bdb253a1-7332-4066-b282-2689173a5562)
   
   Autres exemples avec une connexion TCP sur un port et une IP Public :
   
![image](https://github.com/JardinierBorgne/Crowdsec-Mini/assets/170959069/3d6f15a6-175b-449e-a411-eeed05218923)

## Autres infos

Le script Flush_Files.py permet de vider les alertes générées dans les fichiers : 
```bash
   python3 Flush_Files.py
   ```

## Version

**Version 1.1**

## Auteurs

- **Kylian** & **Nathan**
---
