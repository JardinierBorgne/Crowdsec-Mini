import psutil
import subprocess
import time
from datetime import datetime

CPU_THRESHOLD = 80  # Seuil d'utilisation CPU à partir duquel une alerte est déclenchée
RAM_THRESHOLD = 70  # Seuil d'utilisation de la RAM à partir duquel une alerte est déclenchée

def get_expected_processes():
    """
    Renvoie une liste des processus attendus.
    """
    return ['sshd', 'cron', 'apache2']

def check_high_cpu_usage(alert_file):
    """
    Vérifie les processus utilisant un CPU élevé et écrit une alerte dans le fichier spécifié.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            cpu_usage = proc.info['cpu_percent']
            if cpu_usage is None:
                continue
            cpu_usage_rounded = round(cpu_usage, 2)  # Arrondir à 2 chiffres après la virgule
            if cpu_usage_rounded > CPU_THRESHOLD:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_file.write(f"{current_time} - Alerte : Le processus {proc.info['name']} (PID : {proc.info['pid']}) utilise {cpu_usage_rounded}% du CPU !\n")
                alert_file.flush()  # Forcer l'écriture dans le fichier
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def check_high_ram_usage(alert_file):
    """
    Vérifie les processus utilisant une RAM élevée et écrit une alerte dans le fichier spécifié.
    """
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            ram_usage = proc.info['memory_percent']
            if ram_usage is None:
                continue
            ram_usage_rounded = round(ram_usage, 2)  # Arrondir à 2 chiffres après la virgule
            if ram_usage_rounded > RAM_THRESHOLD:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_file.write(f"{current_time} - Alerte : Le processus {proc.info['name']} (PID : {proc.info['pid']}) utilise {ram_usage_rounded}% de la RAM !\n")
                alert_file.flush()  # Forcer l'écriture dans le fichier
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def detect_suspicious_processes(known_pids, alert_file):
    """
    Détecte les processus suspects et écrit une alerte dans le fichier spécifié.
    """
    expected_processes = get_expected_processes()
    all_processes = psutil.process_iter()
    suspicious_processes = []

    for proc in all_processes:
        try:
            proc_info = proc.as_dict(attrs=['pid', 'name', 'username'])
            pid = proc_info['pid']
            if proc_info['username'] == 'root' and proc_info['name'] not in expected_processes:
                if pid not in known_pids:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    suspicious_processes.append(proc_info)
                    known_pids.add(pid)
                    alert_file.write(f"{current_time} - Alerte : Processus suspect détecté - PID : {pid}, Nom : {proc_info['name']}\n")
                    alert_file.flush()  # Forcer l'écriture dans le fichier
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return suspicious_processes

def detect_suspicious_connections(alert_file):
    """
    Détecte les connexions réseau suspectes et écrit une alerte dans le fichier spécifié.
    """
    known_processes = ['chrome', 'firefox', 'edge', 'wget', 'curl', 'ssh', 'sshd']
    suspicious_ports = [21, 20, 69, 3389, 4444, 5555, 6666, 8888]

    suspicious_connections = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            port = conn.raddr.port
            if not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.'):
                if port in suspicious_ports:
                    try:
                        proc = psutil.Process(conn.pid)
                        if proc.name() not in known_processes:
                            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            alert_file.write(f"{current_time} - Connexion réseau suspecte détectée - Processus : {proc.name()}, IP : {ip}, Port : {port}, PID : {proc.pid}\n")
                            alert_file.flush()  # Forcer l'écriture dans le fichier
                            suspicious_connections.append({
                                'process_name': proc.name(),
                                'ip': ip,
                                'port': port,
                                'pid': proc.pid
                            })
                    except psutil.NoSuchProcess:
                        continue

    return suspicious_connections

def is_service_present(service_name):
    """
    Vérifie si un service spécifié est présent sur le système.
    """
    try:
        result = subprocess.run(['systemctl', 'list-unit-files', service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip()
        return service_name in output
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Erreur lors de la vérification de la présence du service {service_name} : {e}\n")
        return False

def is_rsyslog_running():
    """
    Vérifie si le service rsyslog est en cours d'exécution.
    """
    if not is_service_present('rsyslog.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Le service rsyslog n'est pas présent sur le système.\n")
        return
    for process in psutil.process_iter(['name']):
        if process.info['name'] == 'rsyslogd':
            return True
    with open('proc_status_alerts.txt', 'a') as file:
        file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alerte : rsyslog n'est pas en cours d'exécution !\n")

def check_auditd_status():
    """
    Vérifie l'état du service auditd.
    """
    if not is_service_present('auditd.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Le service auditd n'est pas présent sur le système.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'auditd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alerte : le service auditd n'est pas actif !\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Erreur lors de la vérification de l'état d'auditd : {e}\n")

def check_cron_status():
    """
    Vérifie l'état du service cron.
    """
    if not is_service_present('cron.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Le service cron n'est pas présent sur le système.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'cron'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alerte : le service cron n'est pas actif !\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Erreur lors de la vérification de l'état de cron : {e}\n")

def check_iptables_status():
    """
    Vérifie l'état du service iptables.
    """
    if not is_service_present('iptables.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Le service iptables n'est pas présent sur le système.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'iptables'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alerte : le service iptables n'est pas actif !\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Erreur lors de la vérification de l'état d'iptables : {e}\n")

def main():
    """
    Fonction principale du script.
    """
    known_pids = set()

    print("--------------------")
    print("Script démarré.")
    print("--------------------")

    try:
        while True:
            with open('cpu_alerts.txt', 'a') as cpu_alert_file, \
                    open('ram_alerts.txt', 'a') as ram_alert_file, \
                    open('ip_alerts.txt', 'a') as ip_alert_file, \
                    open('root_alerts.txt', 'a') as root_alert_file:

                check_high_cpu_usage(cpu_alert_file)
                check_high_ram_usage(ram_alert_file)

                detect_suspicious_processes(known_pids, root_alert_file)
                detect_suspicious_connections(ip_alert_file)

            is_rsyslog_running()
            check_auditd_status()
            check_cron_status()
            check_iptables_status()

            time.sleep(10)

    except KeyboardInterrupt:
        print("--------------------")
        print("Script arrêté.")
        print("--------------------")
        pass

if __name__ == "__main__":
    main()
