import psutil
import time

def get_expected_processes():
    # Fonction pour récupérer la liste des processus attendus et légitimes
    return ['sshd', 'cron', 'apache2']

def detect_suspicious_processes(known_pids):
    expected_processes = get_expected_processes()
    # Récupérer tous les processus en cours d'exécution
    all_processes = psutil.process_iter()
    # Liste pour stocker les nouveaux processus suspects
    suspicious_processes = []

    for proc in all_processes:
        try:
            # Récupérer les informations sur le processus
            proc_info = proc.as_dict(attrs=['pid', 'name', 'username'])
            pid = proc_info['pid']
            # Vérifier si le processus est exécuté par root et est un nouveau processus
            if proc_info['username'] == 'root' and proc_info['name'] not in expected_processes:
                if pid not in known_pids:
                    suspicious_processes.append(proc_info)
                    known_pids.add(pid)  # Ajouter le PID à l'ensemble des PIDs connus
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Ignorer les erreurs telles que les processus qui se sont terminés entre la récupération
            # et l'inspection de leurs informations
            pass

    return suspicious_processes

def detect_suspicious_connections():
    # Processus connus à ignorer
    known_processes = ['chrome', 'firefox', 'edge', 'wget', 'curl', 'ssh', 'sshd']
    # Ports souvent utilisés de manière malveillante ou pour des transferts non autorisés
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
                            suspicious_connections.append({
                                'process_name': proc.name(),
                                'ip': ip,
                                'port': port,
                                'pid': proc.pid
                            })
                    except psutil.NoSuchProcess:
                        continue

    return suspicious_connections

def main():
    known_pids = set()  # Ensemble pour stocker les PIDs connus

    print("Initial check for suspicious root processes:")
    suspicious_processes = detect_suspicious_processes(known_pids)
    if suspicious_processes:
        for proc in suspicious_processes:
            print(f"PID: {proc['pid']}, Nom: {proc['name']}")
    
    while True:
        suspicious_processes = detect_suspicious_processes(known_pids)
        if suspicious_processes:
            print("Nouveaux processus inconnus ou suspects exécutés en tant que root :")
            for proc in suspicious_processes:
                print(f"PID: {proc['pid']}, Nom: {proc['name']}")
        
        suspicious_connections = detect_suspicious_connections()
        if suspicious_connections:
            print("Suspicious network connections detected:")
            for conn in suspicious_connections:
                print(f"Suspicious process: {conn['process_name']} with unusual network connection to {conn['ip']}:{conn['port']} (PID: {conn['pid']})")
        
        time.sleep(10)  # Pause de 10 secondes entre chaque analyse

if __name__ == "__main__":
    main()
