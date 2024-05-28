import psutil
import time

CPU_THRESHOLD = 80

def get_expected_processes():
    return ['sshd', 'cron', 'apache2']

def check_high_cpu_usage(alert_file):
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            cpu_usage = proc.info['cpu_percent']
            if cpu_usage is None:
                continue
            if cpu_usage > CPU_THRESHOLD:
                alert_file.write(f"Alert: Process {proc.info['name']} (PID: {proc.info['pid']}) is using {cpu_usage}% CPU!\n")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def detect_suspicious_processes(known_pids, alert_file):
    expected_processes = get_expected_processes()
    all_processes = psutil.process_iter()
    suspicious_processes = []

    for proc in all_processes:
        try:
            proc_info = proc.as_dict(attrs=['pid', 'name', 'username'])
            pid = proc_info['pid']
            if proc_info['username'] == 'root' and proc_info['name'] not in expected_processes:
                if pid not in known_pids:
                    suspicious_processes.append(proc_info)
                    known_pids.add(pid)
                    alert_file.write(f"Alert: Suspicious process detected - PID: {pid}, Name: {proc_info['name']}\n")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return suspicious_processes

def detect_suspicious_connections(alert_file):
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
                            alert_file.write(f"Suspicious network connection detected - Process: {proc.name()}, IP: {ip}, Port: {port}, PID: {proc.pid}\n")
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
    known_pids = set()

    # Open file for alerts related to suspicious processes
    with open('suspicious_processes_alerts.txt', 'w') as process_alert_file:
        print("Initial check for suspicious root processes:")
        suspicious_processes = detect_suspicious_processes(known_pids, process_alert_file)
        if suspicious_processes:
            for proc in suspicious_processes:
                print(f"PID: {proc['pid']}, Name: {proc['name']}")
    
    # Open file for general alerts
    with open('general_alerts.txt', 'w') as general_alert_file:
        while True:
            check_high_cpu_usage(general_alert_file)

            suspicious_processes = detect_suspicious_processes(known_pids, general_alert_file)
            if suspicious_processes:
                print("New unknown or suspicious processes running as root:")
                for proc in suspicious_processes:
                    print(f"PID: {proc['pid']}, Name: {proc['name']}")

            suspicious_connections = detect_suspicious_connections(general_alert_file)
            if suspicious_connections:
                print("Suspicious network connections detected:")
                for conn in suspicious_connections:
                    print(f"Suspicious process: {conn['process_name']} with unusual network connection to {conn['ip']}:{conn['port']} (PID: {conn['pid']})")

            time.sleep(10)

if __name__ == "__main__":
    main()
