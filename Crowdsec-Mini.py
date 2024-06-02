import psutil
import subprocess
import time
from datetime import datetime

CPU_THRESHOLD = 80  # CPU usage threshold at which an alert is triggered
RAM_THRESHOLD = 70  # RAM usage threshold at which an alert is triggered

def get_expected_processes():
    # Returns a list of expected processes.
    return ['sshd', 'cron', 'apache2']

def check_high_cpu_usage(alert_file):
    # Checks for processes using high CPU and writes an alert to the specified file.
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            cpu_usage = proc.info['cpu_percent']
            if cpu_usage is None:
                continue
            cpu_usage_rounded = round(cpu_usage, 2)  # Round to 2 digits after the decimal point
            if cpu_usage_rounded > CPU_THRESHOLD:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_file.write(f"{current_time} - Alert : The process {proc.info['name']} (PID : {proc.info['pid']}) used {cpu_usage_rounded}% of CPU !\n")
                alert_file.flush()  # Force write to file
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def check_high_ram_usage(alert_file):
    # Checks processes using high RAM and writes an alert to the specified file.
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            ram_usage = proc.info['memory_percent']
            if ram_usage is None:
                continue
            ram_usage_rounded = round(ram_usage, 2)  # Round to 2 digits after the decimal point
            if ram_usage_rounded > RAM_THRESHOLD:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_file.write(f"{current_time} - Alert: The process {proc.info['name']} (PID : {proc.info['pid']}) used {ram_usage_rounded}% of RAM !\n")
                alert_file.flush()  # Force write to file
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def detect_suspicious_processes(known_pids, alert_file):
    # Detects suspicious processes and writes an alert to the specified file.
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
                    alert_file.write(f"{current_time} - Alert: Suspicious process detected - PID : {pid}, Name : {proc_info['name']}\n")
                    alert_file.flush()  # Force write to file
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return suspicious_processes

def detect_suspicious_connections(alert_file):
    # Detects suspicious network connections and writes an alert to the specified file.
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
                            alert_file.write(f"{current_time} - Suspicious Network Connection Detected - Process: {proc.name()}, IP : {ip}, Port : {port}, PID : {proc.pid}\n")
                            alert_file.flush()  # Force write to file
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
    #Checks if a specified service is present on the system.
    try:
        result = subprocess.run(['systemctl', 'list-unit-files', service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip()
        return service_name in output
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error checking for service presence {service_name} : {e}\n")
        return False

def is_rsyslog_running():
    #Checks if the rsyslog service is running.

    if not is_service_present('rsyslog.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - The rsyslog service is not present on the system.\n")
        return
    for process in psutil.process_iter(['name']):
        if process.info['name'] == 'rsyslogd':
            return True
    with open('proc_status_alerts.txt', 'a') as file:
        file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alert: rsyslog is not running!\n")

def check_auditd_status():
    # Checks the status of the auditd service.

    if not is_service_present('auditd.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - The auditd service is not present on the system.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'auditd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alert: the auditd service is not active!\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error checking audit status: {e}\n")

def check_cron_status():
    #Checks the status of the cron service.
    if not is_service_present('cron.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - The cron service is not present on the system.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'cron'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alert: the cron service is not active!\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error checking cron status: {e}\n")

def check_iptables_status():
    # Checks the status of the iptables service.
    if not is_service_present('iptables.service'):
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - The iptables service is not present on the system.\n")
        return
    try:
        result = subprocess.run(['systemctl', 'is-active', 'iptables'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = result.stdout.decode().strip()
        if status != 'active':
            with open('proc_status_alerts.txt', 'a') as file:
                file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Alert: the iptables service is not active!\n")
    except Exception as e:
        with open('proc_status_alerts.txt', 'a') as file:
            file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error checking iptables status: {e}\n")

def main():
# Main function of the script
    known_pids = set()

    print("--------------------")
    print("Script running.")
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
        print("Script stopped.")
        print("--------------------")
        pass

if __name__ == "__main__":
    main()
