def clear_alert_files():
    file_names = ['cpu_alerts.txt', 'ram_alerts.txt', 'ip_alerts.txt', 'root_alerts.txt', 'proc_status_alerts.txt']

    for file_name in file_names:
        with open(file_name, 'w') as file:
            file.truncate(0)
    print("Les fichiers ont été vidés avec succès.")

if __name__ == "__main__":
    clear_alert_files()
