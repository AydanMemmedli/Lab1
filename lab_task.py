import re
import json
import csv

# Giriş faylı
log_file = "server_logs.txt"

# JSON və CSV faylları
failed_logins_file = "failed_logins.json"
threat_ips_file = "threat_ips.json"
combined_file = "combined_security_data.json"
log_analysis_txt = "log_analysis.txt"
log_analysis_csv = "log_analysis.csv"

# Təhdid IP-ləri
threat_ips = {
    "192.168.1.11": "Suspicious activity detected",
    "10.0.0.50": "Known malicious IP",
    "172.16.0.5": "Brute-force attack reported"
}

# Log məlumatlarını oxuyun və analiz edin
failed_logins = []
matched_threats = []

with open(log_file, "r") as file:
    for line in file:
        match = re.search(r"(\d+\.\d+\.\d+\.\d+) .*? \[(.*?)\] \"(.*?)\" (\d+) (\d+)", line)
        if match:
            ip, date, method, status, size = match.groups()
            if status == "401":  # Uğursuz girişlər
                failed_logins.append({"ip": ip, "date": date, "method": method})
            if ip in threat_ips:  # Təhdid IP-ləri
                matched_threats.append({"ip": ip, "description": threat_ips[ip]})

# JSON faylları yaradın
with open(failed_logins_file, "w") as f:
    json.dump(failed_logins, f, indent=4)

with open(threat_ips_file, "w") as f:
    json.dump(matched_threats, f, indent=4)

# Birgə məlumatları saxlayın
combined_data = {"failed_logins": failed_logins, "threat_ips": matched_threats}
with open(combined_file, "w") as f:
    json.dump(combined_data, f, indent=4)

# TXT və CSV faylları yaradın
with open(log_analysis_txt, "w") as f:
    for login in failed_logins:
        f.write(f"IP: {login['ip']}, Date: {login['date']}, Method: {login['method']}\n")

with open(log_analysis_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Date", "Method"])
    for login in failed_logins:
        writer.writerow([login["ip"], login["date"], login["method"]])

print("Fayllar uğurla yaradıldı!")
