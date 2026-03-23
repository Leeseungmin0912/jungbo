import socket
import requests
import threading
import ipaddress
import time
import datetime
import tkinter as tk
import hashlib
import re
import os
import webbrowser
import sys

from concurrent.futures import ThreadPoolExecutor
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

CURRENT_VERSION = "1.6"

# ------------------------
# UPDATE CHECK
# ------------------------
def check_update():
    try:
        url = "https://raw.githubusercontent.com/Leeseungmin0912/jungbo/main/version.txt"
        exe_url = "https://raw.githubusercontent.com/Leeseungmin0912/jungbo/main/Tool.exe"

        latest = requests.get(url, timeout=5).text.strip()

        if latest != CURRENT_VERSION:
            if messagebox.askyesno("Update Available", f"New version ({latest}) available. Update?"):
                
                log("Downloading update...")

                r = requests.get(exe_url)

                # exe 실행 환경 대응
                if getattr(sys, 'frozen', False):
                    current_dir = os.path.dirname(sys.executable)
                else:
                    current_dir = os.path.dirname(os.path.abspath(__file__))

                new_file = os.path.join(current_dir, "Tool_new.exe")

                with open(new_file, "wb") as f:
                    f.write(r.content)

                log(f"Saved to: {new_file}")

                updater_path = os.path.join(current_dir, "updater.exe")

                if os.path.exists(updater_path):
                    log("Starting updater...")
                    os.startfile(updater_path)
                else:
                    log("Updater not found!", "error")

                root.destroy()

    except Exception as e:
        log(f"Update Error: {e}", "error")


# ------------------------
# PORT SCANNER
# ------------------------
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "ISAKMP",
    587: "SMTP (Submission)",
    636: "LDAPS",
    989: "FTPS",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2181: "Zookeeper",
    2222: "DirectAdmin",
    2375: "Docker",
    2376: "Docker SSL",
    2483: "Oracle SSL",
    2484: "Oracle SSL",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    4444: "Metasploit",
    4567: "Ruby",
    5000: "Flask",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM SSL",
    6000: "X11",
    6379: "Redis",
    6667: "IRC",
    7001: "WebLogic",
    7002: "WebLogic SSL",
    8000: "HTTP Alt",
    8008: "HTTP Alt",
    8080: "HTTP Proxy",
    8081: "HTTP Alt",
    8086: "InfluxDB",
    8087: "SimplifyMedia",
    8088: "HTTP Alt",
    8090: "HTTP Alt",
    8443: "HTTPS Alt",
    9000: "SonarQube",
    9042: "Cassandra",
    9092: "Kafka",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9418: "Git",
    9999: "Debug",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB"
}

DANGEROUS_PORTS = {
    21: "FTP - 암호화 안됨",
    23: "Telnet - 평문 통신",
    445: "SMB - 랜섬웨어 위험",
    3389: "RDP - 브루트포스 공격 위험"
}

scanned_ports = 0
total_ports = 0
open_port_count = 0
start_time = 0
stop_scan = False


def log(msg, tag=None):
    now = datetime.datetime.now()
    time_str = now.strftime("%H:%M:%S")
    result_box.insert(tk.END, f"[{time_str}] {msg}\n", tag)
    result_box.see(tk.END)


def get_service(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"


def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.1\r\nHost:test\r\n\r\n")
        banner = s.recv(1024).decode().strip().split("\n")[0]
        s.close()
        return banner
    except:
        return None

def analyze_banner(banner):
    if not banner:
        return ""

    banner = banner.lower()

    if "apache" in banner:
        return "웹 서버: Apache"
    elif "nginx" in banner:
        return "웹 서버: Nginx"
    elif "openssh" in banner:
        return "SSH 서버 감지"
    elif "mysql" in banner:
        return "DB: MySQL"
    elif "iis" in banner:
        return "웹 서버: IIS"
    else:
        return ""


def scan_ports():
    global scanned_ports, total_ports, open_port_count, start_time, stop_scan

    stop_scan = False
    target = ip_entry.get()

    try:
        ipaddress.ip_address(target)
    except:
        log("Invalid IP Address", "error")
        return

    start_port = int(start_entry.get())
    end_port = int(end_entry.get())

    scanned_ports = 0
    open_port_count = 0
    total_ports = end_port - start_port + 1
    start_time = time.time()

    result_box.delete(1.0, tk.END)
    log(f"Scanning {target}...")

    def scan(port):
        global scanned_ports, open_port_count

        if stop_scan:
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))

            if result == 0:
                service = get_service(port)
                open_port_count += 1
                
                risk = DANGEROUS_PORTS.get(port, "")
                msg = f"Port {port} OPEN ({service})"

                if risk:
                    msg += f" ⚠ {risk}"

                root.after(0, lambda m=msg: log(m, "open"))

                banner = banner_grab(target, port)

                if banner:
                    root.after(0, lambda b=banner: (f"Banner -> {b}"))

                    analysis = analyze_banner(banner)
                    if analysis:
                        root.after(0, lambda a=analysis: log(f"분석 -> {a}"))

            s.close()
        except:
            pass

        scanned_ports += 1

    def run():
        with ThreadPoolExecutor(max_workers=200) as executor:
            for port in range(start_port, end_port + 1):
                if stop_scan:
                    break
                executor.submit(scan, port)

    threading.Thread(target=run).start()
    update_progress()


def update_progress():
    if total_ports == 0:
        return

    percent = int((scanned_ports / total_ports) * 100)
    progress["value"] = percent
    progress_label.config(text=f"Progress: {percent}%")

    if scanned_ports < total_ports and not stop_scan:
        root.after(200, update_progress)
    else:
        finish_time = round(time.time() - start_time, 2)
        log("Scan Finished")
        log(f"Open Ports: {open_port_count}")
        log(f"Time: {finish_time}s")


def stop():
    global stop_scan
    stop_scan = True
    log("Scan Stopped", "error")


# ------------------------
# WEB SCANNER
# ------------------------
def scan_header():
    url = url_entry.get()
    if not url.startswith("http"):
        url = "http://" + url

    try:
        r = requests.get(url)
        log("Header Scan:")
        for h in r.headers:
            log(f"{h}: {r.headers[h]}")
    except:
        log("Header Scan Failed", "error")


def vulnerability_scan():
    url = url_entry.get()
    if not url.startswith("http"):
        url = "http://" + url

    log("Checking Security Headers...")

    try:
        r = requests.get(url)
        headers = r.headers

        security_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for h in security_headers:
            if h in headers:
                log(f"{h}: OK")
            else:
                log(f"{h}: MISSING", "error")

    except:
        log("Scan Failed", "error")


def dir_bruteforce():
    url = url_entry.get()
    if not url.startswith("http"):
        url = "http://" + url

    wordlist = ["admin","login","backup","test","dashboard","config"]

    log("Starting Directory Scan...")

    for w in wordlist:
        test_url = f"{url}/{w}"
        try:
            r = requests.get(test_url, timeout=2)
            if r.status_code == 200:
                log(f"FOUND: {test_url}", "open")
        except:
            pass


def sqli_test():
    url = url_entry.get()
    if not url.startswith("http"):
        url = "http://" + url

    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"

    log("Testing SQL Injection...")

    try:
        r = requests.get(test_url)
        if "error" in r.text.lower():
            log("Possible SQL Injection Detected!", "error")
        else:
            log("No SQLi detected")
    except:
        log("SQL Test Failed", "error")


# ------------------------
# IP INFO
# ------------------------
def analyze_ip(data):
    isp = data.get("isp", "").lower()
    country = data.get("country", "").lower()

    # 서버 / 클라우드 판단
    if any(x in isp for x in ["amazon", "aws", "google", "cloud", "azure", "digitalocean", "vultr"]):
        ip_type = "서버"
        risk = "MEDIUM"
    
    # 개인 회선
    elif any(x in isp for x in ["kt", "sk", "lg", "telecom"]):
        ip_type = "개인 사용자"
        risk = "LOW"
    
    else:
        ip_type = "알 수 없음"
        risk = "MEDIUM"

    # 위험 국가 (간단 예시)
    if country in ["russia", "china", "iran"]:
        risk = "HIGH ⚠"

    return ip_type, risk

def ip_lookup():
    ip = ip_entry.get()

    try:
        data = requests.get(f"http://ip-api.com/json/{ip}").json()
        log(f"Country: {data['country']}")
        log(f"ISP: {data['isp']}")
        log(f"City: {data['city']}")
    except:
        log("IP Lookup Failed", "error")


# ------------------------
# PASSWORD / HASH
# ------------------------
def check_password():
    pw = password_entry.get()
    score = 0

    if len(pw)>=8: score+=1
    if re.search("[A-Z]",pw): score+=1
    if re.search("[a-z]",pw): score+=1
    if re.search("[0-9]",pw): score+=1
    if re.search("[!@#$%^&*()]",pw): score+=1

    if score<=2:
        log("Weak", "error")
    elif score<=4:
        log("Medium")
    else:
        log("Strong", "open")


def generate_hash():
    text = hash_entry.get()
    log("MD5: "+hashlib.md5(text.encode()).hexdigest())
    log("SHA256: "+hashlib.sha256(text.encode()).hexdigest())


# ------------------------
# SAVE / CLEAR
# ------------------------
def save():
    file = filedialog.asksaveasfilename(defaultextension=".txt")
    if file:
        with open(file,"w",encoding="utf-8") as f:
            f.write(result_box.get(1.0,tk.END))


def clear_log():
    result_box.delete(1.0,tk.END)


# ------------------------
# UI
# ------------------------
root = tk.Tk()
root.title(f"Cyber Security Toolkit v{CURRENT_VERSION}")
root.geometry("900x750")
root.configure(bg="black")

root.after(2000, check_update)

tk.Label(root,text="Cyber Security Toolkit",
font=("Consolas",20,"bold"),fg="#00ff00",bg="black").pack(pady=10)

# PORT
frame1 = tk.LabelFrame(root,text="Port Scanner",bg="black",fg="#00ff00")
frame1.pack(fill="x",padx=10,pady=5)

ip_entry = tk.Entry(frame1,bg="black",fg="#00ff00")
ip_entry.grid(row=0,column=1)

start_entry = tk.Entry(frame1,width=6,bg="black",fg="#00ff00")
start_entry.grid(row=0,column=3)

end_entry = tk.Entry(frame1,width=6,bg="black",fg="#00ff00")
end_entry.grid(row=0,column=5)

tk.Label(frame1,text="IP",bg="black",fg="#00ff00").grid(row=0,column=0)
tk.Label(frame1,text="Start",bg="black",fg="#00ff00").grid(row=0,column=2)
tk.Label(frame1,text="End",bg="black",fg="#00ff00").grid(row=0,column=4)

tk.Button(frame1,text="SCAN",command=scan_ports).grid(row=0,column=6)
tk.Button(frame1,text="STOP",command=stop).grid(row=0,column=7)
tk.Button(frame1,text="IP INFO",command=ip_lookup).grid(row=0,column=8)

# WEB
frame2 = tk.LabelFrame(root,text="Web Scanner",bg="black",fg="#00ff00")
frame2.pack(fill="x",padx=10,pady=5)

url_entry = tk.Entry(frame2,width=40,bg="black",fg="#00ff00")
url_entry.grid(row=0,column=1)

tk.Label(frame2,text="URL",bg="black",fg="#00ff00").grid(row=0,column=0)

tk.Button(frame2,text="HEADER",command=scan_header).grid(row=0,column=2)
tk.Button(frame2,text="VULN",command=vulnerability_scan).grid(row=0,column=3)
tk.Button(frame2,text="DIR",command=dir_bruteforce).grid(row=0,column=4)
tk.Button(frame2,text="SQLi",command=sqli_test).grid(row=0,column=5)

# PASSWORD
frame3 = tk.LabelFrame(root,text="Password",bg="black",fg="#00ff00")
frame3.pack(fill="x",padx=10,pady=5)

password_entry = tk.Entry(frame3,bg="black",fg="#00ff00")
password_entry.pack(side="left")

tk.Button(frame3,text="CHECK",command=check_password).pack(side="left")

# HASH
frame4 = tk.LabelFrame(root,text="Hash",bg="black",fg="#00ff00")
frame4.pack(fill="x",padx=10,pady=5)

hash_entry = tk.Entry(frame4,bg="black",fg="#00ff00")
hash_entry.pack(side="left")

tk.Button(frame4,text="HASH",command=generate_hash).pack(side="left")

# PROGRESS
progress_label = tk.Label(root,text="Progress: 0%",bg="black",fg="#00ff00")
progress_label.pack()

progress = ttk.Progressbar(root,length=400)
progress.pack(pady=5)

# RESULT
result_box = scrolledtext.ScrolledText(root,bg="black",fg="#00ff00")
result_box.pack(expand=True,fill="both")

result_box.tag_config("open",foreground="#00ff00")
result_box.tag_config("error",foreground="red")

# BOTTOM
bottom = tk.Frame(root,bg="black")
bottom.pack(fill="x")

tk.Button(bottom,text="SAVE",command=save).pack(side="left")
tk.Button(bottom,text="CLEAR",command=clear_log).pack(side="left")

root.mainloop()
