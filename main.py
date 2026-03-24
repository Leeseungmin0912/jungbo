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
import sys
import json
import html

from concurrent.futures import ThreadPoolExecutor
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

CURRENT_VERSION = "1.8"

# ------------------------
# GLOBAL STATE
# ------------------------
scanned_ports = 0
total_ports = 0
open_port_count = 0
start_time = 0
stop_scan = False

state_lock = threading.Lock()

scan_results = []
scan_target = ""
scan_start_port = 0
scan_end_port = 0
latest_report_path = None

ip_info_data = None
ip_risk_score = 0
ip_risk_level = "UNKNOWN"
ip_type = "알 수 없음"
ip_suspicious = False

port_risk_score = 0
scan_suspicious = False

SNAPSHOT_FILE = "scan_history.json"

# ------------------------
# PORT DATA
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

# description, points
DANGEROUS_PORTS = {
    21: ("FTP - 암호화 안됨", 20),
    23: ("Telnet - 평문 통신", 30),
    445: ("SMB - 랜섬웨어 / 취약점 악용 위험", 30),
    3389: ("RDP - 브루트포스 공격 위험", 25),
    2375: ("Docker - 인증 없이 노출되면 위험", 30),
    5900: ("VNC - 원격 접속 노출 주의", 20),
    6379: ("Redis - 외부 노출 주의", 25),
    9200: ("Elasticsearch - 데이터 노출 주의", 25),
    27017: ("MongoDB - 외부 노출 주의", 25),
}

# ------------------------
# UTILS
# ------------------------
def get_current_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def log(msg, tag=None):
    time_str = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{time_str}] {msg}\n"

    if "result_box" in globals():
        result_box.insert(tk.END, line, tag)
        result_box.see(tk.END)
    else:
        print(line, end="")

def get_total_risk_info():
    ip_score = min(ip_risk_score, 100)
    port_score = min(port_risk_score, 100)
    total_score = ip_score + port_score
    max_score = 200

    if total_score >= 90:
        final_level = "HIGH ⚠"
        color = "red"
    elif total_score >= 40:
        final_level = "MEDIUM"
        color = "#ffd700"
    else:
        final_level = "LOW"
        color = "#00ff00"

    return {
        "ip_score": ip_score,
        "ip_max": 100,
        "port_score": port_score,
        "port_max": 100,
        "total_score": total_score,
        "total_max": max_score,
        "level": final_level,
        "color": color,
        "suspicious": (ip_suspicious or scan_suspicious),
    }

def update_dashboard():
    risk_info = get_total_risk_info()

    target_value.config(text=scan_target if scan_target else "-")
    open_ports_value.config(text=str(open_port_count))
    risk_score_value.config(text=f"{risk_info['total_score']} / {risk_info['total_max']}")
    suspicious_value.config(text="YES" if risk_info["suspicious"] else "NO")
    final_risk_value.config(text=risk_info["level"], fg=risk_info["color"], bg="black")

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

        if port in [80, 8080, 8081, 8000, 8008, 8088, 443, 8443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost:test\r\n\r\n")
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip().split("\n")[0]
        s.close()
        return banner if banner else None
    except:
        return None

def analyze_banner(banner):
    if not banner:
        return ""

    b = banner.lower()

    if "apache" in b:
        return "웹 서버: Apache"
    elif "nginx" in b:
        return "웹 서버: Nginx"
    elif "openssh" in b:
        return "SSH 서버 감지"
    elif "mysql" in b:
        return "DB: MySQL"
    elif "iis" in b:
        return "웹 서버: IIS"
    elif "postgresql" in b:
        return "DB: PostgreSQL"
    else:
        return ""

def analyze_port_risk(port):
    if port in DANGEROUS_PORTS:
        desc, points = DANGEROUS_PORTS[port]
        return desc, points, "HIGH"
    elif port in [22, 80, 443, 53, 3306, 5432]:
        return "노출 서비스 점검 필요", 5, "MEDIUM"
    else:
        return "", 0, "LOW"

def load_snapshots():
    path = os.path.join(get_current_dir(), SNAPSHOT_FILE)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_snapshot(target, summary):
    data = load_snapshots()
    data[target] = summary
    path = os.path.join(get_current_dir(), SNAPSHOT_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def compare_with_previous(target, current_summary):
    data = load_snapshots()
    previous = data.get(target)

    if not previous:
        log("이전 스캔 결과가 없어 비교할 수 없습니다.")
        return

    prev_ports = set(previous.get("open_ports", []))
    curr_ports = set(current_summary.get("open_ports", []))

    added = sorted(list(curr_ports - prev_ports))
    removed = sorted(list(prev_ports - curr_ports))

    log("")
    log("=== 이전 결과와 비교 ===")

    if added:
        log(f"새로 열린 포트: {', '.join(map(str, added))}", "error")
    else:
        log("새로 열린 포트: 없음")

    if removed:
        log(f"닫힌 포트: {', '.join(map(str, removed))}")
    else:
        log("닫힌 포트: 없음")

    prev_score = previous.get("port_risk_score", 0)
    curr_score = current_summary.get("port_risk_score", 0)
    diff = curr_score - prev_score

    if diff > 0:
        log(f"포트 위험 점수 변화: +{diff}", "error")
    elif diff < 0:
        log(f"포트 위험 점수 변화: {diff}", "open")
    else:
        log("포트 위험 점수 변화: 0")

def build_scan_summary():
    open_ports = sorted([item["port"] for item in scan_results])
    risky_ports = sorted([item["port"] for item in scan_results if item["risk_points"] > 0])

    risk_info = get_total_risk_info()

    return {
        "target": scan_target,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "range": f"{scan_start_port}-{scan_end_port}",
        "open_ports": open_ports,
        "risky_ports": risky_ports,
        "open_port_count": open_port_count,
        "port_risk_score": risk_info["port_score"],
        "ip_risk_score": risk_info["ip_score"],
        "total_risk_score": risk_info["total_score"],
        "ip_risk_level": ip_risk_level,
        "ip_type": ip_type,
        "ip_suspicious": ip_suspicious,
        "scan_suspicious": scan_suspicious,
        "final_risk_level": risk_info["level"],
    }

def get_default_report_filename():
    target_name = scan_target.replace(".", "_") if scan_target else "report"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"security_report_{target_name}_{timestamp}.html"

def generate_html_report(auto=False, report_path=None):
    global latest_report_path

    try:
        if not scan_target:
            log("보고서를 만들 스캔 결과가 없습니다.", "error")
            return False

        if not report_path:
            if auto:
                report_path = os.path.join(get_current_dir(), get_default_report_filename())
            else:
                report_path = filedialog.asksaveasfilename(
                    title="리포트 저장 위치 선택",
                    defaultextension=".html",
                    initialfile=get_default_report_filename(),
                    filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")]
                )
                if not report_path:
                    log("리포트 저장이 취소되었습니다.", "error")
                    return False

        risk_info = get_total_risk_info()
        total_score = risk_info["total_score"]
        max_score = risk_info["total_max"]
        final_level = risk_info["level"]

        if "HIGH" in final_level:
            final_class = "high"
        elif final_level == "MEDIUM":
            final_class = "medium"
        else:
            final_class = "low"

        rows = ""
        for item in sorted(scan_results, key=lambda x: x["port"]):
            rows += f"""
            <tr>
                <td>{item['port']}</td>
                <td>{html.escape(str(item['service']))}</td>
                <td>{item['risk_points']}</td>
                <td>{html.escape(str(item['risk_desc'])) if item['risk_desc'] else '-'}</td>
                <td>{html.escape(str(item['banner'])) if item['banner'] else '-'}</td>
                <td>{html.escape(str(item['banner_analysis'])) if item['banner_analysis'] else '-'}</td>
            </tr>
            """

        if ip_info_data:
            ip_rows = f"""
            <p><b>Country:</b> {html.escape(str(ip_info_data.get('country', '-')))}</p>
            <p><b>City:</b> {html.escape(str(ip_info_data.get('city', '-')))}</p>
            <p><b>ISP:</b> {html.escape(str(ip_info_data.get('isp', '-')))}</p>
            <p><b>Type:</b> {html.escape(str(ip_type))}</p>
            <p><b>IP Risk:</b> {html.escape(str(ip_risk_level))} ({risk_info['ip_score']} / 100)</p>
            """
        else:
            ip_rows = "<p>IP 조회 정보 없음</p>"

        suspicious_text = "YES" if risk_info["suspicious"] else "NO"

        html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0f1117;
    color: #e6edf3;
    margin: 30px;
}}
h1, h2 {{
    color: #58a6ff;
}}
.card {{
    background: #161b22;
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 20px;
    border: 1px solid #30363d;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    border: 1px solid #30363d;
    padding: 10px;
    text-align: left;
}}
th {{
    background: #21262d;
}}
.high {{ color: #ff6b6b; font-weight: bold; }}
.medium {{ color: #ffd166; font-weight: bold; }}
.low {{ color: #06d6a0; font-weight: bold; }}
</style>
</head>
<body>
<h1>Cyber Security Toolkit Report</h1>

<div class="card">
    <h2>기본 정보</h2>
    <p><b>Target:</b> {html.escape(str(scan_target))}</p>
    <p><b>Scan Time:</b> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><b>Port Range:</b> {scan_start_port} - {scan_end_port}</p>
    <p><b>Open Ports:</b> {open_port_count}</p>
    <p><b>Port Risk Score:</b> {risk_info['port_score']} / 100</p>
    <p><b>IP Risk Score:</b> {risk_info['ip_score']} / 100</p>
    <p><b>Total Risk Score:</b> {total_score} / {max_score}</p>
    <p><b>Suspicious:</b> {suspicious_text}</p>
    <p><b>Final Risk:</b> <span class="{final_class}">{html.escape(final_level)}</span></p>
</div>

<div class="card">
    <h2>IP 정보</h2>
    {ip_rows}
</div>

<div class="card">
    <h2>포트 분석 결과</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Risk Score</th>
            <th>Risk Description</th>
            <th>Banner</th>
            <th>Banner Analysis</th>
        </tr>
        {rows if rows else '<tr><td colspan="6">열린 포트 없음</td></tr>'}
    </table>
</div>

</body>
</html>
"""

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        latest_report_path = report_path

        if auto:
            log(f"자동 보고서 생성 완료: {report_path}", "open")
        else:
            log(f"보고서 생성 완료: {report_path}", "open")

        return True

    except Exception as e:
        log(f"보고서 생성 실패: {e}", "error")
        return False

def open_last_report():
    global latest_report_path

    try:
        if latest_report_path and os.path.exists(latest_report_path):
            os.startfile(latest_report_path)
            log(f"보고서를 성공적으로 열었습니다: {latest_report_path}", "open")
            return

        file_path = filedialog.askopenfilename(
            title="열 리포트 선택",
            filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")]
        )

        if not file_path:
            log("열 리포트 선택이 취소되었습니다.", "error")
            return

        latest_report_path = file_path
        os.startfile(latest_report_path)
        log(f"보고서를 성공적으로 열었습니다: {latest_report_path}", "open")

    except Exception as e:
        log(f"보고서 열기 실패: {e}", "error")

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
                r = requests.get(exe_url, timeout=15)

                current_dir = get_current_dir()
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
def scan_ports():
    global scanned_ports, total_ports, open_port_count, start_time, stop_scan
    global scan_results, scan_target, scan_start_port, scan_end_port
    global port_risk_score, scan_suspicious

    stop_scan = False
    target = ip_entry.get().strip()

    try:
        ipaddress.ip_address(target)
    except:
        log("Invalid IP Address", "error")
        return

    try:
        start_port_value = int(start_entry.get())
        end_port_value = int(end_entry.get())
    except:
        log("포트 범위를 숫자로 입력하세요.", "error")
        return

    if start_port_value < 1 or end_port_value > 65535 or start_port_value > end_port_value:
        log("포트 범위는 1 ~ 65535 사이여야 합니다.", "error")
        return

    scanned_ports = 0
    open_port_count = 0
    total_ports = end_port_value - start_port_value + 1
    start_time = time.time()

    scan_results = []
    scan_target = target
    scan_start_port = start_port_value
    scan_end_port = end_port_value
    port_risk_score = 0
    scan_suspicious = False

    progress["value"] = 0
    result_box.delete(1.0, tk.END)

    log(f"Scanning {target}...")
    update_dashboard()

    def scan(port):
        global scanned_ports, open_port_count, port_risk_score, scan_suspicious

        if stop_scan:
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))

            if result == 0:
                service = get_service(port)
                risk_desc, risk_points, risk_level = analyze_port_risk(port)
                banner = banner_grab(target, port)
                banner_analysis = analyze_banner(banner)

                with state_lock:
                    open_port_count += 1
                    port_risk_score += risk_points
                    if port_risk_score > 100:
                        port_risk_score = 100

                    if risk_points >= 20:
                        scan_suspicious = True

                    scan_results.append({
                        "port": port,
                        "service": service,
                        "risk_desc": risk_desc,
                        "risk_points": risk_points,
                        "risk_level": risk_level,
                        "banner": banner or "",
                        "banner_analysis": banner_analysis or ""
                    })

                msg = f"Port {port} OPEN ({service})"
                if risk_desc:
                    msg += f" ⚠ {risk_desc} (+{risk_points})"

                log_tag = "open" if risk_points == 0 else "error"
                root.after(0, lambda m=msg, t=log_tag: log(m, t))

                if banner:
                    root.after(0, lambda b=banner: log(f"Banner -> {b}"))

                if banner_analysis:
                    root.after(0, lambda a=banner_analysis: log(f"분석 -> {a}"))

                root.after(0, update_dashboard)

            s.close()
        except:
            pass
        finally:
            with state_lock:
                scanned_ports += 1

    def run():
        with ThreadPoolExecutor(max_workers=200) as executor:
            for port in range(start_port_value, end_port_value + 1):
                if stop_scan:
                    break
                executor.submit(scan, port)

    threading.Thread(target=run, daemon=True).start()
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
        progress["value"] = 100 if not stop_scan else progress["value"]

        risk_info = get_total_risk_info()

        log("")
        log("Scan Finished" if not stop_scan else "Scan Stopped")
        log(f"Open Ports: {open_port_count}")
        log(f"IP Risk Score: {risk_info['ip_score']} / {risk_info['ip_max']}")
        log(f"Port Risk Score: {risk_info['port_score']} / {risk_info['port_max']}")
        log(f"Total Risk Score: {risk_info['total_score']} / {risk_info['total_max']}")
        log(f"Final Risk: {risk_info['level']}")
        log(f"Time: {finish_time}s")

        summary = build_scan_summary()
        compare_with_previous(scan_target, summary)
        save_snapshot(scan_target, summary)

        if risk_info["suspicious"]:
            log("의심 항목 감지됨", "error")
            if scan_target:
                log(f"의심 IP : {scan_target}", "error")
            generate_html_report(auto=True)

        update_dashboard()

def stop():
    global stop_scan
    stop_scan = True
    log("Scan Stopped", "error")

# ------------------------
# WEB SCANNER
# ------------------------
def normalize_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url

def scan_header():
    url = normalize_url(url_entry.get())
    try:
        r = requests.get(url, timeout=5)
        log("Header Scan:")
        for h in r.headers:
            log(f"{h}: {r.headers[h]}")
    except Exception as e:
        log(f"Header Scan Failed: {e}", "error")

def vulnerability_scan():
    url = normalize_url(url_entry.get())
    log("Checking Security Headers...")

    try:
        r = requests.get(url, timeout=5)
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
                log(f"{h}: OK", "open")
            else:
                log(f"{h}: MISSING", "error")

    except Exception as e:
        log(f"Scan Failed: {e}", "error")

def dir_bruteforce():
    url = normalize_url(url_entry.get())
    wordlist = ["admin", "login", "backup", "test", "dashboard", "config"]

    log("Starting Directory Scan...")
    log("본인이 허가받은 사이트에서만 사용하세요.")

    for w in wordlist:
        test_url = f"{url}/{w}"
        try:
            r = requests.get(test_url, timeout=2)
            if r.status_code == 200:
                log(f"FOUND: {test_url}", "open")
        except:
            pass

def sqli_test():
    url = normalize_url(url_entry.get())
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"

    log("Testing SQL Injection...")
    log("본인이 허가받은 사이트에서만 사용하세요.")

    try:
        r = requests.get(test_url, timeout=5)
        error_keywords = ["sql syntax", "mysql", "warning", "odbc", "database error", "syntax error"]

        if any(k in r.text.lower() for k in error_keywords):
            log("Possible SQL Injection Detected!", "error")
        else:
            log("No obvious SQLi error detected")
    except Exception as e:
        log(f"SQL Test Failed: {e}", "error")

# ------------------------
# IP INFO
# ------------------------
def analyze_ip(data):
    isp_value = data.get("isp", "").lower()
    country_value = data.get("country", "").lower()

    score = 0
    max_score = 100
    suspicious_flag = False

    if any(x in isp_value for x in ["amazon", "aws", "google", "cloud", "azure", "digitalocean", "ovh"]):
        ip_type_value = "서버"
        score += 40
    elif any(x in isp_value for x in ["kt", "sk", "lg", "telecom"]):
        ip_type_value = "개인 사용자"
        score += 10
    else:
        ip_type_value = "알 수 없음"
        score += 25

    if country_value in ["russia", "china", "iran"]:
        score += 50

    if score >= 60:
        suspicious_flag = True
        risk_level_value = "HIGH ⚠"
    elif score >= 30:
        risk_level_value = "MEDIUM"
    else:
        risk_level_value = "LOW"

    return ip_type_value, risk_level_value, score, max_score, suspicious_flag

def ip_lookup():
    global ip_info_data, ip_risk_score, ip_risk_level, ip_type, ip_suspicious

    ip = ip_entry.get().strip()

    try:
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        ip_info_data = data

        log(f"Country: {data.get('country', '-')}")
        log(f"ISP: {data.get('isp', '-')}")
        log(f"City: {data.get('city', '-')}")

        ip_type, ip_risk_level, ip_risk_score, max_score, ip_suspicious = analyze_ip(data)

        update_dashboard()
        risk_info = get_total_risk_info()

        log("")
        log("분석:")
        log(f"Type: {ip_type}")
        log(f"IP Risk: {ip_risk_level}")
        log(f"IP Risk Score: {ip_risk_score} / {max_score}")
        log(f"Port Risk Score: {risk_info['port_score']} / {risk_info['port_max']}")
        log(f"Total Risk Score: {risk_info['total_score']} / {risk_info['total_max']}")
        log(f"Final Risk: {risk_info['level']}")

    except Exception as e:
        log(f"IP Lookup Failed: {e}", "error")

# ------------------------
# PASSWORD / HASH
# ------------------------
def check_password():
    pw = password_entry.get()
    score = 0

    if len(pw) >= 8:
        score += 1
    if re.search("[A-Z]", pw):
        score += 1
    if re.search("[a-z]", pw):
        score += 1
    if re.search("[0-9]", pw):
        score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pw):
        score += 1

    if score <= 2:
        log("Password Strength: Weak", "error")
    elif score <= 4:
        log("Password Strength: Medium")
    else:
        log("Password Strength: Strong", "open")

def generate_hash():
    text = hash_entry.get()
    log("MD5: " + hashlib.md5(text.encode()).hexdigest())
    log("SHA256: " + hashlib.sha256(text.encode()).hexdigest())

# ------------------------
# LOG ANALYZER
# ------------------------
def analyze_log_file():
    file_path = filedialog.askopenfilename(
        title="로그 파일 선택",
        filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")]
    )

    if not file_path:
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        log("")
        log("=== 로그 분석 시작 ===")

        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        port_matches = re.findall(r"Port\s+(\d+)\s+OPEN", content, flags=re.IGNORECASE)

        ip_count = {}
        for ip in ip_matches:
            ip_count[ip] = ip_count.get(ip, 0) + 1

        port_count = {}
        for port in port_matches:
            port_count[port] = port_count.get(port, 0) + 1

        suspicious_keywords = [
            "failed", "error", "denied", "unauthorized",
            "attack", "bruteforce", "sql", "injection",
            "warning", "forbidden"
        ]

        found_keywords = []
        lower_content = content.lower()
        for keyword in suspicious_keywords:
            count = lower_content.count(keyword)
            if count > 0:
                found_keywords.append((keyword, count))

        repeated_ips = [(ip, count) for ip, count in ip_count.items() if count >= 3]

        log(f"IP 개수: {len(ip_matches)}")
        log(f"포트 로그 개수: {len(port_matches)}")

        if repeated_ips:
            log("반복 등장 IP:", "error")
            for ip, count in sorted(repeated_ips, key=lambda x: x[1], reverse=True)[:10]:
                log(f"{ip} -> {count}회", "error")
        else:
            log("반복 등장 IP 없음")

        if port_count:
            log("자주 등장한 OPEN 포트:")
            for port, count in sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                log(f"Port {port} -> {count}회")
        else:
            log("OPEN 포트 기록 없음")

        if found_keywords:
            log("의심 키워드 탐지:", "error")
            for keyword, count in found_keywords:
                log(f"{keyword} -> {count}회", "error")
        else:
            log("의심 키워드 없음", "open")

    except Exception as e:
        log(f"로그 분석 실패: {e}", "error")

# ------------------------
# SAVE / CLEAR
# ------------------------
def save():
    file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file:
        with open(file, "w", encoding="utf-8") as f:
            f.write(result_box.get(1.0, tk.END))
        log(f"로그 저장 완료: {file}", "open")

def clear_log():
    result_box.delete(1.0, tk.END)

# ------------------------
# UI
# ------------------------
root = tk.Tk()
root.title(f"Cyber Security Toolkit v{CURRENT_VERSION}")
root.geometry("980x860")
root.configure(bg="black")

tk.Label(
    root,
    text="Cyber Security Toolkit",
    font=("Consolas", 20, "bold"),
    fg="#00ff00",
    bg="black"
).pack(pady=10)

# DASHBOARD
dashboard = tk.LabelFrame(root, text="Dashboard", bg="black", fg="#00ff00")
dashboard.pack(fill="x", padx=10, pady=5)

tk.Label(dashboard, text="Target", bg="black", fg="#00ff00").grid(row=0, column=0, padx=10, pady=5)
target_value = tk.Label(dashboard, text="-", bg="black", fg="white")
target_value.grid(row=0, column=1, padx=10)

tk.Label(dashboard, text="Open Ports", bg="black", fg="#00ff00").grid(row=0, column=2, padx=10, pady=5)
open_ports_value = tk.Label(dashboard, text="0", bg="black", fg="white")
open_ports_value.grid(row=0, column=3, padx=10)

tk.Label(dashboard, text="Risk Score", bg="black", fg="#00ff00").grid(row=0, column=4, padx=10, pady=5)
risk_score_value = tk.Label(dashboard, text="0 / 200", bg="black", fg="white")
risk_score_value.grid(row=0, column=5, padx=10)

tk.Label(dashboard, text="Suspicious", bg="black", fg="#00ff00").grid(row=1, column=0, padx=10, pady=5)
suspicious_value = tk.Label(dashboard, text="NO", bg="black", fg="white")
suspicious_value.grid(row=1, column=1, padx=10)

tk.Label(dashboard, text="Final Risk", bg="black", fg="#00ff00").grid(row=1, column=2, padx=10, pady=5)
final_risk_value = tk.Label(dashboard, text="LOW", bg="black", fg="#00ff00")
final_risk_value.grid(row=1, column=3, padx=10)

# PORT
frame1 = tk.LabelFrame(root, text="Port Scanner", bg="black", fg="#00ff00")
frame1.pack(fill="x", padx=10, pady=5)

ip_entry = tk.Entry(frame1, bg="black", fg="#00ff00")
ip_entry.grid(row=0, column=1, padx=5, pady=5)

start_entry = tk.Entry(frame1, width=6, bg="black", fg="#00ff00")
start_entry.grid(row=0, column=3, padx=5, pady=5)

end_entry = tk.Entry(frame1, width=6, bg="black", fg="#00ff00")
end_entry.grid(row=0, column=5, padx=5, pady=5)

tk.Label(frame1, text="IP", bg="black", fg="#00ff00").grid(row=0, column=0)
tk.Label(frame1, text="Start", bg="black", fg="#00ff00").grid(row=0, column=2)
tk.Label(frame1, text="End", bg="black", fg="#00ff00").grid(row=0, column=4)

tk.Button(frame1, text="SCAN", command=scan_ports).grid(row=0, column=6, padx=4)
tk.Button(frame1, text="STOP", command=stop).grid(row=0, column=7, padx=4)
tk.Button(frame1, text="IP INFO", command=ip_lookup).grid(row=0, column=8, padx=4)
tk.Button(frame1, text="REPORT", command=generate_html_report).grid(row=0, column=9, padx=4)
tk.Button(frame1, text="OPEN REPORT", command=open_last_report).grid(row=0, column=10, padx=4)

# WEB
frame2 = tk.LabelFrame(root, text="Web Scanner", bg="black", fg="#00ff00")
frame2.pack(fill="x", padx=10, pady=5)

url_entry = tk.Entry(frame2, width=40, bg="black", fg="#00ff00")
url_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame2, text="URL", bg="black", fg="#00ff00").grid(row=0, column=0)

tk.Button(frame2, text="HEADER", command=scan_header).grid(row=0, column=2, padx=4)
tk.Button(frame2, text="VULN", command=vulnerability_scan).grid(row=0, column=3, padx=4)
tk.Button(frame2, text="DIR", command=dir_bruteforce).grid(row=0, column=4, padx=4)
tk.Button(frame2, text="SQLi", command=sqli_test).grid(row=0, column=5, padx=4)

# PASSWORD
frame3 = tk.LabelFrame(root, text="Password", bg="black", fg="#00ff00")
frame3.pack(fill="x", padx=10, pady=5)

password_entry = tk.Entry(frame3, bg="black", fg="#00ff00")
password_entry.pack(side="left", padx=5, pady=5)

tk.Button(frame3, text="CHECK", command=check_password).pack(side="left", padx=5)

# HASH
frame4 = tk.LabelFrame(root, text="Hash", bg="black", fg="#00ff00")
frame4.pack(fill="x", padx=10, pady=5)

hash_entry = tk.Entry(frame4, bg="black", fg="#00ff00")
hash_entry.pack(side="left", padx=5, pady=5)

tk.Button(frame4, text="HASH", command=generate_hash).pack(side="left", padx=5)

# TOOLS
frame5 = tk.LabelFrame(root, text="Analysis Tools", bg="black", fg="#00ff00")
frame5.pack(fill="x", padx=10, pady=5)

tk.Button(frame5, text="LOG ANALYZE", command=analyze_log_file).pack(side="left", padx=5, pady=5)

# PROGRESS
progress_label = tk.Label(root, text="Progress: 0%", bg="black", fg="#00ff00")
progress_label.pack()

progress = ttk.Progressbar(root, length=500)
progress.pack(pady=5)

# RESULT
result_box = scrolledtext.ScrolledText(root, bg="black", fg="#00ff00", insertbackground="#00ff00")
result_box.pack(expand=True, fill="both", padx=10, pady=8)

result_box.tag_config("open", foreground="#00ff00")
result_box.tag_config("error", foreground="red")

# BOTTOM
bottom = tk.Frame(root, bg="black")
bottom.pack(fill="x", pady=5)

tk.Button(bottom, text="SAVE", command=save).pack(side="left", padx=5)
tk.Button(bottom, text="CLEAR", command=clear_log).pack(side="left", padx=5)

update_dashboard()
root.after(2000, check_update)
root.mainloop()
