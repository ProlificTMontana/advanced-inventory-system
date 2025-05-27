import os
import sys
import sqlite3
import subprocess
import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
import argparse
from jinja2 import Template
from threading import Thread
import time
from fpdf import FPDF


# Constants for CVE API and email alert config
CVE_API_BASE = 'https://cve.circl.lu/api/search/'

# SQLite DB file
DB_FILE = 'vuln_scanner.db'


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            target TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            version TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            cve_id TEXT,
            summary TEXT,
            cvss FLOAT,
            severity TEXT,
            link TEXT,
            FOREIGN KEY(port_id) REFERENCES ports(id)
        )
    ''')
    conn.commit()
    conn.close()


def run_nmap(targets):
    # Run nmap scan with service version detection on target(s)
    # -oX for XML output could be used but here we parse greppable output for simplicity
    args = ['nmap', '-sV', '-oX', '-', *targets]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f'Error running nmap: {result.stderr}')
        return None
    return result.stdout


def parse_nmap_xml(xml_data):
    # Minimal XML parsing using built-in xml.etree.ElementTree for extracted data
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_data)
    # Nmap XML root tag is <nmaprun>
    hosts_data = []
    for host in root.findall('host'):
        ip = None
        for addr in host.findall('address'):
            if addr.attrib.get('addrtype') == 'ipv4':
                ip = addr.attrib.get('addr')
        if ip is None:
            continue  # skip if no IP found
        ports = []
        ports_node = host.find('ports')
        if ports_node is None:
            continue
        for port in ports_node.findall('port'):
            portid = int(port.attrib.get('portid', 0))
            protocol = port.attrib.get('protocol', '')
            state = port.find('state').attrib.get('state', '')
            if state != 'open':
                continue
            service_node = port.find('service')
            service = service_node.attrib.get('name', '') if service_node is not None else ''
            version_info = []
            if service_node is not None:
                version_info.append(service_node.attrib.get('product', ''))
                version_info.append(service_node.attrib.get('version', ''))
                version_info.append(service_node.attrib.get('extrainfo', ''))
            version = ' '.join(filter(None, version_info)).strip()
            ports.append({
                'port': portid,
                'protocol': protocol,
                'service': service,
                'version': version
            })
        hosts_data.append({
            'ip': ip,
            'ports': ports
        })
    return hosts_data


def lookup_cve(service, version):
    # Query CVE API for vulnerabilities for a given service and version
    # Use the service string as keyword in CVE API search
    # The CVE API is limited in filtering but returns a list of CVEs
    if not service:
        return []
    query = f"{service} {version}".strip()
    try:
        response = requests.get(CVE_API_BASE + query)
        if response.status_code != 200:
            print(f"CVE API error: {response.status_code}")
            return []
        data = response.json()
        if not isinstance(data, list):
            return []
        vulns = []
        for cve in data:
            vulns.append({
                'cve_id': cve.get('id', ''),
                'summary': cve.get('summary', ''),
                'cvss': float(cve.get('cvss', 0) or 0),
                'severity': severity_from_cvss(float(cve.get('cvss', 0) or 0)),
                'link': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.get('id','')}"
            })
        return vulns
    except Exception as e:
        print(f"Exception querying CVE API: {e}")
        return []


def severity_from_cvss(cvss):
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0:
        return "Low"
    else:
        return "Unknown"


def save_scan_results(targets, hosts):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    scan_time = datetime.utcnow().isoformat()
    c.execute('INSERT INTO scans (scan_time, target) VALUES (?, ?)', (scan_time, ','.join(targets)))
    scan_id = c.lastrowid
    for host in hosts:
        ip = host['ip']
        for port in host['ports']:
            c.execute('''
                INSERT INTO ports(scan_id, ip, port, protocol, service, version)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, ip, port['port'], port['protocol'], port['service'], port['version']))
            port_id = c.lastrowid
            vulns = lookup_cve(port['service'], port['version'])
            for v in vulns:
                c.execute('''
                    INSERT INTO vulnerabilities(port_id, cve_id, summary, cvss, severity, link)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (port_id, v['cve_id'], v['summary'], v['cvss'], v['severity'], v['link']))
    conn.commit()
    conn.close()


def generate_report_html(scan_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT scan_time, target FROM scans WHERE id=?', (scan_id,))
    scan_info = c.fetchone()
    if not scan_info:
        return None
    scan_time, target = scan_info
    c.execute('''
        SELECT ip, port, protocol, service, version, id FROM ports WHERE scan_id=?
    ''', (scan_id,))
    ports = c.fetchall()
    ports_data = []
    for ip, port, protocol, service, version, port_id in ports:
        c.execute('''
            SELECT cve_id, summary, cvss, severity, link FROM vulnerabilities WHERE port_id=?
        ''', (port_id,))
        vulns = c.fetchall()
        vulns_data = []
        for cve_id, summary, cvss, severity, link in vulns:
            vulns_data.append({
                'cve_id': cve_id,
                'summary': summary,
                'cvss': cvss,
                'severity': severity,
                'link': link
            })
        ports_data.append({
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'service': service,
            'version': version,
            'vulnerabilities': vulns_data
        })
    conn.close()

    template = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Vulnerability Scan Report</title>
<style>
body { font-family: Arial, sans-serif; background:#f8f9fa; margin: 20px; }
h1, h2 { color: #2c3e50; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #34495e; color: white; }
tr:nth-child(even){background-color: #f2f2f2;}
.severity-Critical { color: #b71c1c; font-weight: bold; }
.severity-High { color: #d32f2f; font-weight: bold; }
.severity-Medium { color: #f57c00; font-weight: bold; }
.severity-Low { color: #fbc02d; font-weight: bold; }
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
<p><strong>Scan Time (UTC):</strong> {{ scan_time }}</p>
<p><strong>Targets:</strong> {{ target }}</p>
{% for port in ports %}
    <h2>{{ port.ip }} : {{ port.port }}/{{ port.protocol }}</h2>
    <p><strong>Service:</strong> {{ port.service }} {{ port.version }}</p>
    {% if port.vulnerabilities %}
    <table>
        <thead><tr><th>CVE ID</th><th>Summary</th><th>CVSS</th><th>Severity</th><th>Link</th></tr></thead>
        <tbody>
        {% for v in port.vulnerabilities %}
        <tr class="severity-{{v.severity}}">
            <td>{{ v.cve_id }}</td>
            <td>{{ v.summary }}</td>
            <td>{{ "%.1f"|format(v.cvss) }}</td>
            <td>{{ v.severity }}</td>
            <td><a href="{{ v.link }}" target="_blank">Details</a></td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No vulnerabilities found</p>
    {% endif %}
{% endfor %}
</body>
</html>
""")

    html_content = template.render(scan_time=scan_time, target=target, ports=ports_data)
    return html_content


def generate_report_pdf(html_content, output_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    # Convert html_content basic to text for pdf since full html parsing is complex here
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text('\n', strip=True)
    for line in text.split('\n'):
        pdf.cell(0, 10, line, ln=True)
    pdf.output(output_file)


def send_email(smtp_host, smtp_port, smtp_user, smtp_password, to_email, subject, body, attachments=None):
    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    attachments = attachments or []
    for file_path in attachments:
        with open(file_path, 'rb') as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(file_path))
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        msg.attach(part)
    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, to_email, msg.as_string())
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")


def check_high_severity(scan_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('High', 'Critical')
        AND port_id IN (SELECT id FROM ports WHERE scan_id=?)
    ''', (scan_id,))
    count = c.fetchone()[0]
    conn.close()
    return count > 0


def scan(
        targets,
        smtp_config=None,
        email_to=None,
        generate_pdf_report=True,
        generate_html_report=True,
        report_dir='reports'):
    print(f"Starting scan of: {targets}")
    xml_result = run_nmap(targets)
    if xml_result is None:
        print("Nmap scan failed, exiting.")
        return
    hosts = parse_nmap_xml(xml_result)
    if not hosts:
        print("No hosts found in the scan result.")
        return
    save_scan_results(targets, hosts)

    # Fetch last scan_id for report generation
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT MAX(id) FROM scans')
    scan_id = c.fetchone()[0]
    conn.close()

    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    html_report = None
    pdf_report_path = None

    if generate_html_report:
        html_report = generate_report_html(scan_id)
        html_file = os.path.join(report_dir, f'scan_report_{scan_id}.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        print(f"HTML report generated: {html_file}")

    if generate_pdf_report and html_report:
        pdf_report_path = os.path.join(report_dir, f'scan_report_{scan_id}.pdf')
        generate_report_pdf(html_report, pdf_report_path)
        print(f"PDF report generated: {pdf_report_path}")

    # Email alert if high severity vulnerabilities are found
    if smtp_config and email_to:
        if check_high_severity(scan_id):
            subject = f"ALERT: High severity vulnerabilities found in scan {scan_id}"
            body = f"High severity vulnerabilities were detected in the scan of targets: {', '.join(targets)}.\nPlease review attached report."
            attachments = []
            if pdf_report_path:
                attachments.append(pdf_report_path)
            elif generate_html_report:
                attachments.append(html_file)
            send_email(
                smtp_host=smtp_config['host'],
                smtp_port=smtp_config['port'],
                smtp_user=smtp_config['user'],
                smtp_password=smtp_config['password'],
                to_email=email_to,
                subject=subject,
                body=body,
                attachments=attachments
            )
        else:
            print("No high severity vulnerabilities found; no email sent.")


def schedule_scan(interval_seconds, scan_func, *args, **kwargs):
    # Background thread for periodic scanning
    def loop():
        while True:
            scan_func(*args, **kwargs)
            time.sleep(interval_seconds)
    t = Thread(target=loop, daemon=True)
    t.start()


def main():
    parser = argparse.ArgumentParser(description='Automated Vulnerability Scanner')
    parser.add_argument('targets', nargs='+', help='List of IPs or network ranges to scan')
    parser.add_argument('--interval', type=int, help='Interval in seconds for scheduled scans (default: run once)')
    parser.add_argument('--email-to', help='Email address to send alerts')
    parser.add_argument('--smtp-host', help='SMTP server host for sending emails')
    parser.add_argument('--smtp-port', type=int, default=465, help='SMTP server port (default 465)')
    parser.add_argument('--smtp-user', help='SMTP username')
    parser.add_argument('--smtp-password', help='SMTP password')
    parser.add_argument('--no-pdf', action='store_true', help='Disable PDF report generation')
    parser.add_argument('--no-html', action='store_true', help='Disable HTML report generation')

    args = parser.parse_args()

    init_db()

    smtp_config = None
    if args.email_to:
        if not (args.smtp_host and args.smtp_user and args.smtp_password):
            print("Email alert enabled but SMTP host/user/password not fully provided")
            return
        smtp_config = {
            'host': args.smtp_host,
            'port': args.smtp_port,
            'user': args.smtp_user,
            'password': args.smtp_password
        }

    if args.interval:
        print(f"Scheduling scan every {args.interval} seconds")
        schedule_scan(
            args.interval,
            scan,
            args.targets,
            smtp_config=smtp_config,
            email_to=args.email_to,
            generate_pdf_report=not args.no_pdf,
            generate_html_report=not args.no_html
        )
        # Keep the program running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping scheduled scans")
    else:
        scan(
            args.targets,
            smtp_config=smtp_config,
            email_to=args.email_to,
            generate_pdf_report=not args.no_pdf,
            generate_html_report=not args.no_html
        )


if __name__ == '__main__':
    main()


