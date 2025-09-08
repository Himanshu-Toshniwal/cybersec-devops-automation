from flask import Flask, render_template_string, jsonify
import socket
import threading
import requests
import subprocess
import time
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = 'cybersec_automation_2024'

# HTML Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>🔒 Cybersecurity Platform</title>
    <style>
        body { font-family: Arial; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { font-size: 2.5em; text-shadow: 0 0 10px #00ff00; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #1a1a1a; border: 1px solid #00ff00; border-radius: 10px; padding: 20px; }
        .card h3 { color: #00ff00; margin-bottom: 15px; }
        input { width: 100%; padding: 10px; background: #000; border: 1px solid #00ff00; color: #00ff00; border-radius: 5px; margin: 5px 0; }
        .btn { background: #00ff00; color: #000; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 10px; }
        .btn:hover { background: #00cc00; }
        .result { background: #000; border: 1px solid #00ff00; border-radius: 5px; padding: 15px; margin-top: 15px; max-height: 300px; overflow-y: auto; font-family: monospace; }
        .endpoint { background: #1a1a1a; border-left: 4px solid #00ff00; padding: 15px; margin: 10px 0; }
        .endpoint code { color: #00ff00; background: #000; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Cybersecurity Platform</h1>
            <p>Advanced Security Testing & Vulnerability Assessment</p>
        </div>
        <div class="grid">
            <div class="card">
                <h3>🔍 Port Scanner</h3>
                <input type="text" id="portTarget" placeholder="example.com">
                <button class="btn" onclick="scanPorts()">🔍 Scan Ports</button>
                <div id="portResult" class="result" style="display:none;"></div>
            </div>
            <div class="card">
                <h3>🛡️ Vulnerability Scanner</h3>
                <input type="text" id="vulnTarget" placeholder="https://example.com">
                <button class="btn" onclick="scanVulnerabilities()">🛡️ Scan Vulnerabilities</button>
                <div id="vulnResult" class="result" style="display:none;"></div>
            </div>
            <div class="card">
                <h3>🔎 WHOIS Lookup</h3>
                <input type="text" id="whoisDomain" placeholder="example.com">
                <button class="btn" onclick="whoisLookup()">🔎 WHOIS Lookup</button>
                <div id="whoisResult" class="result" style="display:none;"></div>
            </div>
            <div class="card">
                <h3>🌐 DNS Enumeration</h3>
                <input type="text" id="dnsDomain" placeholder="example.com">
                <button class="btn" onclick="dnsEnumeration()">🌐 DNS Lookup</button>
                <div id="dnsResult" class="result" style="display:none;"></div>
            </div>
            <div class="card">
                <h3>📊 Security Report</h3>
                <input type="text" id="reportTarget" placeholder="example.com">
                <button class="btn" onclick="generateReport()">📊 Generate Report</button>
                <div id="reportResult" class="result" style="display:none;"></div>
            </div>
            <div class="card">
                <h3>📡 API Endpoints</h3>
                <div class="endpoint"><strong>Port Scan:</strong><br><code>GET /api/scan/ports/&lt;target&gt;</code></div>
                <div class="endpoint"><strong>Vulnerability Scan:</strong><br><code>GET /api/scan/vulnerabilities/&lt;target&gt;</code></div>
                <div class="endpoint"><strong>WHOIS Lookup:</strong><br><code>GET /api/intel/whois/&lt;domain&gt;</code></div>
                <div class="endpoint"><strong>DNS Enumeration:</strong><br><code>GET /api/intel/dns/&lt;domain&gt;</code></div>
                <div class="endpoint"><strong>Security Report:</strong><br><code>GET /api/report/&lt;target&gt;</code></div>
            </div>
        </div>
    </div>
    <script>
        function showResult(elementId, data) {
            const element = document.getElementById(elementId);
            element.style.display = 'block';
            element.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
        }
        function showError(elementId, error) {
            const element = document.getElementById(elementId);
            element.style.display = 'block';
            element.innerHTML = '<div style="color:#ff0000;">❌ Error: ' + error + '</div>';
        }
        async function scanPorts() {
            const target = document.getElementById('portTarget').value;
            if (!target) return alert('Please enter a target');
            try {
                const response = await fetch(`/api/scan/ports/${target}`);
                const data = await response.json();
                showResult('portResult', data);
            } catch (error) {
                showError('portResult', error.message);
            }
        }
        async function scanVulnerabilities() {
            const target = document.getElementById('vulnTarget').value;
            if (!target) return alert('Please enter a target');
            try {
                const response = await fetch(`/api/scan/vulnerabilities/${encodeURIComponent(target)}`);
                const data = await response.json();
                showResult('vulnResult', data);
            } catch (error) {
                showError('vulnResult', error.message);
            }
        }
        async function whoisLookup() {
            const domain = document.getElementById('whoisDomain').value;
            if (!domain) return alert('Please enter a domain');
            try {
                const response = await fetch(`/api/intel/whois/${domain}`);
                const data = await response.json();
                showResult('whoisResult', data);
            } catch (error) {
                showError('whoisResult', error.message);
            }
        }
        async function dnsEnumeration() {
            const domain = document.getElementById('dnsDomain').value;
            if (!domain) return alert('Please enter a domain');
            try {
                const response = await fetch(`/api/intel/dns/${domain}`);
                const data = await response.json();
                showResult('dnsResult', data);
            } catch (error) {
                showError('dnsResult', error.message);
            }
        }
        async function generateReport() {
            const target = document.getElementById('reportTarget').value;
            if (!target) return alert('Please enter a target');
            try {
                const response = await fetch(`/api/report/${encodeURIComponent(target)}`);
                const data = await response.json();
                showResult('reportResult', data);
            } catch (error) {
                showError('reportResult', error.message);
            }
        }
    </script>
</body>
</html>
"""

class CyberSecurityAnalyzer:
    def __init__(self):
        self.scan_results = {}
        
    def port_scan(self, target):
        """Simple port scanning"""
        try:
            results = {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'open_ports': [],
                'status': 'completed'
            }
            
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        results['open_ports'].append({
                            'port': port,
                            'state': 'open',
                            'service': self.get_service_name(port)
                        })
                    sock.close()
                except:
                    continue
            
            return results
        except Exception as e:
            return {'error': f'Port scan failed: {str(e)}'}
    
    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def vulnerability_scan(self, target):
        """Basic vulnerability assessment"""
        vulnerabilities = []
        try:
            if not target.startswith('http'):
                target = f'http://{target}'
            
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS header missing',
                'Content-Security-Policy': 'CSP header missing'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'description': f'{header}: {description}'
                    })
            
            if 'Server' in headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {headers["Server"]}'
                })
            
            return vulnerabilities
        except Exception as e:
            return [{'type': 'Scan Error', 'severity': 'ERROR', 'description': str(e)}]
    
    def whois_lookup(self, domain):
        """WHOIS lookup using socket"""
        try:
            whois_server = 'whois.internic.net'
            port = 43
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, port))
            sock.send(f"{domain}\r\n".encode())
            
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            result = {
                'domain': domain,
                'status': 'success',
                'raw_data': response_text[:500] + '...' if len(response_text) > 500 else response_text
            }
            
            lines = response_text.lower().split('\n')
            for line in lines:
                if 'registrar:' in line:
                    result['registrar'] = line.split(':', 1)[1].strip()
                elif 'creation date:' in line or 'created:' in line:
                    result['creation_date'] = line.split(':', 1)[1].strip()
                elif 'expiration date:' in line or 'expires:' in line:
                    result['expiration_date'] = line.split(':', 1)[1].strip()
            
            return result
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def dns_enumeration(self, domain):
        """DNS enumeration using system tools"""
        dns_records = {}
        try:
            # Get A record
            try:
                ip = socket.gethostbyname(domain)
                dns_records['A'] = [ip]
            except:
                dns_records['A'] = []
            
            # Try nslookup for other records
            record_types = ['MX', 'NS', 'TXT']
            for record_type in record_types:
                try:
                    result = subprocess.run(['nslookup', f'-type={record_type}', domain], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        records = []
                        for line in result.stdout.split('\n'):
                            if record_type.lower() in line.lower() and '=' in line:
                                records.append(line.strip())
                        dns_records[record_type] = records
                    else:
                        dns_records[record_type] = []
                except:
                    dns_records[record_type] = ['DNS lookup tools not available']
            
            return dns_records
        except Exception as e:
            return {'error': f'DNS enumeration failed: {str(e)}'}
    
    def generate_security_report(self, target):
        """Generate security report"""
        report = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'summary': {}
        }
        
        try:
            port_results = self.port_scan(target)
            vuln_results = self.vulnerability_scan(target)
            
            report['port_scan'] = port_results
            report['vulnerabilities'] = vuln_results
            
            total_vulns = len(vuln_results) if isinstance(vuln_results, list) else 0
            open_ports = len(port_results.get('open_ports', [])) if 'open_ports' in port_results else 0
            
            report['summary'] = {
                'total_vulnerabilities': total_vulns,
                'open_ports': open_ports,
                'risk_level': 'HIGH' if total_vulns > 5 else 'MEDIUM' if total_vulns > 0 else 'LOW'
            }
        except Exception as e:
            report['error'] = str(e)
        
        return report

# Initialize analyzer
analyzer = CyberSecurityAnalyzer()

# Flask Routes
@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/scan/ports/<target>')
def scan_ports(target):
    try:
        results = analyzer.port_scan(target)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/vulnerabilities/<path:target>')
def scan_vulnerabilities(target):
    try:
        results = analyzer.vulnerability_scan(target)
        return jsonify({'vulnerabilities': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/intel/whois/<domain>')
def whois_intel(domain):
    try:
        results = analyzer.whois_lookup(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/intel/dns/<domain>')
def dns_intel(domain):
    try:
        results = analyzer.dns_enumeration(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<path:target>')
def security_report(target):
    try:
        results = analyzer.generate_security_report(target)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_flask_app():
    app.run(host='0.0.0.0', port=5000, debug=False)

def main():
    print("🔒 Starting Advanced Cybersecurity Automation Platform...")
    print("🌐 Flask API running on http://localhost:5000")
    
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    
    print("🛡️ Cybersecurity Platform Ready!")
    print("📊 Available endpoints:")
    print("  - /api/scan/ports/<target>")
    print("  - /api/scan/vulnerabilities/<target>")
    print("  - /api/intel/whois/<domain>")
    print("  - /api/intel/dns/<domain>")
    print("  - /api/report/<target>")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Cybersecurity Platform...")

if __name__ == "__main__":
    main()