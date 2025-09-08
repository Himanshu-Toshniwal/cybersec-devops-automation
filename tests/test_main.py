import pytest
import json
import socket
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import CyberSecurityAnalyzer, app

class TestCyberSecurityAnalyzer:
    
    def setup_method(self):
        """Setup test environment"""
        self.analyzer = CyberSecurityAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test CyberSecurityAnalyzer initialization"""
        assert isinstance(self.analyzer.scan_results, dict)
        assert isinstance(self.analyzer.vulnerability_db, dict)
        assert isinstance(self.analyzer.threat_intelligence, dict)
        assert isinstance(self.analyzer.active_scans, dict)
        assert len(self.analyzer.scan_results) == 0
    
    @patch('nmap.PortScanner')
    def test_port_scan_success(self, mock_nmap):
        """Test successful port scanning"""
        # Mock nmap response
        mock_scanner = Mock()
        mock_scanner.scan.return_value = None
        mock_scanner.all_hosts.return_value = ['192.168.1.1']
        mock_scanner.__getitem__.return_value.state.return_value = 'up'
        mock_scanner.__getitem__.return_value.all_protocols.return_value = ['tcp']
        mock_scanner.__getitem__.return_value.__getitem__.return_value.keys.return_value = [80, 443]
        
        port_info = {
            'state': 'open',
            'name': 'http',
            'product': 'Apache',
            'version': '2.4.41',
            'extrainfo': '',
            'script': {}
        }
        mock_scanner.__getitem__.return_value.__getitem__.return_value.__getitem__.return_value = port_info
        mock_nmap.return_value = mock_scanner
        
        result = self.analyzer.port_scan('192.168.1.1')
        
        assert 'target' in result
        assert result['target'] == '192.168.1.1'
        assert 'hosts' in result
        assert 'vulnerabilities' in result
        assert 'services' in result
    
    @patch('nmap.PortScanner')
    def test_port_scan_failure(self, mock_nmap):
        """Test port scanning failure"""
        mock_nmap.side_effect = Exception("Scan failed")
        
        result = self.analyzer.port_scan('invalid-target')
        
        assert 'error' in result
        assert 'Scan failed' in result['error']
    
    @patch('requests.get')
    def test_check_http_headers(self, mock_get):
        """Test HTTP security headers check"""
        # Mock response with missing security headers
        mock_response = Mock()
        mock_response.headers = {
            'Server': 'Apache/2.4.41',
            'Content-Type': 'text/html'
        }
        mock_get.return_value = mock_response
        
        vulnerabilities = self.analyzer.check_http_headers('example.com')
        
        assert len(vulnerabilities) > 0
        # Should detect missing security headers
        header_vulns = [v for v in vulnerabilities if v['type'] == 'Missing Security Header']
        assert len(header_vulns) > 0
        
        # Should detect information disclosure
        info_vulns = [v for v in vulnerabilities if v['type'] == 'Information Disclosure']
        assert len(info_vulns) > 0
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_check_ssl_vulnerabilities(self, mock_ssl_context, mock_socket):
        """Test SSL vulnerability checking"""
        # Mock SSL certificate
        mock_cert = {
            'notAfter': 'Dec 31 23:59:59 2024 GMT',
            'subject': ((('commonName', 'example.com'),),)
        }
        
        mock_ssl_sock = Mock()
        mock_ssl_sock.getpeercert.return_value = mock_cert
        mock_ssl_sock.cipher.return_value = ('AES256-GCM-SHA384', 'TLSv1.2', 256)
        
        mock_context = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        mock_sock = Mock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        vulnerabilities = self.analyzer.check_ssl_vulnerabilities('example.com')
        
        # Should return list (may be empty if no vulnerabilities)
        assert isinstance(vulnerabilities, list)
    
    @patch('requests.get')
    def test_check_directory_traversal(self, mock_get):
        """Test directory traversal vulnerability check"""
        # Mock response that doesn't contain traversal indicators
        mock_response = Mock()
        mock_response.text = 'Normal web page content'
        mock_get.return_value = mock_response
        
        vulnerabilities = self.analyzer.check_directory_traversal('example.com')
        
        assert isinstance(vulnerabilities, list)
        # Should not detect traversal in normal response
        traversal_vulns = [v for v in vulnerabilities if v['type'] == 'Directory Traversal']
        assert len(traversal_vulns) == 0
    
    @patch('requests.get')
    def test_check_sql_injection(self, mock_get):
        """Test SQL injection vulnerability check"""
        # Mock response without SQL errors
        mock_response = Mock()
        mock_response.text = 'Normal web page content'
        mock_get.return_value = mock_response
        
        vulnerabilities = self.analyzer.check_sql_injection('example.com')
        
        assert isinstance(vulnerabilities, list)
        # Should not detect SQL injection in normal response
        sql_vulns = [v for v in vulnerabilities if v['type'] == 'SQL Injection']
        assert len(sql_vulns) == 0
    
    @patch('requests.get')
    def test_check_xss_vulnerabilities(self, mock_get):
        """Test XSS vulnerability check"""
        # Mock response that doesn't reflect XSS payload
        mock_response = Mock()
        mock_response.text = 'Normal web page content'
        mock_get.return_value = mock_response
        
        vulnerabilities = self.analyzer.check_xss_vulnerabilities('example.com')
        
        assert isinstance(vulnerabilities, list)
        # Should not detect XSS in normal response
        xss_vulns = [v for v in vulnerabilities if v['type'] == 'Cross-Site Scripting (XSS)']
        assert len(xss_vulns) == 0
    
    def test_vulnerability_scan(self):
        """Test comprehensive vulnerability scan"""
        with patch.object(self.analyzer, 'check_ssl_vulnerabilities') as mock_ssl, \
             patch.object(self.analyzer, 'check_http_headers') as mock_headers, \
             patch.object(self.analyzer, 'check_directory_traversal') as mock_traversal, \
             patch.object(self.analyzer, 'check_sql_injection') as mock_sql, \
             patch.object(self.analyzer, 'check_xss_vulnerabilities') as mock_xss:
            
            # Mock all vulnerability checks to return empty lists
            mock_ssl.return_value = []
            mock_headers.return_value = []
            mock_traversal.return_value = []
            mock_sql.return_value = []
            mock_xss.return_value = []
            
            result = self.analyzer.vulnerability_scan('example.com')
            
            assert isinstance(result, list)
            # All checks should have been called
            mock_ssl.assert_called_once()
            mock_headers.assert_called_once()
            mock_traversal.assert_called_once()
            mock_sql.assert_called_once()
            mock_xss.assert_called_once()
    
    @patch('whois.whois')
    def test_whois_lookup_success(self, mock_whois):
        """Test successful WHOIS lookup"""
        # Mock WHOIS response
        mock_whois_data = Mock()
        mock_whois_data.registrar = 'Example Registrar'
        mock_whois_data.creation_date = '2020-01-01'
        mock_whois_data.expiration_date = '2025-01-01'
        mock_whois_data.name_servers = ['ns1.example.com', 'ns2.example.com']
        mock_whois_data.emails = ['admin@example.com']
        mock_whois_data.country = 'US'
        mock_whois.return_value = mock_whois_data
        
        result = self.analyzer.whois_lookup('example.com')
        
        assert 'domain' in result
        assert result['domain'] == 'example.com'
        assert 'registrar' in result
        assert 'creation_date' in result
        assert 'expiration_date' in result
    
    @patch('whois.whois')
    def test_whois_lookup_failure(self, mock_whois):
        """Test WHOIS lookup failure"""
        mock_whois.side_effect = Exception("WHOIS lookup failed")
        
        result = self.analyzer.whois_lookup('invalid-domain')
        
        assert 'error' in result
        assert 'WHOIS lookup failed' in result['error']
    
    @patch('dns.resolver.resolve')
    def test_dns_enumeration(self, mock_resolve):
        """Test DNS enumeration"""
        # Mock DNS responses
        mock_resolve.return_value = ['192.168.1.1', '192.168.1.2']
        
        result = self.analyzer.dns_enumeration('example.com')
        
        assert isinstance(result, dict)
        # Should contain various record types
        expected_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for record_type in expected_types:
            assert record_type in result
    
    @patch('socket.gethostbyname')
    def test_subdomain_enumeration(self, mock_gethostbyname):
        """Test subdomain enumeration"""
        # Mock successful DNS resolution for some subdomains
        def mock_resolve(hostname):
            if hostname in ['www.example.com', 'mail.example.com']:
                return '192.168.1.1'
            else:
                raise socket.gaierror("Name resolution failed")
        
        mock_gethostbyname.side_effect = mock_resolve
        
        result = self.analyzer.subdomain_enumeration('example.com')
        
        assert isinstance(result, list)
        assert 'www.example.com' in result
        assert 'mail.example.com' in result
    
    def test_generate_security_report(self):
        """Test security report generation"""
        with patch.object(self.analyzer, 'port_scan') as mock_port, \
             patch.object(self.analyzer, 'vulnerability_scan') as mock_vuln, \
             patch.object(self.analyzer, 'whois_lookup') as mock_whois, \
             patch.object(self.analyzer, 'dns_enumeration') as mock_dns, \
             patch.object(self.analyzer, 'subdomain_enumeration') as mock_sub:
            
            # Mock all scan results
            mock_port.return_value = {'hosts': {'example.com': {'ports': {80: {}, 443: {}}}}}
            mock_vuln.return_value = [
                {'type': 'Test Vuln', 'severity': 'HIGH', 'description': 'Test vulnerability'}
            ]
            mock_whois.return_value = {'domain': 'example.com'}
            mock_dns.return_value = {'A': ['192.168.1.1']}
            mock_sub.return_value = ['www.example.com']
            
            result = self.analyzer.generate_security_report('example.com')
            
            assert 'target' in result
            assert 'scan_date' in result
            assert 'summary' in result
            assert 'port_scan' in result
            assert 'vulnerabilities' in result
            assert 'whois' in result
            assert 'dns_records' in result
            assert 'subdomains' in result
            
            # Check summary
            summary = result['summary']
            assert 'total_vulnerabilities' in summary
            assert 'high_severity' in summary
            assert 'risk_level' in summary

class TestFlaskAPI:
    
    def setup_method(self):
        """Setup Flask test client"""
        app.config['TESTING'] = True
        self.client = app.test_client()
    
    def test_index_route(self):
        """Test index route"""
        response = self.client.get('/')
        assert response.status_code == 200
        assert b'Cybersecurity Platform' in response.data
    
    @patch('main.analyzer')
    def test_scan_ports_success(self, mock_analyzer):
        """Test successful port scanning API"""
        mock_analyzer.port_scan.return_value = {
            'target': 'example.com',
            'hosts': {'example.com': {'ports': {80: {'state': 'open'}}}},
            'vulnerabilities': []
        }
        
        response = self.client.get('/api/scan/ports/example.com')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['target'] == 'example.com'
        assert 'hosts' in data
    
    @patch('main.analyzer')
    def test_scan_ports_failure(self, mock_analyzer):
        """Test port scanning API failure"""
        mock_analyzer.port_scan.side_effect = Exception("Scan failed")
        
        response = self.client.get('/api/scan/ports/example.com')
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data
    
    @patch('main.analyzer')
    def test_scan_vulnerabilities_success(self, mock_analyzer):
        """Test successful vulnerability scanning API"""
        mock_analyzer.vulnerability_scan.return_value = [
            {'type': 'Test Vuln', 'severity': 'HIGH', 'description': 'Test'}
        ]
        
        response = self.client.get('/api/scan/vulnerabilities/example.com')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'vulnerabilities' in data
        assert len(data['vulnerabilities']) == 1
    
    @patch('main.analyzer')
    def test_whois_intel_success(self, mock_analyzer):
        """Test successful WHOIS intelligence API"""
        mock_analyzer.whois_lookup.return_value = {
            'domain': 'example.com',
            'registrar': 'Test Registrar'
        }
        
        response = self.client.get('/api/intel/whois/example.com')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == 'example.com'
    
    @patch('main.analyzer')
    def test_dns_intel_success(self, mock_analyzer):
        """Test successful DNS intelligence API"""
        mock_analyzer.dns_enumeration.return_value = {
            'A': ['192.168.1.1'],
            'MX': ['mail.example.com']
        }
        
        response = self.client.get('/api/intel/dns/example.com')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'A' in data
        assert 'MX' in data
    
    @patch('main.analyzer')
    def test_security_report_success(self, mock_analyzer):
        """Test successful security report API"""
        mock_analyzer.generate_security_report.return_value = {
            'target': 'example.com',
            'summary': {'risk_level': 'LOW'},
            'vulnerabilities': []
        }
        
        response = self.client.get('/api/report/example.com')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['target'] == 'example.com'
        assert 'summary' in data

class TestSecurityChecks:
    
    def setup_method(self):
        self.analyzer = CyberSecurityAnalyzer()
    
    def test_ssl_certificate_expiry_detection(self):
        """Test SSL certificate expiry detection"""
        # This would require mocking SSL certificate data
        # For now, test that the method exists and handles errors
        result = self.analyzer.check_ssl_vulnerabilities('nonexistent-domain.invalid')
        assert isinstance(result, list)
    
    def test_security_headers_detection(self):
        """Test security headers detection logic"""
        with patch('requests.get') as mock_get:
            # Mock response with all security headers missing
            mock_response = Mock()
            mock_response.headers = {'Content-Type': 'text/html'}
            mock_get.return_value = mock_response
            
            result = self.analyzer.check_http_headers('example.com')
            
            # Should detect multiple missing headers
            assert len(result) >= 5  # At least 5 security headers should be missing
            
            # Check that all are marked as missing security headers
            missing_headers = [v for v in result if v['type'] == 'Missing Security Header']
            assert len(missing_headers) >= 5
    
    def test_vulnerability_severity_classification(self):
        """Test vulnerability severity classification"""
        with patch.object(self.analyzer, 'check_ssl_vulnerabilities') as mock_ssl:
            # Mock high severity vulnerability
            mock_ssl.return_value = [
                {'type': 'SSL Certificate Expiry', 'severity': 'HIGH', 'description': 'Expires in 1 day'}
            ]
            
            result = self.analyzer.vulnerability_scan('example.com')
            
            # Should contain the high severity vulnerability
            high_vulns = [v for v in result if v.get('severity') == 'HIGH']
            assert len(high_vulns) > 0

class TestIntegration:
    
    def setup_method(self):
        self.analyzer = CyberSecurityAnalyzer()
    
    def test_full_security_assessment_workflow(self):
        """Test complete security assessment workflow"""
        target = 'example.com'
        
        with patch.object(self.analyzer, 'port_scan') as mock_port, \
             patch.object(self.analyzer, 'vulnerability_scan') as mock_vuln, \
             patch.object(self.analyzer, 'whois_lookup') as mock_whois, \
             patch.object(self.analyzer, 'dns_enumeration') as mock_dns, \
             patch.object(self.analyzer, 'subdomain_enumeration') as mock_sub:
            
            # Mock all components
            mock_port.return_value = {'hosts': {target: {'ports': {80: {}, 443: {}}}}}
            mock_vuln.return_value = [
                {'type': 'Missing Security Header', 'severity': 'MEDIUM', 'description': 'X-Frame-Options missing'}
            ]
            mock_whois.return_value = {'domain': target, 'registrar': 'Test'}
            mock_dns.return_value = {'A': ['192.168.1.1']}
            mock_sub.return_value = ['www.example.com', 'mail.example.com']
            
            # Generate comprehensive report
            report = self.analyzer.generate_security_report(target)
            
            # Verify all components are included
            assert report['target'] == target
            assert 'port_scan' in report
            assert 'vulnerabilities' in report
            assert 'whois' in report
            assert 'dns_records' in report
            assert 'subdomains' in report
            
            # Verify summary is calculated correctly
            summary = report['summary']
            assert summary['total_vulnerabilities'] == 1
            assert summary['high_severity'] == 0
            assert summary['open_ports'] == 2
            assert summary['subdomains_found'] == 2
            assert summary['risk_level'] == 'MEDIUM'  # Has vulnerabilities but no high severity