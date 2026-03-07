import nmap
import psutil
import socket
import requests
from datetime import datetime
import subprocess
import platform
import os

class DataCollector:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def scan_network(self, target="127.0.0.1"):
        """Scan network for open ports and services"""
        try:
            self.nm.scan(target, arguments='-T4 -F')
            open_ports = 0
            critical_ports = 0
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    open_ports += len(ports)
                    
                    # Check for critical ports
                    critical_port_list = [21, 22, 23, 3389, 445, 1433, 3306, 5432]
                    critical_ports += sum(1 for port in ports if port in critical_port_list)
                    
            return {
                "open_ports": open_ports,
                "critical_ports": critical_ports
            }
        except Exception as e:
            print(f"Network scan error: {e}")
            return {"open_ports": 0, "critical_ports": 0}
    
    def check_system_updates(self):
        """Check system patch status"""
        try:
            if platform.system() == "Windows":
                # Windows update check
                result = subprocess.run(["wmic", "qfe", "list", "brief"], 
                                      capture_output=True, text=True)
                patches = len(result.stdout.split('\n')) - 2
            else:
                # Linux update check
                result = subprocess.run(["apt", "list", "--upgradable"], 
                                      capture_output=True, text=True)
                patches = len(result.stdout.split('\n')) - 1
            
            return {
                "patches_installed": patches,
                "patches_missing": max(0, 20 - patches)  # Assume 20 is baseline
            }
        except Exception as e:
            print(f"Update check error: {e}")
            return {"patches_installed": 0, "patches_missing": 10}
    
    def check_firewall_status(self):
        """Check if firewall is enabled"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], 
                                      capture_output=True, text=True)
                return "ON" in result.stdout
            else:
                result = subprocess.run(["sudo", "ufw", "status"], 
                                      capture_output=True, text=True)
                return "active" in result.stdout
        except:
            return False
    
    def get_authentication_logs(self):
        """Get failed login attempts"""
        try:
            if platform.system() == "Windows":
                # Check Windows Event Log for failed logins
                result = subprocess.run(
                    ['wevtutil', 'qe', 'Security', '/q:', "*[System[(EventID=4625)]]", '/c:10'],
                    capture_output=True, text=True
                )
                failed_logins = result.stdout.count('EventID')
            else:
                # Check Linux auth log
                if os.path.exists('/var/log/auth.log'):
                    with open('/var/log/auth.log', 'r') as f:
                        content = f.read()
                        failed_logins = content.count('Failed password')
                else:
                    failed_logins = 0
                    
            return failed_logins
        except:
            return 0
    
    def collect_system_metrics(self):
        """Collect system performance metrics"""
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_connections": len(psutil.net_connections()),
            "running_processes": len(psutil.pids())
        }
    
    def check_malware_indicators(self):
        """Check for potential malware indicators"""
        indicators = 0
        suspicious_processes = ['keylogger', 'spyware', 'miner']
        
        # Check running processes
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                if any(suspect in proc_name for suspect in suspicious_processes):
                    indicators += 1
            except:
                pass
        
        return indicators
    
    def perform_full_assessment(self, system_id="host-01"):
        """Perform complete system assessment"""
        network_data = self.scan_network()
        update_data = self.check_system_updates()
        firewall_status = self.check_firewall_status()
        failed_logins = self.get_authentication_logs()
        malware_indicators = self.check_malware_indicators()
        system_metrics = self.collect_system_metrics()
        
        # Simulate password strength (would integrate with actual password policy)
        password_strength = 65  # Placeholder
        
        # Simulate suspicious IPs
        suspicious_ips = 2  # Placeholder
        
        # Simulate traffic anomaly
        traffic_anomaly = 0.3  # Placeholder
        
        return {
            "system_id": system_id,
            "password_strength": password_strength,
            "failed_logins": failed_logins,
            "open_ports": network_data["open_ports"],
            "critical_ports": network_data["critical_ports"],
            "firewall_enabled": firewall_status,
            "patches_installed": update_data["patches_installed"],
            "patches_missing": update_data["patches_missing"],
            "suspicious_ips": suspicious_ips,
            "traffic_anomaly_score": traffic_anomaly,
            "malware_indicators": malware_indicators,
            "antivirus_enabled": True,  # Placeholder
            "encryption_enabled": True,  # Placeholder
            "cpu_usage": system_metrics["cpu_usage"],
            "memory_usage": system_metrics["memory_usage"]
        }