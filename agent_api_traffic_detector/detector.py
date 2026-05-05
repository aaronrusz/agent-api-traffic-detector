import logging
import os
import re
import psutil
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw


class AgentApiTrafficDetector:
    def __init__(self, interface=None, quiet=False, no_log=False, log_file='agent_api_traffic.log', daemon=False):
        self.interface = interface
        self.quiet = quiet
        self.no_log = no_log
        self.log_file = log_file
        self.daemon = daemon
        self.agent_protocols = {
            'openai': ['api.openai.com', 'openai.com'],
            'anthropic': ['api.anthropic.com', 'claude.ai'],
            'google_ai': ['generativelanguage.googleapis.com', 'bard.google.com'],
            'azure_openai': ['openai.azure.com'],
            'huggingface': ['huggingface.co', 'api-inference.huggingface.co'],
        }
        self.agent_ports = [8080, 8081, 8082, 9090, 9091, 5000, 5001]
        self.connection_counts = defaultdict(int)
        self.alerts = []
        self.logger = self._configure_logging()

    def _configure_logging(self):
        handlers = []
        if not self.no_log:
            handlers.append(logging.FileHandler(self.log_file))
        if not self.quiet:
            handlers.append(logging.StreamHandler())

        if handlers:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=handlers)
        else:
            logging.disable(logging.CRITICAL)

        return logging.getLogger(__name__)

    def get_network_interfaces(self):
        return list(psutil.net_if_addrs().keys())

    def detect_agent_protocols(self, packet):
        alerts = []
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            if dst_port in self.agent_ports:
                conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                self.connection_counts[conn_key] += 1
                alerts.append(f"Agent/API port traffic: {conn_key}")
                if self.connection_counts[conn_key] > 50:
                    alerts.append(f"High-frequency agent/API traffic: {conn_key} ({self.connection_counts[conn_key]})")
        return alerts

    def detect_protocol_signatures(self, packet):
        alerts = []
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            text = payload.decode('utf-8', errors='ignore')
            for name, domains in self.agent_protocols.items():
                for domain in domains:
                    if domain in text:
                        alerts.append(f"Agent/API domain detected: {name} in packet payload")
            if re.search(r'"method"\s*:\s*"agent\.', text, re.IGNORECASE):
                alerts.append('Agent JSON-RPC traffic detected')
        return alerts

    def detect_ai_service_dns(self, packet):
        alerts = []
        if packet.haslayer(IP) and packet.haslayer(DNS) and packet[DNS].qr == 0:
            query = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            for name, domains in self.agent_protocols.items():
                for domain in domains:
                    if domain in query:
                        alerts.append(f"AI service DNS query: {name} - {query}")
        return alerts

    def packet_handler(self, packet):
        try:
            alerts = []
            alerts.extend(self.detect_agent_protocols(packet))
            alerts.extend(self.detect_protocol_signatures(packet))
            alerts.extend(self.detect_ai_service_dns(packet))
            for alert in alerts:
                self.logger.warning(f"ALERT: {alert}")
                self.alerts.append({'timestamp': datetime.now().isoformat(), 'alert': alert})
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def start_monitoring(self):
        if self.daemon:
            self._daemonize()

        if not self.interface:
            interfaces = self.get_network_interfaces()
            self.interface = interfaces[0] if interfaces else None

        if not self.quiet:
            print(f"Starting agent/API detector on {self.interface or 'all interfaces'}")

        sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: False)

    def _daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                raise SystemExit(0)
        except OSError as exc:
            self.logger.error(f"Failed to daemonize: {exc}")
            raise
