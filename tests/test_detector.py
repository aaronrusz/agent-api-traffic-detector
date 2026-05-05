from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR

from agent_api_traffic_detector.detector import AgentApiTrafficDetector


def test_detect_agent_protocols_with_port():
    detector = AgentApiTrafficDetector(quiet=True, no_log=True)
    packet = IP(src='203.0.113.1') / TCP(dport=8080)
    alerts = detector.detect_agent_protocols(packet)
    assert any('Agent/API port traffic' in alert for alert in alerts)


def test_detect_protocol_signatures_with_payload():
    detector = AgentApiTrafficDetector(quiet=True, no_log=True)
    packet = IP(src='203.0.113.2') / TCP(dport=443) / Raw(load=b'GET / HTTP/1.1\r\nHost: api.openai.com\r\n')
    alerts = detector.detect_protocol_signatures(packet)
    assert any('Agent/API domain detected' in alert for alert in alerts)


def test_detect_ai_service_dns():
    detector = AgentApiTrafficDetector(quiet=True, no_log=True)
    packet = IP(src='203.0.113.3') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='api.openai.com.'))
    alerts = detector.detect_ai_service_dns(packet)
    assert isinstance(alerts, list)
