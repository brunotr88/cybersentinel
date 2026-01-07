"""
Test per CyberSentinel Scanner
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

import pytest
from unittest.mock import patch, MagicMock
import socket

import sys
from pathlib import Path

# Aggiungi src al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import PortScanner, PortResult, HostResult, ScanResult
from src.classifier import PortClassifier, RiskLevel, PortInfo


class TestPortScanner:
    """Test per la classe PortScanner"""

    def test_init_default_ports(self):
        """Verifica inizializzazione con porte default"""
        scanner = PortScanner()
        assert len(scanner.ports) == 20
        assert 22 in scanner.ports
        assert 443 in scanner.ports
        assert 3389 in scanner.ports

    def test_init_custom_ports(self):
        """Verifica inizializzazione con porte custom"""
        custom_ports = [80, 443, 8080]
        scanner = PortScanner(ports=custom_ports)
        assert scanner.ports == custom_ports

    def test_validate_target_ip(self):
        """Verifica validazione IP singolo"""
        assert PortScanner.validate_target("192.168.1.1") is True
        assert PortScanner.validate_target("10.0.0.1") is True
        assert PortScanner.validate_target("172.16.0.1") is True

    def test_validate_target_cidr(self):
        """Verifica validazione CIDR"""
        assert PortScanner.validate_target("192.168.1.0/24") is True
        assert PortScanner.validate_target("10.0.0.0/8") is True
        assert PortScanner.validate_target("172.16.0.0/16") is True

    def test_validate_target_invalid(self):
        """Verifica rifiuto target invalidi"""
        assert PortScanner.validate_target("invalid") is False
        assert PortScanner.validate_target("999.999.999.999") is False
        assert PortScanner.validate_target("192.168.1.0/33") is False

    def test_get_local_network(self):
        """Verifica rilevamento rete locale"""
        network = PortScanner.get_local_network()
        assert network.endswith("/24")
        # Deve essere un CIDR valido
        assert PortScanner.validate_target(network) is True

    def test_port_services_mapping(self):
        """Verifica mapping porte-servizi"""
        scanner = PortScanner()
        assert scanner.PORT_SERVICES[22] == "SSH"
        assert scanner.PORT_SERVICES[80] == "HTTP"
        assert scanner.PORT_SERVICES[443] == "HTTPS"
        assert scanner.PORT_SERVICES[3389] == "RDP (Desktop Remoto)"


class TestPortClassifier:
    """Test per la classe PortClassifier"""

    def test_classify_critical_port(self):
        """Verifica classificazione porte critiche"""
        classifier = PortClassifier()

        # Porte che dovrebbero essere critiche
        critical_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900]

        for port in critical_ports:
            info = classifier.classify_port(port)
            assert info.risk_level == RiskLevel.CRITICAL, \
                f"Porta {port} dovrebbe essere CRITICAL"

    def test_classify_warning_port(self):
        """Verifica classificazione porte warning"""
        classifier = PortClassifier()

        warning_ports = [22, 25, 80, 110, 143, 8080]

        for port in warning_ports:
            info = classifier.classify_port(port)
            assert info.risk_level == RiskLevel.WARNING, \
                f"Porta {port} dovrebbe essere WARNING"

    def test_classify_ok_port(self):
        """Verifica classificazione porte OK"""
        classifier = PortClassifier()

        ok_ports = [53, 443, 993, 995]

        for port in ok_ports:
            info = classifier.classify_port(port)
            assert info.risk_level == RiskLevel.OK, \
                f"Porta {port} dovrebbe essere OK"

    def test_classify_unknown_port(self):
        """Verifica classificazione porta sconosciuta"""
        classifier = PortClassifier()

        info = classifier.classify_port(12345)
        assert info.risk_level == RiskLevel.WARNING
        assert "non nel database" in info.risk_explanation.lower()

    def test_risk_labels_italian(self):
        """Verifica etichette italiane"""
        classifier = PortClassifier()

        assert classifier.get_risk_label_italian(RiskLevel.CRITICAL) == "CRITICO"
        assert classifier.get_risk_label_italian(RiskLevel.WARNING) == "ATTENZIONE"
        assert classifier.get_risk_label_italian(RiskLevel.OK) == "OK"

    def test_risk_colors(self):
        """Verifica colori RGB"""
        classifier = PortClassifier()

        # Rosso per critico
        r, g, b = classifier.get_risk_color(RiskLevel.CRITICAL)
        assert r > 200  # Predominanza rosso

        # Verde per OK
        r, g, b = classifier.get_risk_color(RiskLevel.OK)
        assert g > 100  # Predominanza verde


class TestScanResult:
    """Test per ScanResult"""

    def test_to_dict(self):
        """Verifica serializzazione dizionario"""
        from datetime import datetime

        result = ScanResult(target="192.168.1.0/24")
        result.hosts = [
            HostResult(
                ip="192.168.1.1",
                state="up",
                ports=[PortResult(port=80, state="open", service="HTTP")]
            )
        ]
        result.end_time = datetime.now()

        data = result.to_dict()

        assert data["target"] == "192.168.1.0/24"
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["ip"] == "192.168.1.1"
        assert data["hosts"][0]["ports"][0]["port"] == 80


class TestIntegration:
    """Test di integrazione"""

    def test_scan_localhost(self):
        """Test scansione localhost (porta 80 potrebbe essere chiusa)"""
        scanner = PortScanner(ports=[80, 443], timeout=1.0, use_nmap=False)

        # Non solleva eccezioni
        result = scanner.scan("127.0.0.1")

        assert result.target == "127.0.0.1"
        assert result.start_time is not None
        assert result.end_time is not None

    def test_full_pipeline(self):
        """Test pipeline completa: scan -> classify"""
        from datetime import datetime

        # Crea risultato simulato
        result = ScanResult(target="test")
        result.hosts = [
            HostResult(
                ip="192.168.1.100",
                state="up",
                ports=[
                    PortResult(port=22, state="open", service="SSH"),
                    PortResult(port=445, state="open", service="SMB"),
                    PortResult(port=443, state="open", service="HTTPS"),
                ]
            )
        ]

        # Classifica
        classifier = PortClassifier()
        classified = classifier.classify_scan_results(result.hosts)

        assert classified["summary"]["total_open_ports"] == 3
        assert classified["summary"]["critical_count"] == 1  # 445
        assert classified["summary"]["warning_count"] == 1   # 22
        assert classified["summary"]["ok_count"] == 1        # 443


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
