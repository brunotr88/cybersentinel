"""
Scanner Engine - Modulo principale per la scansione delle porte
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

import socket
import subprocess
import sys
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import json


@dataclass
class PortResult:
    """Risultato scansione singola porta"""
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    version: str = ""
    protocol: str = "tcp"


@dataclass
class HostResult:
    """Risultato scansione singolo host"""
    ip: str
    hostname: str = ""
    state: str = "unknown"  # up, down
    ports: List[PortResult] = field(default_factory=list)
    scan_time: float = 0.0


@dataclass
class ScanResult:
    """Risultato completo della scansione"""
    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    hosts: List[HostResult] = field(default_factory=list)
    scanner_version: str = "1.0.0"

    def to_dict(self) -> Dict:
        """Converte in dizionario per serializzazione JSON"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scanner_version": self.scanner_version,
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "state": h.state,
                    "scan_time": h.scan_time,
                    "ports": [
                        {
                            "port": p.port,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "protocol": p.protocol
                        }
                        for p in h.ports
                    ]
                }
                for h in self.hosts
            ]
        }

    def to_json(self, filepath: str) -> None:
        """Salva risultati in formato JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


class PortScanner:
    """
    Scanner porte di rete per PMI
    Supporta scansione di IP singoli, range CIDR e hostname
    """

    # Porte predefinite per PMI
    DEFAULT_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080,  # HTTP-Alt
    ]

    # Servizi noti per porta
    PORT_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "RPC/DCOM",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "Microsoft SQL Server",
        3306: "MySQL",
        3389: "RDP (Desktop Remoto)",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Alternativo",
    }

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        use_nmap: bool = True
    ):
        """
        Inizializza lo scanner

        Args:
            ports: Lista porte da scansionare (default: porte PMI)
            timeout: Timeout connessione in secondi
            use_nmap: Usa nmap se disponibile (più accurato)
        """
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.use_nmap = use_nmap and self._check_nmap()
        self._nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Verifica se nmap è installato"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def get_local_network() -> str:
        """
        Rileva automaticamente la rete locale

        Returns:
            Range CIDR della rete locale (es: 192.168.1.0/24)
        """
        try:
            # Crea socket per ottenere IP locale
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            # Connessione fittizia per ottenere IP locale
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Calcola range /24
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"  # Fallback comune

    @staticmethod
    def validate_target(target: str) -> bool:
        """
        Valida il target (IP, CIDR, hostname)

        Args:
            target: Target da validare

        Returns:
            True se valido
        """
        # Prova come rete CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass

        # Prova come IP singolo
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        # Prova come hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            pass

        return False

    def _get_hosts_from_target(self, target: str) -> List[str]:
        """
        Estrae lista IP dal target

        Args:
            target: IP, CIDR o hostname

        Returns:
            Lista di IP da scansionare
        """
        # Prova come rete CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            # Limita a 1024 host per sicurezza
            hosts = list(network.hosts())
            if len(hosts) > 1024:
                print(f"[!] Attenzione: range troppo grande ({len(hosts)} host), limitato a 1024")
                hosts = hosts[:1024]
            return [str(ip) for ip in hosts]
        except ValueError:
            pass

        # Prova come IP singolo
        try:
            ip = ipaddress.ip_address(target)
            return [str(ip)]
        except ValueError:
            pass

        # Prova come hostname
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except socket.gaierror:
            return []

    def _scan_port_socket(self, ip: str, port: int) -> PortResult:
        """
        Scansiona singola porta con socket Python

        Args:
            ip: Indirizzo IP
            port: Numero porta

        Returns:
            Risultato scansione
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                return PortResult(
                    port=port,
                    state="open",
                    service=self.PORT_SERVICES.get(port, "unknown")
                )
            else:
                return PortResult(port=port, state="closed")

        except socket.timeout:
            return PortResult(port=port, state="filtered")
        except Exception:
            return PortResult(port=port, state="error")

    def _scan_host_socket(self, ip: str, callback=None) -> HostResult:
        """
        Scansiona host con socket Python

        Args:
            ip: Indirizzo IP
            callback: Funzione callback per progress

        Returns:
            Risultato scansione host
        """
        import time
        start = time.time()

        # Verifica se host è raggiungibile
        host_up = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            # Prova porta comune per verificare se host è up
            for test_port in [80, 443, 22, 445]:
                if sock.connect_ex((ip, test_port)) == 0:
                    host_up = True
                    break
            sock.close()
        except Exception:
            pass

        # Se host sembra down, prova comunque le porte
        if not host_up:
            # Tenta ping
            try:
                if sys.platform == "win32":
                    ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
                else:
                    ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
                result = subprocess.run(ping_cmd, capture_output=True, timeout=3)
                host_up = result.returncode == 0
            except Exception:
                pass

        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        ports = []
        for i, port in enumerate(self.ports):
            result = self._scan_port_socket(ip, port)
            if result.state == "open":
                ports.append(result)
                host_up = True  # Se una porta è aperta, host è up
            if callback:
                callback(ip, port, i + 1, len(self.ports))

        return HostResult(
            ip=ip,
            hostname=hostname,
            state="up" if host_up else "down",
            ports=ports,
            scan_time=time.time() - start
        )

    def _scan_with_nmap(self, target: str, callback=None) -> List[HostResult]:
        """
        Scansiona con nmap (più accurato)

        Args:
            target: Target da scansionare
            callback: Funzione callback per progress

        Returns:
            Lista risultati host
        """
        import time

        ports_str = ",".join(str(p) for p in self.ports)

        # Costruisci comando nmap
        cmd = [
            "nmap",
            "-sT",  # TCP connect scan (non richiede root)
            "-sV",  # Version detection
            "-p", ports_str,
            "--open",  # Solo porte aperte
            "-T4",  # Timing aggressivo
            "-oX", "-",  # Output XML su stdout
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minuti max
            )

            if result.returncode != 0:
                return []

            # Parse XML output
            return self._parse_nmap_xml(result.stdout)

        except subprocess.TimeoutExpired:
            print("[!] Timeout nmap, uso fallback socket")
            return []
        except Exception as e:
            print(f"[!] Errore nmap: {e}, uso fallback socket")
            return []

    def _parse_nmap_xml(self, xml_output: str) -> List[HostResult]:
        """
        Parsa output XML di nmap

        Args:
            xml_output: Output XML

        Returns:
            Lista risultati host
        """
        import xml.etree.ElementTree as ET

        results = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall(".//host"):
                # Stato host
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                # IP
                address = host.find("address[@addrtype='ipv4']")
                if address is None:
                    continue
                ip = address.get("addr")

                # Hostname
                hostname = ""
                hostnames = host.find("hostnames/hostname")
                if hostnames is not None:
                    hostname = hostnames.get("name", "")

                # Porte
                ports = []
                for port in host.findall(".//port"):
                    port_num = int(port.get("portid"))
                    state = port.find("state")
                    service = port.find("service")

                    port_result = PortResult(
                        port=port_num,
                        state=state.get("state") if state is not None else "unknown",
                        protocol=port.get("protocol", "tcp")
                    )

                    if service is not None:
                        port_result.service = service.get("name", self.PORT_SERVICES.get(port_num, ""))
                        port_result.version = service.get("version", "")
                        product = service.get("product", "")
                        if product:
                            port_result.version = f"{product} {port_result.version}".strip()
                    else:
                        port_result.service = self.PORT_SERVICES.get(port_num, "")

                    if port_result.state == "open":
                        ports.append(port_result)

                results.append(HostResult(
                    ip=ip,
                    hostname=hostname,
                    state="up",
                    ports=ports
                ))

        except ET.ParseError as e:
            print(f"[!] Errore parsing XML nmap: {e}")

        return results

    def scan(
        self,
        target: str,
        callback=None,
        progress_callback=None
    ) -> ScanResult:
        """
        Esegue scansione completa

        Args:
            target: IP, CIDR o hostname
            callback: Callback per ogni porta scansionata
            progress_callback: Callback per progress globale

        Returns:
            Risultato scansione
        """
        from datetime import datetime

        if not self.validate_target(target):
            raise ValueError(f"Target non valido: {target}")

        result = ScanResult(target=target, start_time=datetime.now())

        # Prova con nmap se disponibile
        if self.use_nmap and self._nmap_available:
            print(f"[*] Scansione con nmap: {target}")
            hosts = self._scan_with_nmap(target, callback)
            if hosts:
                result.hosts = hosts
                result.end_time = datetime.now()
                return result

        # Fallback a socket
        print(f"[*] Scansione con socket Python: {target}")
        ip_list = self._get_hosts_from_target(target)

        total_hosts = len(ip_list)
        for i, ip in enumerate(ip_list):
            if progress_callback:
                progress_callback(i + 1, total_hosts, ip)

            print(f"[*] Scansione {ip} ({i+1}/{total_hosts})")
            host_result = self._scan_host_socket(ip, callback)

            # Aggiungi solo host con porte aperte o esplicitamente up
            if host_result.ports or host_result.state == "up":
                result.hosts.append(host_result)

        result.end_time = datetime.now()
        return result


def main():
    """Test base dello scanner"""
    scanner = PortScanner()

    print("=" * 50)
    print("PMI Port Scanner - Test")
    print("Sviluppato da ISIPC - Truant Bruno")
    print("https://isipc.com")
    print("=" * 50)

    # Rileva rete locale
    local_net = scanner.get_local_network()
    print(f"\nRete locale rilevata: {local_net}")
    print(f"Nmap disponibile: {scanner._nmap_available}")

    # Test su localhost
    print("\nTest scansione localhost...")
    result = scanner.scan("127.0.0.1")

    print(f"\nRisultati per {result.target}:")
    for host in result.hosts:
        print(f"  Host: {host.ip} ({host.hostname or 'N/A'})")
        print(f"  Stato: {host.state}")
        for port in host.ports:
            print(f"    Porta {port.port}/{port.protocol}: {port.state} - {port.service}")


if __name__ == "__main__":
    main()
