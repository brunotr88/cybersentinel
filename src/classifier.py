"""
Classificatore Rischio Porte - CyberSentinel
Classifica le porte aperte per livello di rischio

Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Tuple


class RiskLevel(Enum):
    """Livelli di rischio per le porte"""
    CRITICAL = "critical"      # Rosso - Rischio critico
    WARNING = "warning"        # Giallo - Richiede attenzione
    OK = "ok"                  # Verde - Generalmente sicuro
    INFO = "info"              # Blu - Informativo


@dataclass
class PortInfo:
    """Informazioni complete su una porta"""
    port: int
    service: str
    risk_level: RiskLevel
    description: str
    recommendation: str
    risk_explanation: str


class PortClassifier:
    """
    Classifica le porte in base al rischio per la sicurezza.
    Orientato alle PMI italiane con descrizioni comprensibili.
    """

    # Database porte con classificazione rischio
    PORT_DATABASE: Dict[int, Tuple[str, RiskLevel, str, str, str]] = {
        # Porta: (servizio, rischio, descrizione, spiegazione_rischio, raccomandazione)

        # CRITICHE (Rosso) - Non dovrebbero MAI essere esposte su Internet
        21: (
            "FTP",
            RiskLevel.CRITICAL,
            "Trasferimento file (protocollo obsoleto)",
            "FTP trasmette dati e password in chiaro. Chiunque sulla rete può intercettare le credenziali.",
            "Disabilitare FTP e usare SFTP (porta 22) o FTPS. Se necessario, limitare l'accesso solo da IP interni."
        ),
        23: (
            "Telnet",
            RiskLevel.CRITICAL,
            "Accesso remoto non cifrato",
            "Telnet non usa crittografia. Password e comandi viaggiano in chiaro sulla rete.",
            "Disabilitare immediatamente Telnet e usare SSH (porta 22) per l'accesso remoto sicuro."
        ),
        135: (
            "RPC/DCOM",
            RiskLevel.CRITICAL,
            "Servizi Windows remoti",
            "Porta usata da molti attacchi automatizzati contro Windows. Vettore comune per malware.",
            "Bloccare sul firewall perimetrale. Non dovrebbe mai essere accessibile da Internet."
        ),
        139: (
            "NetBIOS",
            RiskLevel.CRITICAL,
            "Condivisione file Windows (legacy)",
            "Espone informazioni sulla rete Windows e può permettere accesso non autorizzato alle condivisioni.",
            "Bloccare sul firewall perimetrale. Usare solo in rete interna se necessario."
        ),
        445: (
            "SMB",
            RiskLevel.CRITICAL,
            "Condivisione file e stampanti Windows",
            "Porta bersaglio di ransomware come WannaCry. Vulnerabilità EternalBlue molto sfruttata.",
            "URGENTE: Bloccare sul firewall perimetrale. Mai esporre SMB su Internet. Usare VPN per accesso remoto."
        ),
        1433: (
            "Microsoft SQL Server",
            RiskLevel.CRITICAL,
            "Database Microsoft SQL",
            "Database esposto = accesso diretto ai dati aziendali. Bersaglio frequente di attacchi brute-force.",
            "Mai esporre database su Internet. Usare VPN o tunnel SSH per accesso remoto."
        ),
        3306: (
            "MySQL",
            RiskLevel.CRITICAL,
            "Database MySQL/MariaDB",
            "Come per MSSQL, un database esposto è un rischio gravissimo per i dati aziendali.",
            "Bloccare accesso esterno. Configurare MySQL per ascoltare solo su localhost o IP interni."
        ),
        5432: (
            "PostgreSQL",
            RiskLevel.CRITICAL,
            "Database PostgreSQL",
            "Database esposto permette attacchi diretti ai dati. Rischio furto o cancellazione dati.",
            "Limitare accesso a IP specifici. Usare pg_hba.conf per controllo accessi rigoroso."
        ),
        3389: (
            "RDP",
            RiskLevel.CRITICAL,
            "Desktop Remoto Windows",
            "Bersaglio principale di attacchi ransomware. Vulnerabilità BlueKeep ancora sfruttata. Attacchi brute-force continui.",
            "URGENTE: Non esporre RDP su Internet. Usare VPN + RDP o soluzioni come RD Gateway con autenticazione forte."
        ),
        5900: (
            "VNC",
            RiskLevel.CRITICAL,
            "Controllo remoto schermo",
            "Spesso configurato senza password o con password deboli. Permette controllo totale del computer.",
            "Disabilitare se non necessario. Se serve, usare solo tramite VPN con autenticazione forte."
        ),

        # ATTENZIONE (Giallo) - Richiedono verifica configurazione
        22: (
            "SSH",
            RiskLevel.WARNING,
            "Accesso remoto sicuro",
            "SSH è sicuro se ben configurato, ma espone comunque un punto di accesso. Attacchi brute-force comuni.",
            "Usare autenticazione con chiave (no password). Cambiare porta default. Implementare fail2ban. Limitare IP se possibile."
        ),
        25: (
            "SMTP",
            RiskLevel.WARNING,
            "Invio email",
            "Se mal configurato può essere usato come relay per spam, causando blacklist dell'IP aziendale.",
            "Verificare che l'autenticazione sia richiesta. Controllare che non sia un open relay."
        ),
        80: (
            "HTTP",
            RiskLevel.WARNING,
            "Sito web non cifrato",
            "Il traffico HTTP viaggia in chiaro. Form di login e dati sensibili possono essere intercettati.",
            "Configurare redirect automatico a HTTPS. Non trasmettere mai dati sensibili su HTTP."
        ),
        110: (
            "POP3",
            RiskLevel.WARNING,
            "Ricezione email (non cifrato)",
            "Le email e le credenziali viaggiano in chiaro sulla rete.",
            "Migrare a POP3S (porta 995) o IMAPS (porta 993) per connessioni cifrate."
        ),
        143: (
            "IMAP",
            RiskLevel.WARNING,
            "Ricezione email (non cifrato)",
            "Come POP3, le credenziali e i messaggi non sono protetti durante il trasporto.",
            "Usare IMAPS (porta 993) per connessioni sicure. Disabilitare IMAP non cifrato."
        ),
        8080: (
            "HTTP Alternativo",
            RiskLevel.WARNING,
            "Sito web/applicazione su porta alternativa",
            "Spesso usata per interfacce di amministrazione o proxy. Potrebbe esporre pannelli di controllo.",
            "Verificare cosa è in ascolto. Proteggere con autenticazione. Considerare di limitare gli IP di accesso."
        ),

        # OK (Verde) - Generalmente sicure se aggiornate
        53: (
            "DNS",
            RiskLevel.OK,
            "Risoluzione nomi dominio",
            "Necessario per server DNS. Verificare che non sia un resolver aperto sfruttabile per attacchi DDoS.",
            "Se non è un server DNS pubblico, bloccare dall'esterno. Se lo è, configurare rate limiting."
        ),
        443: (
            "HTTPS",
            RiskLevel.OK,
            "Sito web cifrato",
            "Traffico cifrato, generalmente sicuro. La sicurezza dipende dalla configurazione del certificato e del server.",
            "Mantenere certificato SSL aggiornato. Usare TLS 1.2+. Verificare configurazione con SSL Labs."
        ),
        993: (
            "IMAPS",
            RiskLevel.OK,
            "Email cifrata (IMAP sicuro)",
            "Versione sicura di IMAP con crittografia TLS.",
            "Mantenere il server email aggiornato. Verificare validità certificato."
        ),
        995: (
            "POP3S",
            RiskLevel.OK,
            "Email cifrata (POP3 sicuro)",
            "Versione sicura di POP3 con crittografia TLS.",
            "Considerare migrazione a IMAP per funzionalità migliori. Mantenere server aggiornato."
        ),
    }

    def __init__(self):
        """Inizializza il classificatore"""
        pass

    def classify_port(self, port: int, service: str = "") -> PortInfo:
        """
        Classifica una singola porta

        Args:
            port: Numero porta
            service: Nome servizio (opzionale, per override)

        Returns:
            Informazioni complete sulla porta
        """
        if port in self.PORT_DATABASE:
            svc, risk, desc, explanation, recommendation = self.PORT_DATABASE[port]
            return PortInfo(
                port=port,
                service=service or svc,
                risk_level=risk,
                description=desc,
                risk_explanation=explanation,
                recommendation=recommendation
            )

        # Porta sconosciuta
        return PortInfo(
            port=port,
            service=service or "Sconosciuto",
            risk_level=RiskLevel.WARNING,
            description=f"Servizio non identificato sulla porta {port}",
            risk_explanation="Porta non nel database standard. Potrebbe essere un servizio personalizzato o potenzialmente pericoloso.",
            recommendation=f"Verificare quale servizio è in ascolto sulla porta {port}. Se non necessario, chiuderla."
        )

    def classify_scan_results(self, hosts: List) -> Dict:
        """
        Classifica tutti i risultati di una scansione

        Args:
            hosts: Lista di HostResult dalla scansione

        Returns:
            Dizionario con classificazione completa
        """
        results = {
            "critical": [],
            "warning": [],
            "ok": [],
            "summary": {
                "total_hosts": len(hosts),
                "total_open_ports": 0,
                "critical_count": 0,
                "warning_count": 0,
                "ok_count": 0,
                "risk_score": 0
            }
        }

        for host in hosts:
            for port_result in host.ports:
                if port_result.state != "open":
                    continue

                port_info = self.classify_port(
                    port_result.port,
                    port_result.service
                )

                entry = {
                    "host": host.ip,
                    "hostname": host.hostname,
                    "port_info": port_info,
                    "version": getattr(port_result, 'version', '')
                }

                results["summary"]["total_open_ports"] += 1

                if port_info.risk_level == RiskLevel.CRITICAL:
                    results["critical"].append(entry)
                    results["summary"]["critical_count"] += 1
                    results["summary"]["risk_score"] += 30
                elif port_info.risk_level == RiskLevel.WARNING:
                    results["warning"].append(entry)
                    results["summary"]["warning_count"] += 1
                    results["summary"]["risk_score"] += 10
                else:
                    results["ok"].append(entry)
                    results["summary"]["ok_count"] += 1

        # Normalizza risk_score a 0-100
        max_possible = results["summary"]["total_open_ports"] * 30
        if max_possible > 0:
            results["summary"]["risk_score"] = min(100, int(
                (results["summary"]["risk_score"] / max_possible) * 100
            ))
        else:
            results["summary"]["risk_score"] = 0

        return results

    def get_risk_color(self, risk_level: RiskLevel) -> Tuple[int, int, int]:
        """
        Restituisce colore RGB per il livello di rischio

        Args:
            risk_level: Livello di rischio

        Returns:
            Tupla RGB
        """
        colors = {
            RiskLevel.CRITICAL: (220, 53, 69),    # Rosso
            RiskLevel.WARNING: (255, 193, 7),     # Giallo
            RiskLevel.OK: (40, 167, 69),          # Verde
            RiskLevel.INFO: (23, 162, 184),       # Blu
        }
        return colors.get(risk_level, (108, 117, 125))  # Grigio default

    def get_risk_label_italian(self, risk_level: RiskLevel) -> str:
        """
        Restituisce etichetta italiana per il livello di rischio

        Args:
            risk_level: Livello di rischio

        Returns:
            Etichetta in italiano
        """
        labels = {
            RiskLevel.CRITICAL: "CRITICO",
            RiskLevel.WARNING: "ATTENZIONE",
            RiskLevel.OK: "OK",
            RiskLevel.INFO: "INFO",
        }
        return labels.get(risk_level, "N/D")

    def calculate_overall_risk(self, classified_results: Dict) -> str:
        """
        Calcola valutazione complessiva del rischio

        Args:
            classified_results: Risultati classificati

        Returns:
            Descrizione testuale del rischio
        """
        score = classified_results["summary"]["risk_score"]
        critical = classified_results["summary"]["critical_count"]

        if critical > 0 or score >= 70:
            return "ALTO - Intervento immediato necessario"
        elif score >= 40:
            return "MEDIO - Verifiche consigliate"
        elif score >= 20:
            return "BASSO - Alcune attenzioni richieste"
        else:
            return "MINIMO - Situazione sotto controllo"


def main():
    """Test del classificatore"""
    classifier = PortClassifier()

    print("=" * 60)
    print("CyberSentinel - Test Classificatore")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)

    # Test porte comuni
    test_ports = [21, 22, 80, 443, 445, 3389, 8080, 9999]

    for port in test_ports:
        info = classifier.classify_port(port)
        label = classifier.get_risk_label_italian(info.risk_level)
        print(f"\nPorta {port} ({info.service}):")
        print(f"  Rischio: {label}")
        print(f"  Descrizione: {info.description}")
        print(f"  Raccomandazione: {info.recommendation[:80]}...")


if __name__ == "__main__":
    main()
