#!/usr/bin/env python3
"""
CyberSentinel - Scanner porte di rete per PMI italiane
La sentinella digitale che protegge la tua rete aziendale

Uso:
    python run.py --target 192.168.1.0/24 --output report.pdf
    python run.py --auto-detect --output report.pdf
    python run.py --target server.example.com

Sviluppato da ISIPC - Truant Bruno
https://isipc.com | https://github.com/brunotr88
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def print_banner():
    """Stampa banner applicazione"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗                ║
    ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗               ║
    ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝               ║
    ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗               ║
    ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║               ║
    ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝               ║
    ║                                                           ║
    ║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗       ║
    ║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║       ║
    ║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║       ║
    ║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║       ║
    ║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║       ║
    ║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝       ║
    ║                                                           ║
    ║   La sentinella digitale per le PMI italiane     v1.0.0  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """

    if HAS_COLOR:
        print(Fore.CYAN + banner + Style.RESET_ALL)
    else:
        print(banner)

    print("  Sviluppato da ISIPC - Truant Bruno")
    print("  https://isipc.com | https://github.com/brunotr88")
    print()


def print_colored(text: str, color: str = "white"):
    """Stampa testo colorato"""
    if HAS_COLOR:
        colors = {
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE,
        }
        print(colors.get(color, Fore.WHITE) + text + Style.RESET_ALL)
    else:
        print(text)


def main():
    """Funzione principale"""
    parser = argparse.ArgumentParser(
        description="CyberSentinel - Scanner porte di rete per PMI italiane",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  %(prog)s --target 192.168.1.0/24 --output report.pdf
  %(prog)s --target 192.168.1.100
  %(prog)s --auto-detect --output analisi_rete.pdf
  %(prog)s --target server.local --quick

Sviluppato da ISIPC - Truant Bruno | https://isipc.com
        """
    )

    parser.add_argument(
        "-t", "--target",
        help="Target da scansionare (IP, CIDR o hostname)"
    )

    parser.add_argument(
        "-a", "--auto-detect",
        action="store_true",
        help="Rileva automaticamente la rete locale"
    )

    parser.add_argument(
        "-o", "--output",
        default="cybersentinel_report.pdf",
        help="File PDF di output (default: cybersentinel_report.pdf)"
    )

    parser.add_argument(
        "--json",
        help="Salva anche risultati in formato JSON"
    )

    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Scansione veloce (solo porte critiche)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout per connessione in secondi (default: 2.0)"
    )

    parser.add_argument(
        "--no-nmap",
        action="store_true",
        help="Non usare nmap anche se disponibile"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Output dettagliato"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="CyberSentinel v1.0.0 - ISIPC - Truant Bruno"
    )

    args = parser.parse_args()

    # Mostra banner
    print_banner()

    # Importa moduli (qui per velocizzare --help)
    from src.scanner import PortScanner
    from src.classifier import PortClassifier
    from src.report_generator import ReportGenerator

    # Determina target
    if args.auto_detect:
        target = PortScanner.get_local_network()
        print_colored(f"[*] Rete locale rilevata: {target}", "cyan")
    elif args.target:
        target = args.target
    else:
        print_colored("[!] Errore: specificare --target o --auto-detect", "red")
        parser.print_help()
        sys.exit(1)

    # Valida target
    if not PortScanner.validate_target(target):
        print_colored(f"[!] Target non valido: {target}", "red")
        sys.exit(1)

    # Configura porte
    if args.quick:
        # Porte critiche per scan veloce
        ports = [21, 22, 23, 80, 443, 445, 3389, 3306, 1433, 5900]
        print_colored("[*] Modalità veloce: solo 10 porte critiche", "yellow")
    else:
        ports = None  # Usa default (20 porte)

    # Crea scanner
    scanner = PortScanner(
        ports=ports,
        timeout=args.timeout,
        use_nmap=not args.no_nmap
    )

    # Info nmap
    if scanner._nmap_available and not args.no_nmap:
        print_colored("[+] Nmap rilevato: scansione avanzata attiva", "green")
    else:
        print_colored("[*] Uso scansione socket Python", "yellow")

    print()
    print_colored(f"[*] Avvio scansione: {target}", "cyan")
    print_colored(f"[*] Porte da verificare: {len(scanner.ports)}", "cyan")
    print()

    # Progress callback
    start_time = datetime.now()

    def progress_callback(current, total, ip):
        elapsed = (datetime.now() - start_time).seconds
        if args.verbose:
            print(f"    Scansione {ip} ({current}/{total}) - {elapsed}s trascorsi")

    # Esegui scansione
    try:
        result = scanner.scan(
            target,
            progress_callback=progress_callback
        )
    except KeyboardInterrupt:
        print_colored("\n[!] Scansione interrotta dall'utente", "yellow")
        sys.exit(130)
    except Exception as e:
        print_colored(f"\n[!] Errore durante la scansione: {e}", "red")
        sys.exit(1)

    # Mostra risultati
    print()
    print_colored("=" * 60, "cyan")
    print_colored("RISULTATI SCANSIONE", "cyan")
    print_colored("=" * 60, "cyan")

    # Classifica risultati
    classifier = PortClassifier()
    classified = classifier.classify_scan_results(result.hosts)

    # Statistiche
    summary = classified['summary']
    print()
    print(f"  Host scansionati con porte aperte: {summary['total_hosts']}")
    print(f"  Totale porte aperte trovate: {summary['total_open_ports']}")
    print()

    if summary['critical_count'] > 0:
        print_colored(f"  [!] PROBLEMI CRITICI: {summary['critical_count']}", "red")
    if summary['warning_count'] > 0:
        print_colored(f"  [!] ATTENZIONE: {summary['warning_count']}", "yellow")
    if summary['ok_count'] > 0:
        print_colored(f"  [+] OK: {summary['ok_count']}", "green")

    print()

    # Dettaglio critici
    if classified['critical']:
        print_colored("  Problemi critici trovati:", "red")
        for item in classified['critical']:
            port_info = item['port_info']
            print_colored(
                f"    - {item['host']}: Porta {port_info.port} ({port_info.service})",
                "red"
            )
        print()

    # Genera report PDF
    print_colored(f"[*] Generazione report PDF: {args.output}", "cyan")

    try:
        generator = ReportGenerator()
        output_path = generator.generate(result, args.output)
        print_colored(f"[+] Report generato: {output_path}", "green")
    except Exception as e:
        print_colored(f"[!] Errore generazione PDF: {e}", "red")
        print_colored("[*] Installa reportlab: pip install reportlab", "yellow")

    # Salva JSON se richiesto
    if args.json:
        try:
            result.to_json(args.json)
            print_colored(f"[+] JSON salvato: {args.json}", "green")
        except Exception as e:
            print_colored(f"[!] Errore salvataggio JSON: {e}", "red")

    # Tempo totale
    total_time = (datetime.now() - start_time).seconds
    print()
    print_colored(f"[*] Scansione completata in {total_time} secondi", "cyan")

    # Valutazione rischio
    print()
    if summary['critical_count'] > 0:
        print_colored(
            "[!] ATTENZIONE: Trovate vulnerabilità critiche!",
            "red"
        )
        print_colored(
            "    Consulta il report PDF per le raccomandazioni.",
            "yellow"
        )
    elif summary['warning_count'] > 0:
        print_colored(
            "[*] Alcune configurazioni richiedono attenzione.",
            "yellow"
        )
    else:
        print_colored(
            "[+] La rete appare ben configurata.",
            "green"
        )

    print()
    print("  Grazie per aver usato CyberSentinel!")
    print("  ISIPC - Truant Bruno | https://isipc.com")
    print()


if __name__ == "__main__":
    main()
