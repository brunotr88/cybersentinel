# CyberSentinel

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Made in Italy](https://img.shields.io/badge/Made%20in-Italy%20🇮🇹-red.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

**La sentinella digitale che protegge la tua rete aziendale**

Scanner porte di rete professionale pensato per le PMI italiane. Genera report PDF chiari e comprensibili anche per chi non è un esperto di informatica.

---

## 🎯 A cosa serve?

CyberSentinel analizza la tua rete aziendale per trovare **porte aperte** che potrebbero rappresentare un rischio di sicurezza. Pensa alle porte di rete come alle porte di un edificio: alcune devono restare aperte per lavorare, ma altre andrebbero chiuse per evitare intrusioni.

Il report generato ti dice:
- ✅ **Quali porte sono aperte** nella tua rete
- 🔴 **Quali sono pericolose** e vanno chiuse subito
- 🟡 **Quali richiedono attenzione**
- 🟢 **Quali sono sicure**
- 📋 **Cosa fare** per ogni problema trovato

---

## 📸 Esempio Report

Il report PDF include:
- Riepilogo esecutivo con punteggio rischio
- Problemi critici con spiegazioni semplici
- Raccomandazioni concrete
- Tutto in italiano, senza tecnicismi inutili

---

## 🚀 Installazione

### Requisiti
- Python 3.8 o superiore
- (Opzionale) Nmap per scansioni più accurate

### Installazione rapida

```bash
# Clona il repository
git clone https://github.com/brunotr88/cybersentinel.git
cd cybersentinel

# Installa dipendenze
pip install -r requirements.txt
```

### Installazione Nmap (opzionale ma consigliato)

**Windows:**
Scarica da [nmap.org/download](https://nmap.org/download.html)

**Linux (Debian/Ubuntu):**
```bash
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

---

## 📖 Uso

### Scansione rete locale (auto-detect)

```bash
python run.py --auto-detect --output report.pdf
```

### Scansione range specifico

```bash
python run.py --target 192.168.1.0/24 --output report.pdf
```

### Scansione singolo IP

```bash
python run.py --target 192.168.1.100 --output report.pdf
```

### Scansione hostname

```bash
python run.py --target server.miazienda.local --output report.pdf
```

### Modalità veloce (solo porte critiche)

```bash
python run.py --target 10.0.0.0/24 --quick --output report.pdf
```

### Salva anche in JSON

```bash
python run.py --target 192.168.1.0/24 --output report.pdf --json risultati.json
```

---

## ⚙️ Opzioni

| Opzione | Descrizione |
|---------|-------------|
| `-t, --target` | Target da scansionare (IP, CIDR o hostname) |
| `-a, --auto-detect` | Rileva automaticamente la rete locale |
| `-o, --output` | File PDF di output (default: cybersentinel_report.pdf) |
| `--json` | Salva risultati anche in formato JSON |
| `-q, --quick` | Scansione veloce (solo 10 porte critiche) |
| `--timeout` | Timeout connessione in secondi (default: 2.0) |
| `--no-nmap` | Non usare nmap anche se disponibile |
| `-v, --verbose` | Output dettagliato |
| `--version` | Mostra versione |

---

## 🔍 Porte Analizzate

CyberSentinel analizza le 20 porte più importanti per la sicurezza delle PMI:

| Porta | Servizio | Rischio se esposta |
|-------|----------|-------------------|
| 21 | FTP | 🔴 Critico |
| 22 | SSH | 🟡 Attenzione |
| 23 | Telnet | 🔴 Critico |
| 25 | SMTP | 🟡 Attenzione |
| 53 | DNS | 🟢 OK |
| 80 | HTTP | 🟡 Attenzione |
| 110 | POP3 | 🟡 Attenzione |
| 135 | RPC | 🔴 Critico |
| 139 | NetBIOS | 🔴 Critico |
| 143 | IMAP | 🟡 Attenzione |
| 443 | HTTPS | 🟢 OK |
| 445 | SMB | 🔴 Critico |
| 993 | IMAPS | 🟢 OK |
| 995 | POP3S | 🟢 OK |
| 1433 | MSSQL | 🔴 Critico |
| 3306 | MySQL | 🔴 Critico |
| 3389 | RDP | 🔴 Critico |
| 5432 | PostgreSQL | 🔴 Critico |
| 5900 | VNC | 🔴 Critico |
| 8080 | HTTP-Alt | 🟡 Attenzione |

---

## 🛡️ Disclaimer

Questo strumento è fornito **solo per scopi legittimi**:
- Analisi della propria rete aziendale
- Audit di sicurezza autorizzati
- Scopi educativi

**Non usare** questo strumento per scansionare reti senza autorizzazione. È illegale e non etico.

---

## 📄 Licenza

MIT License - Vedi file [LICENSE](LICENSE)

---

## 👨‍💻 Autore

**ISIPC - Truant Bruno**

- 🌐 Website: [isipc.com](https://isipc.com)
- 💻 GitHub: [github.com/brunotr88](https://github.com/brunotr88)

Consulente IT con oltre 14 anni di esperienza al servizio delle PMI italiane.

---

## 🤝 Contributi

Contributi, issue e feature request sono benvenuti!

1. Fai un Fork del progetto
2. Crea il tuo branch (`git checkout -b feature/NuovaFeature`)
3. Commit delle modifiche (`git commit -m 'Aggiunta NuovaFeature'`)
4. Push sul branch (`git push origin feature/NuovaFeature`)
5. Apri una Pull Request

---

## ⭐ Supporta il progetto

Se CyberSentinel ti è utile, lascia una ⭐ su GitHub!

---

*Fatto con ❤️ in Italia per le PMI italiane*
