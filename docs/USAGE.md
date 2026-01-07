# Guida all'uso di CyberSentinel

## Indice
1. [Introduzione](#introduzione)
2. [Installazione](#installazione)
3. [Primo utilizzo](#primo-utilizzo)
4. [Esempi pratici](#esempi-pratici)
5. [Interpretare il report](#interpretare-il-report)
6. [Scansioni programmate](#scansioni-programmate)
7. [Risoluzione problemi](#risoluzione-problemi)

---

## Introduzione

CyberSentinel è uno strumento pensato per aiutare le piccole e medie imprese italiane a verificare la sicurezza della propria rete. Non richiede competenze tecniche avanzate: basta lanciare il comando e leggere il report PDF generato.

### Cosa fa CyberSentinel?

1. **Scansiona** la tua rete alla ricerca di "porte" aperte
2. **Classifica** ogni porta trovata per livello di rischio
3. **Genera** un report PDF in italiano con spiegazioni semplici
4. **Consiglia** cosa fare per ogni problema trovato

### Cosa sono le "porte"?

Pensa al tuo computer come a un edificio con tante porte. Ogni porta permette un tipo di comunicazione diverso:
- Porta 80: sito web
- Porta 443: sito web sicuro
- Porta 3389: Desktop Remoto Windows

Alcune porte dovrebbero essere aperte (per lavorare), altre dovrebbero essere chiuse (per sicurezza).

---

## Installazione

### Requisiti minimi

- Computer con Windows, macOS o Linux
- Python 3.8 o superiore
- Connessione alla rete da analizzare

### Passaggi

1. **Scarica il progetto**
   ```bash
   git clone https://github.com/brunotr88/cybersentinel.git
   cd cybersentinel
   ```

2. **Installa le dipendenze**
   ```bash
   pip install -r requirements.txt
   ```

3. **(Opzionale) Installa Nmap** per scansioni più accurate
   - Windows: scarica da nmap.org
   - Linux: `sudo apt install nmap`
   - macOS: `brew install nmap`

---

## Primo utilizzo

### Scansione automatica della rete locale

Il modo più semplice per iniziare:

```bash
python run.py --auto-detect --output mia_rete.pdf
```

Questo comando:
1. Rileva automaticamente la tua rete (es: 192.168.1.0/24)
2. Scansiona tutti i dispositivi
3. Genera un report PDF chiamato `mia_rete.pdf`

### Cosa aspettarsi

```
    ╔═══════════════════════════════════════════════════════════╗
    ║   CYBERSENTINEL                                           ║
    ║   La sentinella digitale per le PMI italiane     v1.0.0  ║
    ╚═══════════════════════════════════════════════════════════╝

  [*] Rete locale rilevata: 192.168.1.0/24
  [+] Nmap rilevato: scansione avanzata attiva

  [*] Avvio scansione: 192.168.1.0/24
  [*] Porte da verificare: 20

  [*] Scansione 192.168.1.1 (1/254)
  [*] Scansione 192.168.1.100 (2/254)
  ...

  ============================================================
  RISULTATI SCANSIONE
  ============================================================

    Host scansionati con porte aperte: 5
    Totale porte aperte trovate: 12

    [!] PROBLEMI CRITICI: 2
    [!] ATTENZIONE: 4
    [+] OK: 6

  [*] Generazione report PDF: mia_rete.pdf
  [+] Report generato: mia_rete.pdf
```

---

## Esempi pratici

### Esempio 1: Scansione rete ufficio
```bash
python run.py --target 192.168.1.0/24 --output ufficio_gennaio.pdf
```

### Esempio 2: Scansione singolo server
```bash
python run.py --target 192.168.1.100 --output server_principale.pdf
```

### Esempio 3: Scansione veloce (solo porte critiche)
```bash
python run.py --target 10.0.0.0/24 --quick --output quick_scan.pdf
```

### Esempio 4: Scansione con export JSON
```bash
python run.py --target 192.168.1.0/24 --output report.pdf --json dati.json
```

### Esempio 5: Scansione rete diversa da 192.168.x
```bash
# Rete classe A
python run.py --target 10.10.10.0/24 --output sede_remota.pdf

# Rete classe B
python run.py --target 172.16.5.0/24 --output filiale.pdf
```

---

## Interpretare il report

### Sezione "Riepilogo Esecutivo"

Nella prima pagina trovi:
- **Livello di rischio** (ALTO/MEDIO/BASSO)
- **Conteggio problemi** per categoria
- Una breve spiegazione

### Colori semaforo

- 🔴 **Rosso (CRITICO)**: Problema grave, agire subito
- 🟡 **Giallo (ATTENZIONE)**: Da verificare
- 🟢 **Verde (OK)**: Situazione normale

### Sezione "Problemi Critici"

Per ogni problema critico trovi:
1. **Cos'è**: Spiegazione del servizio
2. **Perché è pericoloso**: Rischi concreti
3. **Cosa fare**: Azione da intraprendere

### Esempio problema critico

> **Porta 3389 (RDP) su 192.168.1.100**
>
> *Cos'è:* Desktop Remoto Windows
>
> *Perché è pericoloso:* Bersaglio principale di attacchi ransomware.
> Vulnerabilità BlueKeep ancora sfruttata. Attacchi brute-force continui.
>
> *Cosa fare:* URGENTE: Non esporre RDP su Internet.
> Usare VPN + RDP o soluzioni come RD Gateway con autenticazione forte.

---

## Scansioni programmate

### Windows (Task Scheduler)

1. Apri "Utilità di pianificazione"
2. Crea attività di base
3. Imposta trigger (es: ogni lunedì alle 6:00)
4. Azione: Avvia programma
   - Programma: `python`
   - Argomenti: `C:\path\to\run.py --auto-detect --output C:\reports\scan_%date%.pdf`

### Linux/macOS (cron)

```bash
# Modifica crontab
crontab -e

# Aggiungi (scansione ogni lunedì alle 6:00)
0 6 * * 1 cd /path/to/cybersentinel && python run.py --auto-detect --output /var/reports/scan_$(date +\%Y\%m\%d).pdf
```

---

## Risoluzione problemi

### "Nmap non trovato"

CyberSentinel funziona anche senza Nmap, ma le scansioni saranno meno accurate.

Per installare Nmap:
- Windows: [nmap.org/download](https://nmap.org/download.html)
- Linux: `sudo apt install nmap`
- macOS: `brew install nmap`

### "Permesso negato" o scansione lenta

Alcune scansioni avanzate richiedono privilegi amministratore:
- Windows: Esegui come Amministratore
- Linux/macOS: `sudo python run.py ...`

### "Target non valido"

Verifica il formato:
- IP singolo: `192.168.1.100`
- Range CIDR: `192.168.1.0/24`
- Hostname: `server.local` (deve essere risolvibile)

### Scansione troppo lenta

Prova la modalità veloce:
```bash
python run.py --target 192.168.1.0/24 --quick
```

Oppure riduci il timeout:
```bash
python run.py --target 192.168.1.0/24 --timeout 1.0
```

---

## Supporto

Per assistenza:
- 🌐 Website: [isipc.com](https://isipc.com)
- 💻 GitHub Issues: [github.com/brunotr88/cybersentinel/issues](https://github.com/brunotr88/cybersentinel/issues)

---

*Sviluppato da ISIPC - Truant Bruno | https://isipc.com*
