"""
Generatore Report PDF - CyberSentinel
Crea report professionali e comprensibili per non-tecnici

Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie

from .classifier import PortClassifier, RiskLevel


class ReportGenerator:
    """
    Genera report PDF professionali per PMI.
    Report ottimizzato per non-tecnici con spiegazioni chiare.
    """

    # Colori tema
    COLORS = {
        'primary': colors.HexColor('#1a365d'),      # Blu scuro
        'secondary': colors.HexColor('#38a169'),    # Verde
        'critical': colors.HexColor('#dc3545'),     # Rosso
        'warning': colors.HexColor('#ffc107'),      # Giallo
        'ok': colors.HexColor('#28a745'),           # Verde
        'light_gray': colors.HexColor('#f8f9fa'),
        'dark_gray': colors.HexColor('#343a40'),
        'text': colors.HexColor('#212529'),
    }

    def __init__(self):
        """Inizializza il generatore"""
        self.classifier = PortClassifier()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Configura stili personalizzati"""
        # Titolo principale
        self.styles.add(ParagraphStyle(
            name='MainTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=self.COLORS['primary'],
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        ))

        # Sottotitolo
        self.styles.add(ParagraphStyle(
            name='SubTitle',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.COLORS['dark_gray'],
            alignment=TA_CENTER,
            spaceAfter=30
        ))

        # Sezione
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.COLORS['primary'],
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))

        # Corpo testo
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['text'],
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            leading=14
        ))

        # Critico
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.COLORS['critical'],
            fontName='Helvetica-Bold'
        ))

        # Warning
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#856404'),
            fontName='Helvetica-Bold'
        ))

        # OK
        self.styles.add(ParagraphStyle(
            name='Ok',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.COLORS['ok'],
            fontName='Helvetica-Bold'
        ))

        # Footer
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=self.COLORS['dark_gray'],
            alignment=TA_CENTER
        ))

    def _create_header(self, target: str, scan_date: datetime) -> List:
        """Crea header del report"""
        elements = []

        # Titolo
        elements.append(Paragraph(
            "CYBERSENTINEL",
            self.styles['MainTitle']
        ))

        elements.append(Paragraph(
            "Report Sicurezza Rete Aziendale",
            self.styles['SubTitle']
        ))

        # Info scansione
        info_data = [
            ["Target scansionato:", target],
            ["Data scansione:", scan_date.strftime("%d/%m/%Y alle %H:%M")],
            ["Generato da:", "CyberSentinel v1.0.0"]
        ]

        info_table = Table(info_data, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['text']),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(info_table)
        elements.append(Spacer(1, 20))

        return elements

    def _create_executive_summary(self, classified: Dict) -> List:
        """Crea riepilogo esecutivo"""
        elements = []

        elements.append(Paragraph(
            "Riepilogo Esecutivo",
            self.styles['SectionHeader']
        ))

        summary = classified['summary']

        # Box riepilogo con colore basato su rischio
        risk_score = summary['risk_score']
        if summary['critical_count'] > 0:
            risk_color = self.COLORS['critical']
            risk_text = "RISCHIO ALTO"
            risk_desc = "Sono state trovate vulnerabilità critiche che richiedono intervento immediato."
        elif risk_score >= 40:
            risk_color = self.COLORS['warning']
            risk_text = "RISCHIO MEDIO"
            risk_desc = "Sono presenti alcune configurazioni che richiedono attenzione."
        else:
            risk_color = self.COLORS['ok']
            risk_text = "RISCHIO BASSO"
            risk_desc = "La rete appare ben configurata, con poche aree di miglioramento."

        # Tabella riepilogo visuale
        summary_data = [
            [
                Paragraph(f"<font size='20'><b>{risk_text}</b></font>",
                         ParagraphStyle('risk', alignment=TA_CENTER, textColor=risk_color)),
            ],
            [
                Paragraph(risk_desc,
                         ParagraphStyle('desc', alignment=TA_CENTER, fontSize=10))
            ]
        ]

        summary_table = Table(summary_data, colWidths=[15*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_gray']),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Conteggi
        counts_data = [
            ["Problemi Critici", "Attenzione", "OK", "Totale Porte"],
            [
                str(summary['critical_count']),
                str(summary['warning_count']),
                str(summary['ok_count']),
                str(summary['total_open_ports'])
            ]
        ]

        counts_table = Table(counts_data, colWidths=[3.75*cm]*4)
        counts_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 0), (0, 0), self.COLORS['critical']),
            ('BACKGROUND', (1, 0), (1, 0), self.COLORS['warning']),
            ('BACKGROUND', (2, 0), (2, 0), self.COLORS['ok']),
            ('BACKGROUND', (3, 0), (3, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 1), (-1, 1), 18),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 1), (0, 1), self.COLORS['critical']),
            ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#856404')),
            ('TEXTCOLOR', (2, 1), (2, 1), self.COLORS['ok']),
            ('TEXTCOLOR', (3, 1), (3, 1), self.COLORS['primary']),
            ('GRID', (0, 0), (-1, -1), 1, colors.white),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))

        elements.append(counts_table)
        elements.append(Spacer(1, 20))

        # Spiegazione per non-tecnici
        elements.append(Paragraph(
            "<b>Cosa significa questo report?</b>",
            self.styles['BodyText']
        ))

        elements.append(Paragraph(
            "Abbiamo scansionato la vostra rete per verificare quali 'porte' sono aperte e accessibili. "
            "Le porte sono come le porte di un edificio: alcune devono essere aperte per lavorare "
            "(come la porta d'ingresso), ma altre dovrebbero restare chiuse per sicurezza "
            "(come la porta del caveau). Questo report vi mostra quali porte sono aperte e se "
            "rappresentano un rischio per la vostra azienda.",
            self.styles['BodyText']
        ))

        return elements

    def _create_critical_section(self, critical_items: List) -> List:
        """Crea sezione problemi critici"""
        elements = []

        if not critical_items:
            return elements

        elements.append(PageBreak())

        elements.append(Paragraph(
            "Problemi Critici - Intervento Urgente",
            self.styles['SectionHeader']
        ))

        # Box rosso di avviso
        warning_text = Paragraph(
            "<font color='white'><b>ATTENZIONE:</b> I seguenti problemi rappresentano "
            "un rischio significativo per la sicurezza della vostra rete e dei vostri dati. "
            "Si consiglia di intervenire il prima possibile.</font>",
            ParagraphStyle('warning_box', fontSize=10, textColor=colors.white)
        )

        warning_table = Table([[warning_text]], colWidths=[15*cm])
        warning_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['critical']),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))

        elements.append(warning_table)
        elements.append(Spacer(1, 15))

        # Dettaglio ogni problema
        for item in critical_items:
            port_info = item['port_info']

            elements.append(Paragraph(
                f"<font color='#dc3545'>&#9679;</font> "
                f"<b>Porta {port_info.port} ({port_info.service})</b> "
                f"su {item['host']}",
                self.styles['Critical']
            ))

            elements.append(Paragraph(
                f"<b>Cos'è:</b> {port_info.description}",
                self.styles['BodyText']
            ))

            elements.append(Paragraph(
                f"<b>Perché è pericoloso:</b> {port_info.risk_explanation}",
                self.styles['BodyText']
            ))

            elements.append(Paragraph(
                f"<b>Cosa fare:</b> {port_info.recommendation}",
                self.styles['BodyText']
            ))

            elements.append(HRFlowable(
                width="100%", thickness=0.5,
                color=self.COLORS['light_gray'], spaceAfter=10
            ))

        return elements

    def _create_warning_section(self, warning_items: List) -> List:
        """Crea sezione attenzione"""
        elements = []

        if not warning_items:
            return elements

        elements.append(Paragraph(
            "Punti di Attenzione",
            self.styles['SectionHeader']
        ))

        elements.append(Paragraph(
            "Queste porte non sono necessariamente pericolose, ma richiedono "
            "verifica della configurazione per garantire la sicurezza.",
            self.styles['BodyText']
        ))

        elements.append(Spacer(1, 10))

        for item in warning_items:
            port_info = item['port_info']

            elements.append(Paragraph(
                f"<font color='#ffc107'>&#9679;</font> "
                f"<b>Porta {port_info.port} ({port_info.service})</b> "
                f"su {item['host']}",
                self.styles['Warning']
            ))

            elements.append(Paragraph(
                f"{port_info.description}. {port_info.recommendation}",
                self.styles['BodyText']
            ))

            elements.append(Spacer(1, 5))

        return elements

    def _create_ok_section(self, ok_items: List) -> List:
        """Crea sezione OK"""
        elements = []

        if not ok_items:
            return elements

        elements.append(Paragraph(
            "Configurazioni Corrette",
            self.styles['SectionHeader']
        ))

        elements.append(Paragraph(
            "Le seguenti porte sono aperte ma generalmente sicure se "
            "i servizi sono aggiornati.",
            self.styles['BodyText']
        ))

        elements.append(Spacer(1, 10))

        # Tabella compatta per le porte OK
        ok_data = [["Host", "Porta", "Servizio", "Note"]]

        for item in ok_items:
            port_info = item['port_info']
            ok_data.append([
                item['host'],
                str(port_info.port),
                port_info.service,
                "Mantenere aggiornato"
            ])

        if len(ok_data) > 1:
            ok_table = Table(ok_data, colWidths=[4*cm, 2*cm, 4*cm, 5*cm])
            ok_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['ok']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['light_gray']),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white, self.COLORS['light_gray']]),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(ok_table)

        return elements

    def _create_recommendations(self, classified: Dict) -> List:
        """Crea sezione raccomandazioni"""
        elements = []

        elements.append(Paragraph(
            "Prossimi Passi Consigliati",
            self.styles['SectionHeader']
        ))

        recommendations = []

        if classified['summary']['critical_count'] > 0:
            recommendations.extend([
                "1. <b>URGENTE:</b> Affrontare immediatamente i problemi critici elencati sopra",
                "2. Contattare il vostro tecnico IT o un consulente di sicurezza",
                "3. Verificare i backup dei dati siano aggiornati e funzionanti",
                "4. Considerare un audit di sicurezza completo",
            ])
        elif classified['summary']['warning_count'] > 0:
            recommendations.extend([
                "1. Verificare la configurazione dei servizi segnalati in giallo",
                "2. Aggiornare tutti i sistemi alle ultime versioni",
                "3. Rivedere le regole del firewall",
                "4. Pianificare scansioni periodiche (mensili)",
            ])
        else:
            recommendations.extend([
                "1. Continuare a mantenere i sistemi aggiornati",
                "2. Eseguire scansioni periodiche (trimestrali)",
                "3. Formare il personale sulla sicurezza informatica",
                "4. Verificare periodicamente i backup",
            ])

        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['BodyText']))

        return elements

    def _create_footer(self) -> List:
        """Crea footer del report"""
        elements = []

        elements.append(Spacer(1, 30))

        elements.append(HRFlowable(
            width="100%", thickness=1,
            color=self.COLORS['primary'], spaceAfter=10
        ))

        elements.append(Paragraph(
            "Report generato da <b>CyberSentinel</b> - La sentinella digitale per le PMI italiane",
            self.styles['Footer']
        ))

        elements.append(Paragraph(
            "Sviluppato da <b>ISIPC - Truant Bruno</b> | "
            "<link href='https://isipc.com'>isipc.com</link> | "
            "<link href='https://github.com/brunotr88'>github.com/brunotr88</link>",
            self.styles['Footer']
        ))

        elements.append(Spacer(1, 10))

        elements.append(Paragraph(
            "<i>Nota: Questo report fornisce una valutazione di base della sicurezza di rete. "
            "Non sostituisce un audit di sicurezza professionale completo. "
            "Per una valutazione approfondita, contattare un professionista della sicurezza informatica.</i>",
            ParagraphStyle('disclaimer', fontSize=7, textColor=self.COLORS['dark_gray'],
                          alignment=TA_CENTER)
        ))

        return elements

    def generate(
        self,
        scan_result,
        output_path: str,
        title: str = "Report Sicurezza Rete"
    ) -> str:
        """
        Genera il report PDF completo

        Args:
            scan_result: Risultato della scansione (ScanResult)
            output_path: Percorso file PDF output
            title: Titolo personalizzato (opzionale)

        Returns:
            Percorso del file generato
        """
        # Classifica risultati
        classified = self.classifier.classify_scan_results(scan_result.hosts)

        # Crea documento
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        # Costruisci contenuto
        elements = []

        # Header
        elements.extend(self._create_header(
            scan_result.target,
            scan_result.start_time
        ))

        # Riepilogo esecutivo
        elements.extend(self._create_executive_summary(classified))

        # Problemi critici
        elements.extend(self._create_critical_section(classified['critical']))

        # Attenzione
        elements.extend(self._create_warning_section(classified['warning']))

        # OK
        elements.extend(self._create_ok_section(classified['ok']))

        # Raccomandazioni
        elements.append(PageBreak())
        elements.extend(self._create_recommendations(classified))

        # Footer
        elements.extend(self._create_footer())

        # Genera PDF
        doc.build(elements)

        return output_path


def main():
    """Test del generatore report"""
    from .scanner import PortScanner, ScanResult, HostResult, PortResult
    from datetime import datetime

    print("=" * 60)
    print("CyberSentinel - Test Generatore Report")
    print("Sviluppato da ISIPC - Truant Bruno | https://isipc.com")
    print("=" * 60)

    # Crea dati di test
    test_result = ScanResult(
        target="192.168.1.0/24",
        start_time=datetime.now()
    )

    # Simula alcuni host
    test_result.hosts = [
        HostResult(
            ip="192.168.1.1",
            hostname="router.local",
            state="up",
            ports=[
                PortResult(port=80, state="open", service="HTTP"),
                PortResult(port=443, state="open", service="HTTPS"),
            ]
        ),
        HostResult(
            ip="192.168.1.100",
            hostname="server.local",
            state="up",
            ports=[
                PortResult(port=22, state="open", service="SSH"),
                PortResult(port=445, state="open", service="SMB"),
                PortResult(port=3389, state="open", service="RDP"),
            ]
        ),
    ]
    test_result.end_time = datetime.now()

    # Genera report
    generator = ReportGenerator()
    output = generator.generate(test_result, "test_report.pdf")

    print(f"\nReport generato: {output}")


if __name__ == "__main__":
    main()
