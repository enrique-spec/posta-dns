"""Prima fase della migrazione: fotografia dei record MX del dominio."""
import base64
import binascii
import ipaddress
import re
import sys
from pathlib import Path
from PySide6.QtGui import QPixmap
from datetime import datetime

import dns.exception
import dns.resolver
from PySide6.QtCore import Qt, QSettings, QIODevice, QSaveFile, QThread, Signal
from PySide6.QtWidgets import (
    QStackedWidget, QHBoxLayout, QComboBox, QApplication, QCheckBox, QFileDialog, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)


EN = {
    "Selettore DKIM (facoltativo)": "DKIM selector (optional)",
    "Esempio: ovhmo-selector-1": "Example: ovhmo-selector-1",
    "Controllo MX, SPF e DKIM": "MX, SPF and DKIM lookup",
    "Inserisci un selettore valido, per esempio ovhmo-selector-1.": "Enter a valid selector, for example ovhmo-selector-1.",
    "Chiave DKIM pubblicata.": "DKIM key published.",
    "Chiave DKIM revocata.": "DKIM key revoked.",
    "Nessuna chiave DKIM trovata per questo selettore.": "No DKIM key found for this selector.",
    "Record DKIM da verificare.": "Review the DKIM record."
,
    'Record SPF pubblicato.': 'SPF record published.',
    'Più record SPF pubblicati: configurazione da correggere.': 'Multiple SPF records published: review the configuration.',
    'Nessun record SPF pubblicato.': 'No SPF record published.',
    'Lingua': 'Language',
    'Tema': 'Theme',
    'Chiaro': 'Light',
    'Scuro': 'Dark',
    'Dominio': 'Domain',
    'Posta DNS · Controllo del dominio': 'Posta DNS · Domain check',
    'Controlla la posta del dominio': 'Check domain mail servers',
    'Consulta i server MX e la regola SPF pubblicata dal dominio.': 'Look up MX servers and the SPF policy published by the domain.',
    'Dominio · esempio.it': 'Domain · example.com',
    'Controlla posta': 'Check mail',
    'Mostra dettagli tecnici': 'Show technical details',
    'Salva risultato…': 'Save result…',
    'Testo (*.txt)': 'Text (*.txt)',
    'Inserisci il dominio, per esempio esempio.it.': 'Enter a domain, for example example.com.',
    'Inserisci un dominio al posto dell’indirizzo IP.': 'Enter a domain instead of an IP address.',
    'Dominio inesistente secondo il DNS consultato.': 'The DNS resolver reports that this domain does not exist.',
    'Nessun record MX esplicito pubblicato.': 'No explicit MX record published.',
    'Il recapito può usare gli indirizzi A o AAAA del dominio.': "Delivery may use the domain's A or AAAA addresses.",
    'Controllo non completato. Verifica la rete e riprova.': 'Lookup incomplete. Check your connection and try again.',
    'Il dominio dichiara di non accettare posta.': 'The domain declares it does not accept mail.',
    'Configurazione MX incoerente. Controlla i record pubblicati.': 'Inconsistent MX configuration. Check the published records.',
    'Server di ricezione pubblicati: {}.': 'Published receiving servers: {}.',
    'Priorità    Server MX': 'Priority    MX server',
    'TTL osservato: {} secondi': 'Observed TTL: {} seconds',
    'Consultazione DNS in corso…': 'Looking up DNS…',
    'Controllo MX e SPF': 'MX and SPF lookup',
    'Salvataggio non riuscito. Scegli un’altra destinazione.': 'Could not save. Choose another location.',
    'Attendi la fine della richiesta DNS prima di chiudere.': 'Wait for the DNS lookup to finish before closing.',
}


def domain_name(value):
    try:
        name = value.strip().removesuffix(".").encode("idna").decode().lower()
    except UnicodeError:
        name = ""
    labels = name.split(".")
    valid_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(name) > 253 or len(labels) < 2 or not all(
        re.fullmatch(valid_label, label) for label in labels
    ):
        raise ValueError("Inserisci il dominio, per esempio esempio.it.")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("Inserisci un dominio al posto dell’indirizzo IP.")


def lookup(name):
    try:
        answer = dns.resolver.resolve(name + ".", "MX", lifetime=6)
    except dns.resolver.NXDOMAIN:
        return ("Dominio inesistente secondo il DNS consultato."), "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return ("Nessun record MX esplicito pubblicato."), ("Il recapito può usare gli indirizzi A o AAAA del dominio.")
    except (dns.exception.DNSException, OSError) as error:
        return ("Controllo non completato. Verifica la rete e riprova."), type(error).__name__
    servers = sorted((int(r.preference), str(r.exchange)) for r in answer)
    if servers == [(0, ".")]:
        status = ("Il dominio dichiara di non accettare posta.")
    elif any(host == "." for _, host in servers):
        status = ("Configurazione MX incoerente. Controlla i record pubblicati.")
    else:
        status = ("Server di ricezione pubblicati: {}.", len(servers))
    rows = [("Priorità    Server MX")]
    rows.extend(f"{priority:>5}    {host}" for priority, host in servers)
    rows.extend(["", ("TTL osservato: {} secondi", answer.rrset.ttl)])
    return status, rows


def lookup_spf(name):
    try:
        answer = dns.resolver.resolve(name + ".", "TXT", lifetime=6)
    except dns.resolver.NoAnswer:
        return "Nessun record SPF pubblicato.", []
    except dns.resolver.NXDOMAIN:
        return "Dominio inesistente secondo il DNS consultato.", ["NXDOMAIN"]
    except (dns.exception.DNSException, OSError) as error:
        return "Controllo non completato. Verifica la rete e riprova.", [type(error).__name__]

    policies = []
    for record in answer:
        value = b"".join(record.strings)
        if re.match(rb"^v=spf1(?: |$)", value, re.IGNORECASE):
            policies.append("".join(chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02x}" for byte in value))
    if not policies:
        return "Nessun record SPF pubblicato.", []
    status = "Record SPF pubblicato." if len(policies) == 1 else "Più record SPF pubblicati: configurazione da correggere."
    return status, sorted(policies)


def selector_name(value, domain):
    selector = value.strip().lower()
    if selector:
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(f"{selector}._domainkey.{domain}") > 253 or not all(
            re.fullmatch(label, part) for part in selector.split(".")
        ):
            raise ValueError("Inserisci un selettore valido, per esempio ovhmo-selector-1.")
    return selector


def lookup_dkim(domain, selector):
    owner = f"{selector}._domainkey.{domain}."
    details = [owner]
    try:
        answer = dns.resolver.resolve(owner, "TXT", lifetime=6)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "Nessuna chiave DKIM trovata per questo selettore.", details
    except (dns.exception.DNSException, OSError) as error:
        return "Controllo non completato. Verifica la rete e riprova.", details + [type(error).__name__]
    if str(answer.canonical_name).lower() != owner:
        details.append(str(answer.canonical_name))
    candidates = []
    for record in answer:
        value = b"".join(record.strings).decode("ascii", errors="backslashreplace")
        parts = [tag.strip() for tag in value.split(";") if tag.strip()]
        if not any(re.match(r"^(?:p\s*=|v\s*=\s*DKIM1\b)", tag) for tag in parts):
            continue
        tags = {}
        valid = True
        for part in parts:
            key, separator, content = part.partition("=")
            key = key.strip()
            if not separator or key in tags:
                valid = False
            tags[key] = content.strip()
        candidates.append((tags, valid))
        details.append(value)
    if not candidates:
        return "Nessuna chiave DKIM trovata per questo selettore.", details
    tags, valid = candidates[0]
    if len(candidates) != 1 or not valid or tags.get("v", "DKIM1") != "DKIM1" or "p" not in tags:
        return "Record DKIM da verificare.", details
    key = "".join(tags["p"].split())
    if not key:
        return "Chiave DKIM revocata.", details
    try:
        base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error):
        return "Record DKIM da verificare.", details
    return "Chiave DKIM pubblicata.", details


class Query(QThread):
    result = Signal(object, object, object)

    def __init__(self, domain, selector, parent):
        super().__init__(parent)
        self.domain = domain
        self.selector = selector

    def run(self):
        dkim = lookup_dkim(self.domain, self.selector) if self.selector else None
        self.result.emit(lookup(self.domain), lookup_spf(self.domain), dkim)


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Informaticadeso", "PostaDNS")
        self.last_result = None
        self.message = ""
        self.resize(750, 620)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(12)
        preferences = QHBoxLayout()
        preferences.addStretch()
        self.language = QComboBox()
        self.language.addItems(["Italiano", "English"])
        self.theme = QComboBox()
        self.theme.addItems(["Chiaro", "Scuro"])
        self.language_label = QLabel()
        self.theme_label = QLabel()
        for widget in (self.language_label, self.language, self.theme_label, self.theme):
            preferences.addWidget(widget)
        layout.addLayout(preferences)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages)
        self.page_text = []
        cover = self.add_page()
        illustration = QLabel()
        image = QPixmap(str(Path(__file__).with_name("copertina.jpg")))
        if not image.isNull():
            illustration.setPixmap(image.scaledToWidth(680, Qt.TransformationMode.SmoothTransformation))
            illustration.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cover.addWidget(illustration)
        self.heading(cover, "Posta DNS", "Posta DNS")
        self.paragraph(cover, "Scopri dove arriva la posta del tuo dominio.", "See where mail for your domain is delivered.")
        self.nav(cover, "Entra →", "Enter →", 1)
        cover.addStretch()

        guide = self.add_page()
        self.heading(guide, "Come funziona Posta DNS", "How Posta DNS works")
        self.paragraph(guide,
            "Il percorso di migrazione comprende tre fasi. Oggi puoi controllare il dominio e salvare un rapporto senza inserire credenziali.",
            "The migration workflow has three stages. Today you can check a domain and save a report without entering credentials.")
        self.heading(guide, "1 · Controllo del dominio", "1 · Domain check", 17)
        self.paragraph(guide,
            "Controlla MX e SPF. Se conosci il selettore DKIM, inseriscilo per cercare la chiave pubblica. Puoi salvare i risultati in un rapporto TXT.",
            "Check MX and SPF. Enter a DKIM selector if you know it to look up the public key. Save the results in a TXT report.")
        self.heading(guide, "2 · Copia della posta", "2 · Mailbox copy", 17)
        self.paragraph(guide,
            "In progetto: scegliere le cartelle e copiare i messaggi tra due caselle. Questa versione non accede ai messaggi e non modifica i DNS.",
            "Planned: select folders and copy messages between mailboxes. This version does not access messages or change DNS settings.")
        self.heading(guide, "3 · Verifica della migrazione", "3 · Migration review", 17)
        self.paragraph(guide,
            "In progetto: confrontare origine e destinazione e documentare una prova di consegna. La presenza dei record MX da sola non conferma la consegna.",
            "Planned: compare source and destination and document a delivery test. MX records alone do not confirm delivery.")
        self.nav(guide, "Apri il controllo DNS →", "Open DNS check →", 2)
        self.nav(guide, "← Copertina", "← Welcome", 0)
        guide.addStretch()

        layout = self.add_page()
        self.nav(layout, "← Guida", "← Guide", 1)
        self.title = QLabel()
        self.title.setStyleSheet("font-size:25px;font-weight:bold")
        self.subtitle = QLabel()
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        self.domain = QLineEdit()
        self.domain.setClearButtonEnabled(True)
        self.selector = QLineEdit()
        self.selector.setClearButtonEnabled(True)
        self.selector_label = QLabel()
        self.selector_label.setBuddy(self.selector)
        self.check = QPushButton("Controlla posta")
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.toggle = QCheckBox("Mostra dettagli tecnici")
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.save = QPushButton("Salva risultato…")
        for widget in (self.domain, self.selector_label, self.selector, self.check, self.status, self.toggle, self.details, self.save):
            layout.addWidget(widget)
        layout.addStretch()
        self.toggle.toggled.connect(self.details.setVisible)
        self.domain.textChanged.connect(self.reset)
        self.selector.textChanged.connect(self.reset)
        self.selector.returnPressed.connect(self.start)
        self.domain.returnPressed.connect(self.start)
        self.check.clicked.connect(self.start)
        self.save.clicked.connect(self.export)
        self.worker = None
        self.language.setCurrentIndex(int(self.settings.value("language", 0)) == 1)
        self.theme.setCurrentIndex(int(self.settings.value("theme", 0)) == 1)
        self.language.currentIndexChanged.connect(self.refresh)
        self.theme.currentIndexChanged.connect(self.apply_theme)
        self.reset()
        self.refresh()
        self.apply_theme()

    def add_page(self):
        page = QWidget()
        self.pages.addWidget(page)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        return layout

    def paragraph(self, layout, italian, english):
        label = QLabel()
        label.setWordWrap(True)
        self.page_text.append((label, italian, english))
        layout.addWidget(label)
        return label

    def heading(self, layout, italian, english, size=28):
        label = self.paragraph(layout, italian, english)
        label.setStyleSheet(f"font-size:{size}px;font-weight:bold")

    def nav(self, layout, italian, english, destination):
        button = QPushButton()
        self.page_text.append((button, italian, english))
        button.clicked.connect(lambda: self.pages.setCurrentIndex(destination))
        layout.addWidget(button)

    def reset(self):
        self.last_result = None
        self.message = ""
        self.report = ""
        self.status.clear()
        self.details.clear()
        self.details.hide()
        self.toggle.setChecked(False)
        self.toggle.hide()
        self.save.hide()

    def start(self):
        if self.worker and self.worker.isRunning():
            return
        self.reset()
        try:
            name = domain_name(self.domain.text())
            selector = selector_name(self.selector.text(), name)
        except ValueError as error:
            self.show_message(str(error))
            return
        self.domain.setEnabled(False)
        self.selector.setEnabled(False)
        self.check.setEnabled(False)
        self.show_message("Consultazione DNS in corso…")
        self.worker = Query(name, selector, self)
        self.worker.result.connect(self.display)
        self.worker.finished.connect(self.ready)
        self.worker.start()

    def ready(self):
        self.domain.setEnabled(True)
        self.selector.setEnabled(True)
        self.check.setEnabled(True)
        self.worker.deleteLater()
        self.worker = None

    def display(self, status, details, dkim):
        self.last_result = (domain_name(self.domain.text()), datetime.now().astimezone().isoformat(timespec="seconds"), status, details, dkim)
        self.message = ""
        self.render_result()
        self.toggle.show()
        self.save.show()
        self.toggle.setChecked(True)

    def local(self, key):
        if isinstance(key, tuple):
            pattern, value = key
            return self.local(pattern).format(value)
        return EN.get(key, key) if self.language.currentIndex() else key

    def show_message(self, message):
        self.message = message
        self.status.setText(self.local(message))

    def render_result(self):
        name, timestamp, status, lines, dkim = self.last_result
        mx_status, mx_lines = status
        spf_status, policies = lines
        mx_details = "\n".join(map(self.local, mx_lines)) if isinstance(mx_lines, list) else self.local(mx_lines)
        status = f"MX · {self.local(mx_status)}\nSPF · {self.local(spf_status)}"
        details = mx_details + "\n\nSPF\n" + ("\n".join(policies) or self.local(spf_status))
        title = "Controllo MX e SPF"
        if dkim:
            title = "Controllo MX, SPF e DKIM"
            dkim_status, dkim_lines = dkim
            status += "\nDKIM · " + self.local(dkim_status)
            details += "\n\nDKIM\n" + "\n".join(dkim_lines)
        self.status.setText(f"{name} — {status}")
        self.details.setPlainText(details)
        self.report = f"{self.local(title)} · {timestamp}\n{name}\n{status}\n\n{details}\n"

    def refresh(self):
        self.settings.setValue("language", self.language.currentIndex())
        self.setWindowTitle("Posta DNS")
        for widget, italian, english in self.page_text:
            widget.setText(english if self.language.currentIndex() else italian)
        self.language_label.setText(self.local("Lingua"))
        self.theme_label.setText(self.local("Tema"))
        self.theme.setItemText(0, self.local("Chiaro"))
        self.theme.setItemText(1, self.local("Scuro"))
        self.title.setText(self.local("Controlla la posta del dominio"))
        self.subtitle.setText(self.local("Consulta i server MX e la regola SPF pubblicata dal dominio."))
        self.domain.setPlaceholderText(self.local("Dominio · esempio.it"))
        self.selector_label.setText(self.local("Selettore DKIM (facoltativo)"))
        self.selector.setPlaceholderText(self.local("Esempio: ovhmo-selector-1"))
        self.domain.setAccessibleName(self.local("Dominio"))
        self.check.setText(self.local("Controlla posta"))
        self.toggle.setText(self.local("Mostra dettagli tecnici"))
        self.save.setText(self.local("Salva risultato…"))
        if self.last_result:
            self.render_result()
        if self.message:
            self.status.setText(self.local(self.message))

    def apply_theme(self):
        dark = self.theme.currentIndex() == 1
        self.settings.setValue("theme", int(dark))
        bg, panel, ink, border = ("#172431", "#253746", "#edf5fa", "#8396a8") if dark else ("#f4f7fa", "#ffffff", "#17334b", "#a7bac7")
        self.setStyleSheet(f"""
            QWidget {{ background:{bg}; color:{ink}; font-size:15px; }}
            QLineEdit,QPlainTextEdit,QComboBox {{ background:{panel}; border:1px solid {border}; border-radius:7px; padding:8px; }}
            QPushButton {{ background:#115c69; color:white; border-radius:7px; padding:10px; font-weight:bold; }}
            QPushButton:disabled {{ background:#627e82; }}
        """)

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, self.local("Salva risultato…"), ("controllo-mx-spf-dkim.txt" if self.last_result[-1] else "controllo-mx-spf.txt"), self.local("Testo (*.txt)"))
        if path:
            data = self.report.encode("utf-8")
            out = QSaveFile(path)
            if not out.open(QIODevice.OpenModeFlag.WriteOnly) or out.write(data) != len(data) or not out.commit():
                self.show_message("Salvataggio non riuscito. Scegli un’altra destinazione.")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.show_message("Attendi la fine della richiesta DNS prima di chiudere.")
            event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = Window()
    window.show()
    sys.exit(app.exec())
