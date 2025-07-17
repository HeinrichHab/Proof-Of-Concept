# Phishing_Detector.py
import sys
import os
import re
import email
import logging
from email.policy import default
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
# Punktevergabe
PUNKTE_LEERER_RETURN_PATH = 20
PUNKTE_ROUTE_INKONSISTENZ = 20
PUNKTE_KEIN_EMPFAENGER = 20
PUNKTE_ABSENDER_IST_EMPFAENGER = 20
PUNKTE_PRO_EINZELWORT_BETREFF = 3
PUNKTE_PRO_WORTPAAR_TEXT = 7
PUNKTE_EMPFAENGER_ALIAS_IN_BETREFF = 5
PUNKTE_PRO_EINZELWORT_TEXT = 3
PUNKTE_PRO_GENERISCHE_ANREDE = 4
PUNKTE_EMPFAENGER_ALIAS_IN_TEXT = 5
#Schwellenwert
SCHWELLENWERT_GEFAHR = 20
SCHWELLENWERT_WARNUNG = 10

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    USE_COLOR = True
except ImportError:
    USE_COLOR = False

if USE_COLOR:
    C_UEBERSCHRIFT = Fore.YELLOW + Style.BRIGHT
    C_TITEL = Fore.GREEN + Style.BRIGHT
    C_POSITIV = Fore.GREEN + Style.BRIGHT
    C_WARNUNG = Fore.YELLOW
    C_GEFAHR = Fore.RED + Style.BRIGHT
    C_NEUTRAL = Fore.WHITE
    C_FEHLER = Fore.RED + Style.BRIGHT
else:
    C_UEBERSCHRIFT, C_TITEL, C_POSITIV, C_WARNUNG, C_GEFAHR, C_NEUTRAL, C_FEHLER = ("",) * 7
#Unpersönliche Anrede
ANREDE_MUSTER = re.compile(
    r'\b(sehr geehrte|sehr geehrter|liebe|lieber|hallo)(\s+\w+){0,2}\s+'
    r'(kunde|kundin|nutzer|nutzerin|benutzer|kontoinhaber|damen und herren)\b', re.IGNORECASE)
#Verdächtige Wörter
VERDAECHTIGE_EINZELWOERTER = [
    "konto", "dringend", "sofort", "rechnung", "verifizieren", "bestätigen", "anmelden",
    "kreditkarte", "bankdaten", "kostenlos", "preis", "gewinnen", "überprüfen", "deaktiviert"
]
VERDAECHTIGE_EINZELWOERTER_RE = re.compile(r'\b(?:' + '|'.join(map(re.escape, VERDAECHTIGE_EINZELWOERTER)) + r')\b', re.IGNORECASE)

VERDAECHTIGE_WORTPAARE = [
    ("konto", "gesperrt"), ("konto", "überprüfung"), ("passwort", "zurücksetzen"),
    ("sicherheits", "warnung"), ("klicken", "hier"), ("klicken", "link"), 
    ("dringende", "handlung"), ("verdächtige", "aktivität"), ("ungewöhnliche", "aktivitäten")
]

# Gibt Text farbig aus
def print_farbig(text, farbe=C_NEUTRAL, bold=False):
    if USE_COLOR and bold:
        print(Style.BRIGHT + farbe + text)
    elif USE_COLOR:
        print(farbe + text)
    else:
        print(text)

# Extrahiert die Hauptdomain
def get_hauptdomain(domain_oder_url):
    if not domain_oder_url:
        return None
    return tldextract.extract(domain_oder_url).domain

# Extrahiert den E-Mail Inhalt
def _get_email_inhalt(nachricht):
    betreff = nachricht.get("Subject", "")
    text_inhalt = ""
    bild_link_domains = {}

    html_part = nachricht.get_body(preferencelist=('html',))
    if html_part:
        try:
            soup = BeautifulSoup(html_part.get_content(), 'html.parser')
            text_inhalt = soup.get_text(separator=' ', strip=True)
            for a_tag in soup.find_all('a', href=True):
                if a_tag.find('img'):
                    domain = urlparse(a_tag.get('href')).netloc.replace("www.", "")
                    if domain:
                        bild_link_domains[domain] = bild_link_domains.get(domain, 0) + 1
        except Exception as e:
            logging.warning(f"Fehler beim Parsen des HTML-Teils: {e}")

    if not text_inhalt:
        plain_part = nachricht.get_body(preferencelist=('plain',))
        if plain_part:
            text_inhalt = plain_part.get_content()

    return betreff, text_inhalt, bild_link_domains

# Fügt eine Warnung hinzu
def _add_warnung(warnliste, punkte, nachricht):
    warnliste.append((nachricht, f"+{punkte} Punkte"))
    return punkte

# Analysiert die E-Mail
def analysiere_email(nachricht):
    punktzahl, header_warnungen, body_warnungen = 0, [], []

    return_path_header = nachricht.get('Return-Path', '').strip()
    return_path_address_match = re.search(r'<([^>]+)>', return_path_header)
    return_path_address = return_path_address_match.group(1) if return_path_address_match else return_path_header

    if return_path_header == '<>':
        punktzahl += _add_warnung(header_warnungen, PUNKTE_LEERER_RETURN_PATH, "Leerer Return-Path (<>) (verhindert Unzustellbarkeits-Nachrichten)")
    
    received_from_domains = {
        match.group(1) for header in nachricht.get_all('Received', [])
        if (match := re.search(r'from\s+([\w.-]+)', header, re.IGNORECASE))
    }
    
    if return_path_address and return_path_address != "<>":
        main_return_domain = get_hauptdomain(return_path_address)
        main_received_domains = {get_hauptdomain(d) for d in received_from_domains}
        if main_return_domain and main_return_domain not in main_received_domains:
            punktzahl += _add_warnung(header_warnungen, PUNKTE_ROUTE_INKONSISTENZ, "Technnischer Absender (Return-Path) passt nicht zur Versandroute (Received)")

    from_header = nachricht.get("From")
    _, recipient_address = email.utils.parseaddr(nachricht.get("To", ""))
    recipient_username = recipient_address.split('@')[0] if '@' in recipient_address else None

    if not recipient_address:
        punktzahl += _add_warnung(header_warnungen, PUNKTE_KEIN_EMPFAENGER, "Kein Empfänger im 'An:'-Feld")

    sender_addrs = email.utils.getaddresses([from_header]) if from_header else []
    sender_address = sender_addrs[0][1] if sender_addrs else None
    if sender_address and recipient_address and sender_address.lower() == recipient_address.lower():
        punktzahl += _add_warnung(header_warnungen, PUNKTE_ABSENDER_IST_EMPFAENGER, "Sichtbarer Absender ist identisch mit Empfänger")

    betreff, text_inhalt, bild_link_domains = _get_email_inhalt(nachricht)

    gefundene_woerter_betreff = {match.lower() for match in VERDAECHTIGE_EINZELWOERTER_RE.findall(betreff)}
    if gefundene_woerter_betreff:
        punkte = len(gefundene_woerter_betreff) * PUNKTE_PRO_EINZELWORT_BETREFF
        punktzahl += _add_warnung(header_warnungen, punkte, f"Verdächtige Einzelwörter im Betreff: {', '.join(gefundene_woerter_betreff)}")

    if recipient_username and recipient_username in betreff:
        punktzahl += _add_warnung(header_warnungen, PUNKTE_EMPFAENGER_ALIAS_IN_BETREFF, f"Empfänger-Alias '{recipient_username}' im Betreff gefunden.")

    gefundene_woerter_body = {match.lower() for match in VERDAECHTIGE_EINZELWOERTER_RE.findall(text_inhalt)}
    if gefundene_woerter_body:
        punkte = len(gefundene_woerter_body) * PUNKTE_PRO_EINZELWORT_TEXT
        punktzahl += _add_warnung(body_warnungen, punkte, f"Verdächtige Einzelwörter im Text: {', '.join(gefundene_woerter_body)}")

    gefundene_paare = [f'"{w1} + {w2}"' for w1, w2 in VERDAECHTIGE_WORTPAARE if w1 in text_inhalt.lower() and w2 in text_inhalt.lower()]
    if gefundene_paare:
        punkte = len(gefundene_paare) * PUNKTE_PRO_WORTPAAR_TEXT
        punktzahl += _add_warnung(body_warnungen, punkte, f"Verdächtige Wortpaare im Text: {', '.join(gefundene_paare)}")

    gefundene_anreden = ANREDE_MUSTER.findall(text_inhalt)
    if gefundene_anreden:
        punkte = len(gefundene_anreden) * PUNKTE_PRO_GENERISCHE_ANREDE
        bereinigte_anreden = [' '.join(p.strip() for p in m if p.strip()) for m in gefundene_anreden]
        punktzahl += _add_warnung(body_warnungen, punkte, f"Generische Anrede(n): {', '.join(bereinigte_anreden)}")

    if recipient_username and recipient_username in text_inhalt:
        punktzahl += _add_warnung(body_warnungen, PUNKTE_EMPFAENGER_ALIAS_IN_TEXT, f"Empfänger-Alias '{recipient_username}' im Text gefunden.")

    return {
        "punktzahl": punktzahl, "from_header": from_header, "recipient_address": recipient_address,
        "return_path_address": return_path_header, "received_from": list(received_from_domains),
        "header_warnungen": header_warnungen, "body_warnungen": body_warnungen,
        "bild_link_domains": bild_link_domains
    }

# Gibt die Ergebnisse aus
def print_ergebnisse(analyse_daten, dateipfad):
    dateiname = os.path.basename(dateipfad)
    print_farbig(f"--- Analyse-Ergebnis für: {dateiname} ---", C_TITEL, bold=True)
#Ausgabe Headeranalyse
    print_farbig("\nHeaderanalyse:", C_UEBERSCHRIFT)
    if analyse_daten["from_header"]: print(f"    - Sichtbarer Absender (From): {analyse_daten['from_header']}")
    if analyse_daten["recipient_address"]: print(f"    - Empfänger (To): {C_POSITIV}{analyse_daten['recipient_address']}")
    if analyse_daten["return_path_address"]: print(f"    - Technischer Absender (Return-Path): {analyse_daten['return_path_address']}")
    if analyse_daten["received_from"]: print(f"    - Versandroute (Received from): {', '.join(analyse_daten['received_from'])}")
    for item, wert in analyse_daten["header_warnungen"]:
        print_farbig(f"    - {item} ({wert})", C_GEFAHR)
#Ausgabe Bodyanalyse
    print_farbig("\nBodyanalyse:", C_UEBERSCHRIFT)
    for item, wert in analyse_daten["body_warnungen"]:
        print_farbig(f"    - {item} ({wert})", C_GEFAHR)

    if analyse_daten["bild_link_domains"]:
        print_farbig("\nEs wurden eingebettete Links mit folgenden Zieldomains gefunden:", C_UEBERSCHRIFT)
        for domain, anzahl in analyse_daten["bild_link_domains"].items():
            print(f"    - \"{domain}\" [{anzahl}x]")

    print_farbig(f"\nGesamtpunktzahl: {analyse_daten['punktzahl']}", C_UEBERSCHRIFT, bold=True)
    if analyse_daten['punktzahl'] >= SCHWELLENWERT_GEFAHR:
        klassifizierung, farbe = "Vorsicht Phishing", C_GEFAHR
    elif analyse_daten['punktzahl'] >= SCHWELLENWERT_WARNUNG:
        klassifizierung, farbe = "Möglicherweise Phishing", C_WARNUNG
    else:
        klassifizierung, farbe = "Kein Phishing", C_POSITIV
    print_farbig(f"Klassifizierung: {klassifizierung}", farbe, bold=True)
    print_farbig("--------------------------------------------------", C_UEBERSCHRIFT)


# Mainfunktion des Skripts
def main():
    if len(sys.argv) != 2:
        print_farbig(f"Verwendung: python {os.path.basename(__file__)} <email_datei.eml>", C_FEHLER)
        sys.exit(1)

    dateipfad = sys.argv[1]
    if not os.path.exists(dateipfad) or not dateipfad.lower().endswith(".eml"):
        print_farbig(f"Fehler: Gültige .eml-Datei erwartet.", C_FEHLER)
        sys.exit(1)

    try:
        with open(dateipfad, 'rb') as f:
            nachricht = email.message_from_binary_file(f, policy=default)
        analyse_daten = analysiere_email(nachricht)
        print_ergebnisse(analyse_daten, dateipfad)
    except Exception as e:
        logging.error(f"Ein unerwarteter Fehler ist aufgetreten: {e}", exc_info=True)
        print_farbig(f"Kritischer Fehler bei der Analyse.", C_FEHLER)
        sys.exit(1)

if __name__ == "__main__":
    main()