# DNS-01 Bot für Plesk & Domain-Robot

Automatisierte Verlängerung von **Wildcard-Zertifikaten (Let’s Encrypt)** auf unserem Plesk-Server per **DNS-01-Challenge** über die Domain-Robot-API.

Der Bot:

1. prüft die Restlaufzeit vorhandener Zertifikate,
2. triggert bei Bedarf Plesk/SSL It! per CLI,
3. setzt/aktualisiert den `_acme-challenge`-TXT-Record via Domain-Robot-API,
4. wartet, bis der TXT im DNS sichtbar ist,
5. bestätigt die Challenge per `-continue` und schließt die Zertifikatsausstellung ab.

> Wichtig: Der `_acme-challenge`-Record wird **nicht gelöscht**, sondern nur **erstellt bzw. aktualisiert**. Das ist gewollt, weil Let’s Encrypt Validierungen cached.

---

## 1. Voraussetzungen

- Plesk-Server mit SSH-Zugriff (root oder sudo)
- Plesk Let’s Encrypt / SSL It! Extension
- Domain-Robot-Account (mit API-Zugriff)
- Go-Binary `dns01-bot` (vorab gebaut)
- Aktuell: Login beim Domain-Robot **mit OTP**  
  → Workaround: Helper-Script fragt OTP zur Laufzeit ab (siehe unten)

---

## 2. Manuelle Zertifikatsausstellung per Plesk CLI (Referenz)

Zum Verständnis des Flows ohne Bot:

```bash
# 1. Wildcard-Order anstoßen (DNS-01 Challenge wird generiert)
plesk ext sslit --certificate -issue \
  -domain "<domain_name>" \
  -registrationEmail "<email>" \
  -secure-domain \
  -wildcard

# 2. Wenn der TXT korrekt gesetzt und im DNS sichtbar ist:
plesk ext sslit --certificate -issue \
  -domain "<domain_name>" \
  -registrationEmail "<email>" \
  -continue
````

Der Bot automatisiert genau diese Schritte (inkl. TXT-Handling & DNS-Check).

---

## 3. Deployment des `dns01-bot` auf dem Plesk-Server

### 3.1 Binary installieren

1. Binary per Plesk-Dateimanager in eine beliebige Domain hochladen
   (z. B. `/var/www/vhosts/<ABO>/<DOMAIN>/dns01-bot`).
2. Per Web-SSH auf dem Server:

```bash
cp /var/www/vhosts/<ABO>/<DOMAIN>/dns01-bot /usr/local/bin/dns01-bot
chmod +x /usr/local/bin/dns01-bot

# kurzer Funktionscheck
/usr/local/bin/dns01-bot --help 2>/dev/null || echo "binary aufrufbar"
```

### 3.2 Konfigurationsverzeichnis anlegen

```bash
mkdir -p /etc/dns01-bot
chmod 755 /etc/dns01-bot
```

### 3.3 `domains.conf` anlegen

Eine Zeile pro Domain, die per Bot verwaltet werden soll:

```bash
cat >/etc/dns01-bot/domains.conf <<'EOF'
# domain         contact_email
grothe.guru      support@grothe.it
# weitere Domains:
# beispiel.de    certs@firma.tld
EOF
```

Der Bot nimmt sich für jede Domain die hinterlegte Kontakt-E-Mail und ruft damit die Plesk-CLI auf.

### 3.4 `.env` anlegen (Domain-Robot-Zugang + Tuning)

```bash
cat >/etc/dns01-bot/.env <<'EOF'
DR_BASE_URL=https://domain-robot.de/api
DR_EMAIL=DEIN_LOGIN_BEI_DOMAIN_ROBOT
DR_PASS=DEIN_PASSWORT

# aktuell: OTP wird NICHT fix hinterlegt,
# sondern zur Laufzeit abgefragt (siehe Helper-Script)
DR_OTP=

# Zertifikate erneuern, wenn Restlaufzeit <= 31 Tage
RENEW_BEFORE_DAYS=31

# Max. Wartezeit, bis der TXT im DNS sichtbar ist (Sekunden)
DNS_TIMEOUT_SECONDS=600

# TTL für den _acme-challenge-TXT (Sekunden)
ACME_TTL_SECONDS=60

# Intervall zwischen den DNS-Checks (Sekunden)
DNS_CHECK_INTERVAL_SECONDS=15

# Pfad zur Domainliste
DOMAINS_CONF=/etc/dns01-bot/domains.conf
EOF

# .env nur für root lesbar (wichtig!)
chmod 600 /etc/dns01-bot/.env
```

**Wichtig:**
Kommentare immer in **eigener Zeile**. Kein `DR_OTP=   # Kommentar`, sonst landet der Kommentar als Wert in der Variable.

---

## 4. Helper-Script für Läufe mit OTP

Solange der Domain-Robot-Account ein OTP erfordert, läuft der Bot **manuell** über ein Helper-Script, das zur Laufzeit nach dem OTP fragt.

### 4.1 Helper-Script anlegen

```bash
cat >/usr/local/bin/run-dns01-bot <<'EOF'
#!/bin/bash
set -euo pipefail

cd /etc/dns01-bot

# .env laden
set -a
. ./.env
set +a

# OTP abfragen
read -p "Domain-Robot OTP: " DR_OTP
export DR_OTP

# Bot starten, Log anhängen
/usr/local/bin/dns01-bot | tee -a /var/log/dns01-bot.log
EOF

chmod +x /usr/local/bin/run-dns01-bot
touch /var/log/dns01-bot.log
```

### 4.2 Helper nutzen

```bash
/usr/local/bin/run-dns01-bot
# → OTP aus dem Passwortmanager einfügen, Enter, Bot läuft.
```

Der Bot:

* lädt `.env` und `domains.conf`,
* loggt sich mit E-Mail, Passwort + OTP beim Domain-Robot ein,
* prüft pro Domain die Restlaufzeit des Zertifikats,
* führt nur dann eine neue DNS-01-Challenge aus, wenn die Restlaufzeit <= `RENEW_BEFORE_DAYS` ist.

---

## 5. Beispiel: einmaliger Testrun

```bash
cd /etc/dns01-bot

# optional: Config prüfen/anpassen
vim .env
vim domains.conf

# Testrun mit OTP
/usr/local/bin/run-dns01-bot

# Logs prüfen
tail -n 100 /var/log/dns01-bot.log
```

Typischer Ablauf im Log:

* `[cert] <domain> expires at … (in XX days)`
* falls `XX <= RENEW_BEFORE_DAYS`: ACME-Flow startet
* `[plesk issue] ...`
* `[dns] creating/updating TXT _acme-challenge.<domain>`
* `[dns] TXT for _acme-challenge.<domain> ok: <token>`
* `[plesk continue] ...`
* `=== done for <domain> ===`

---

## 6. Cron-Integration (für später, wenn kein OTP mehr nötig)

**Aktuell** verhindert OTP echten Autopilot via Cron.
Sobald ein Domain-Robot-User ohne OTP zur Verfügung steht, kann die Ausführung komplett automatisiert werden.

### 6.1 Cron-Wrapper ohne OTP

```bash
cat >/usr/local/bin/dns01-bot-cron <<'EOF'
#!/bin/bash
set -euo pipefail

cd /etc/dns01-bot || exit 1

# .env laden
set -a
. ./.env
set +a

/usr/local/bin/dns01-bot >> /var/log/dns01-bot.log 2>&1
EOF

chmod +x /usr/local/bin/dns01-bot-cron
touch /var/log/dns01-bot.log
```

### 6.2 Cronjob (erst aktivieren, wenn DR_OTP leer ist und kein OTP mehr nötig)

```bash
crontab -e

# alle 12 Stunden
0 */12 * * * /usr/local/bin/dns01-bot-cron
```

Kontrolle:

```bash
crontab -l
tail -n 50 /var/log/dns01-bot.log
```

---

## 7. Technische Eckpunkte

* Der Bot nutzt einen eigenen `http.Client` mit Timeout (30 s) für Domain-Robot-Requests.
* Restlaufzeit des Zertifikats wird via TLS-Handshake auf `<domain>:443` ermittelt.
* `_acme-challenge`-TXT wird über:

  * `POST /zones/{zoneId}` (create)
  * `PUT /zones/{zoneId}/{recordId}` (update)
    gepflegt.
* Der TXT-Record wird **nicht gelöscht**, sondern beim nächsten Run überschrieben
  → robust gegenüber Let’s-Encrypt-Caching.
* DNS-Check erfolgt über `net.LookupTXT`, bis:

  * der erwartete Wert im TXT erscheint oder
  * `DNS_TIMEOUT_SECONDS` erreicht ist.

---

## 8. Markdown → HTML (für Odoo)

Wenn `pandoc` verfügbar ist, kann die README nach HTML konvertiert werden:

```bash
pandoc -f markdown -t html -s dns01-bot-readme.md -o dns01-bot-readme.html
```

Den Inhalt von `dns01-bot-readme.html` kann man anschließend in Odoo in ein HTML-Feld der Wissensdatenbank einfügen.

```
