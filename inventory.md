===========================
dns01-bot – File Inventory
===========================

1. Binary (Programm)

  /usr/local/bin/dns01-bot
    - Das eigentliche Go-Programm.
    - Läuft als root (über Cron oder das Helper-Script).
    - Empfohlene Rechte: 755
      (chmod 755 /usr/local/bin/dns01-bot)


2. Helper-Skripte

  /usr/local/bin/run-dns01-bot
    - Interaktives Helper-Script.
    - Fragt nach dem Domain-Robot OTP-Code.
    - Lädt /etc/dns01-bot/.env und startet dns01-bot.
    - Schreibt Log nach /var/log/dns01-bot.log
    - Rechte: 755
      (chmod 755 /usr/local/bin/run-dns01-bot)

  /usr/local/bin/dns01-bot-cron      (optional / später)
    - Wrapper-Script für Cron (ohne OTP-Eingabe).
    - Lädt /etc/dns01-bot/.env und startet dns01-bot.
    - Wird z. B. in root’s Crontab eingetragen:
        0 */12 * * * /usr/local/bin/dns01-bot-cron
    - Rechte: 755
      (chmod 755 /usr/local/bin/dns01-bot-cron)


3. Konfiguration

  /etc/dns01-bot/                    (Verzeichnis)
    - Basisverzeichnis für Config & Umgebung.
    - Rechte: 755
      (chmod 755 /etc/dns01-bot)

  /etc/dns01-bot/domains.conf
    - Liste der Domains, die automatisch per DNS-01 erneuert werden.
    - Format (pro Zeile):
        domain.tld    contact@example.com
      Beispiel:
        grothe.guru   support@grothe.it
    - Rechte: 644 (oder 640)
      (chmod 644 /etc/dns01-bot/domains.conf)

  /etc/dns01-bot/.env
    - Environment-Variablen für dns01-bot:
        DR_BASE_URL=https://domain-robot.de/api
        DR_EMAIL=...
        DR_PASS=...
        DR_OTP=        # meist leer, außer bei manueller Eingabe
        RENEW_BEFORE_DAYS=31
        DNS_TIMEOUT_SECONDS=600
        ACME_TTL_SECONDS=60
        DNS_CHECK_INTERVAL_SECONDS=15
        DOMAINS_CONF=/etc/dns01-bot/domains.conf
    - Enthält Zugangsdaten → **nur root lesen!**
    - Rechte: 600
      (chmod 600 /etc/dns01-bot/.env)


4. Logs

  /var/log/dns01-bot.log
    - Sammel-Log des Bots (Helper & Cron).
    - Enthält:
      - Start/Ende des Bots
      - Plesk-Output (inkl. ACME-Challenge)
      - Domain-Robot API Aktivitäten (nur Status, keine Passwörter)
      - DNS-Checks (_acme-challenge TXT)
    - Rechte z. B.: 644 oder 640
      (touch /var/log/dns01-bot.log
       chmod 644 /var/log/dns01-bot.log)


5. Einmaliger Upload-Pfad (nur zur Info)

  /var/www/vhosts/<ABO>/<DOMAIN>/dns01-bot
    - Hier wurde die Go-Binary zunächst über den Plesk-Dateimanager hochgeladen.
    - Wird anschließend nach /usr/local/bin/dns01-bot kopiert.
    - Kann nach erfolgreichem Deployment gelöscht werden.


6. Cron (keine Datei von uns, aber wichtig)

  root’s Crontab (Bearbeitung über):
    crontab -e

  Beispiel-Eintrag:
    0 */12 * * * /usr/local/bin/dns01-bot-cron

  - Führt den Bot alle 12
