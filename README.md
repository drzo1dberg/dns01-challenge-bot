# dns01-bot

A small Go daemon that automates **Let’s Encrypt wildcard certificates** for Plesk servers using a **DNS-01 challenge** and the **Domain-Robot API** (InterNetX / Domain-Robot).

The tool is meant to run on the Plesk host itself and drives everything via:

* `plesk ext sslit` (Plesk “SSL It!” extension)
* Domain-Robot `/zones` API (to manage `_acme-challenge` TXT records) / external Nameserver you are using
* A simple `domains.conf` file with the domains to manage
* Optional cronjob wrapper for regular renewals

---

## Features

* 🔒 Automatically issues / renews **wildcard** Let’s Encrypt certificates
* 🧠 Decides per domain whether renewal is needed based on **TLS certificate expiry**
* 🤝 Talks to Domain-Robot API to:

  * find the correct DNS zone
  * create or update `_acme-challenge` TXT records
* ⏳ Waits until the TXT record is actually visible via DNS before letting ACME continue
* 🧾 Simple config:

  * `.env` file with credentials / settings
  * `domains.conf` with `domain email` pairs
* 🧰 Can be run:

  * manually (interactive, e.g. with OTP prompt)
  * via cron wrapper for unattended runs (if the Domain-Robot user does not require OTP)

---

## How it works

For each configured domain the bot performs roughly this flow:

1. **Check current certificate**

   * Opens a TLS connection to `<domain>:443`
   * Reads the server certificate and calculates days until expiry
   * If the cert is valid for more than `RENEW_BEFORE_DAYS` days, the domain is skipped

2. **Start Let’s Encrypt order in Plesk**

   * Calls:

     ```bash
     plesk ext sslit --certificate -issue \
       -domain <domain> \
       -registrationEmail <email> \
       -secure-domain \
       -wildcard
     ```
   * Parses the CLI output to extract:

     * `dnsRecordHost` → usually `_acme-challenge`
     * `dnsRecordValue` → the ACME token

3. **Update DNS via Domain-Robot**

   * Logs in to Domain-Robot `/login` to obtain a JWT token
   * Fetches zones via `/zones?full=true` and finds the zone for the domain
   * Fetches zone details via `/zones/{zoneId}`
   * If a TXT record for `_acme-challenge` exists:

     * Updates it via `PUT /zones/{zoneId}/{recordId}` (multipart form: `name=content`, `value=<token>`)
   * Otherwise:

     * Creates it via `POST /zones/{zoneId}` with JSON body:

       ```json
       {
         "subdomain": "_acme-challenge",
         "type": "TXT",
         "content": "<token>",
         "ttl": 60
       }
       ```

4. **Wait for DNS propagation**

   * Repeatedly performs `net.LookupTXT("_acme-challenge.<domain>")`
   * Sleeps `DNS_CHECK_INTERVAL_SECONDS` between attempts
   * Stops once the expected token is seen or `DNS_TIMEOUT_SECONDS` is reached

5. **Complete the order in Plesk**

   * Calls:

     ```bash
     plesk ext sslit --certificate -issue \
       -domain <domain> \
       -registrationEmail <email> \
       -continue
     ```
   * On success, the domain is now secured with the new wildcard certificate

All of the above is logged to stdout (or a log file when run via wrapper).

---

## Requirements

* **Plesk Obsidian** with the **SSL It!** extension (`plesk ext sslit`)
* Go-built binary deployed on the Plesk host
* Domain-Robot account with:

  * API access enabled
  * IP of the server whitelisted
* DNS zones for managed domains hosted at Domain-Robot
* Root access (or sudo) to install the binary and create config / log files

---

## Installation

1. **Build the binary** (on a dev machine)

   ```bash
   go build -o dns01-bot .
   ```

2. **Upload the binary to Plesk**

   * Upload into some subscription via the Plesk file manager (e.g. `/var/www/vhosts/<subscription>/<domain>/dns01-bot`)
   * SSH into the server (Web SSH is fine) and move it to a system-wide location:

   ```bash
   cp /var/www/vhosts/<subscription>/<domain>/dns01-bot /usr/local/bin/dns01-bot
   chmod +x /usr/local/bin/dns01-bot
   ```

3. **Create config directory**

   ```bash
   mkdir -p /etc/dns01-bot
   chmod 755 /etc/dns01-bot
   ```

---

## Configuration

### 1. `domains.conf`

List of domains to manage and the email used for Let’s Encrypt in Plesk:

```bash
cat >/etc/dns01-bot/domains.conf <<'EOF'
# domain         contact_email
example.com      admin@example.com
example.org      noc@example.org
EOF
```

Format:

* one domain per line
* whitespace-separated: `<domain> <email>`
* `#` at the beginning of a line = comment

---

### 2. `.env`

Environment configuration for the bot:

```bash
cat >/etc/dns01-bot/.env <<'EOF'
DR_BASE_URL=https://domain-robot.de/api
DR_EMAIL=YOUR_DOMAIN_ROBOT_LOGIN
DR_PASS=YOUR_DOMAIN_ROBOT_PASSWORD
DR_OTP=   # leave empty if OTP is not required

# How many days before expiry we renew
RENEW_BEFORE_DAYS=31

# DNS wait / polling behaviour
DNS_TIMEOUT_SECONDS=600
ACME_TTL_SECONDS=60
DNS_CHECK_INTERVAL_SECONDS=15

# Path to domains.conf
DOMAINS_CONF=/etc/dns01-bot/domains.conf
EOF

chmod 600 /etc/dns01-bot/.env   # important: only root can read/write
```

#### Environment variables

* `DR_BASE_URL` – Domain-Robot API base (defaults to `https://domain-robot.de/api`)
* `DR_EMAIL` – Domain-Robot login email
* `DR_PASS` – Domain-Robot password
* `DR_OTP` – One-time password (empty if not needed; see helper script below)
* `RENEW_BEFORE_DAYS` – renew when certificate has **≤ this many** days left (default 31)
* `DNS_TIMEOUT_SECONDS` – max time to wait for TXT record to show up
* `ACME_TTL_SECONDS` – TTL for `_acme-challenge` TXT record (default 60)
* `DNS_CHECK_INTERVAL_SECONDS` – delay between TXT DNS lookups
* `DOMAINS_CONF` – path to the domain configuration file

---

## Running the bot (manual)

For quick tests or a one-off renewal:

```bash
cd /etc/dns01-bot
set -a; . ./.env; set +a

/usr/local/bin/dns01-bot
```

Logs are written to stdout. For a **single domain**, just keep only that domain in `domains.conf`.

---

## OTP helper script (interactive)

If the Domain-Robot account currently **requires OTP** for login, a small helper script prompts for the OTP and passes it as environment variable to the bot.

```bash
cat >/usr/local/bin/run-dns01-bot <<'EOF'
#!/bin/bash
set -euo pipefail

cd /etc/dns01-bot

# Load .env
set -a
. ./.env
set +a

# Ask for OTP from user / password manager
read -p "Domain-Robot OTP: " DR_OTP
export DR_OTP

/usr/local/bin/dns01-bot | tee -a /var/log/dns01-bot.log
EOF

chmod +x /usr/local/bin/run-dns01-bot
touch /var/log/dns01-bot.log
```

Usage:

```bash
/usr/local/bin/run-dns01-bot
# paste the OTP from your authenticator / password manager
```

---

## Cron integration (OTP-free accounts)

Once you have a Domain-Robot user that does **not** require OTP, you can run the bot via cron.

### 1. Cron wrapper

```bash
cat >/usr/local/bin/dns01-bot-cron <<'EOF'
#!/bin/bash
set -euo pipefail

cd /etc/dns01-bot || exit 1

# Load .env
set -a
. ./.env
set +a

# Run bot, append to log
/usr/local/bin/dns01-bot >> /var/log/dns01-bot.log 2>&1
EOF

chmod +x /usr/local/bin/dns01-bot-cron
touch /var/log/dns01-bot.log
```

### 2. Test cron wrapper manually

```bash
/usr/local/bin/dns01-bot-cron
tail -n 100 /var/log/dns01-bot.log
```

### 3. Add crontab entry (e.g. every 12 hours)

```bash
crontab -e

0 */12 * * * /usr/local/bin/dns01-bot-cron

crontab -l
```

---

## Logging & troubleshooting

* Main log file (when using wrappers): `/var/log/dns01-bot.log`
* Typical log lines include:

  * certificate expiry data
  * Plesk `sslit` output (including ACME challenge)
  * DNS actions (create/update TXT)
  * DNS lookup status while waiting
* If something fails you’ll see messages like:

  * `[plesk] issue failed for ...`
  * `[dns] upsert TXT failed for ...`
  * `[dns] waitForDNS failed for ...`
  * `login to Domain-Robot failed: ...`

Use these to pinpoint whether the problem is on the Plesk side, Domain-Robot API, or DNS propagation.

---

## Security considerations

* `.env` contains API credentials – **must be `chmod 600`** and owned by root.
* Binary runs as root when triggered from root’s crontab / helper; treat it as privileged code:

  * keep it in `/usr/local/bin`
  * source code should be version controlled / reviewed
* Logfile `/var/log/dns01-bot.log` may contain:

  * Domain names
  * ACME tokens
  * Plesk output
    Make sure log rotation and access permissions fit your policies.

---

## Limitations / roadmap ideas

* Currently tailored to **Domain-Robot** as DNS provider.
* Uses `net.LookupTXT` and system resolver; no per-resolver configuration yet.
* Does not auto-cleanup old `_acme-challenge` records (but updates the existing record in-place).
* No concurrency per domain; domains are processed sequentially (which is fine for a small number of sites, but could be parallelized later).

---

## License
MIT 
