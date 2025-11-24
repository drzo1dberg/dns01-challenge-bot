package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DomainConfig struct {
	Domain string
	Email  string
}

type ZoneListResponse struct {
	Data []struct {
		ID     int64  `json:"id"`
		Domain string `json:"domain"`
	} `json:"data"`
}

type ZoneDetailResponse struct {
	Data []struct {
		ID      int64        `json:"id"`
		Domain  string       `json:"domain"`
		Records []ZoneRecord `json:"records"`
	} `json:"data"`
}

type ZoneRecord struct {
	ID        int64  `json:"id"`
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	TTL       int    `json:"ttl"`
	Prio      int    `json:"prio"`
	Hidden    int    `json:"hidden"`
	DynDNS    string `json:"dyndns"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type Challenge struct {
	Host  string
	Value string
}

// ---------- Konstante Defaults ----------

const (
	DefaultRenewBeforeDays         = 31
	DefaultDNSTimeoutSeconds       = 600 // 10 Minuten
	DefaultACMETTLSecs             = 60  // TTL für _acme-challenge
	DefaultDNSCheckIntervalSeconds = 15  // Intervall für TXT-Check
)

// ---------- HTTP-Client mit Timeout ----------

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ---------- Helpers ----------

func getEnvOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func parseIntEnv(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

// ---------- TLS: Zertifikats-Check ----------

func getCertExpiry(domain string) (time.Time, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return time.Time{}, errors.New("no peer certificates")
	}

	return state.PeerCertificates[0].NotAfter, nil
}

// ---------- Plesk / SSL It! ----------

var (
	hostRe  = regexp.MustCompile(`dnsRecordHost:\s*(\S+)`)
	valueRe = regexp.MustCompile(`dnsRecordValue:\s*(\S+)`)
)

func parseChallenge(out string) (*Challenge, error) {
	hostMatch := hostRe.FindStringSubmatch(out)
	valMatch := valueRe.FindStringSubmatch(out)

	if len(hostMatch) < 2 || len(valMatch) < 2 {
		return nil, errors.New("could not parse dnsRecordHost/Value from sslit output")
	}

	return &Challenge{
		Host:  strings.TrimSpace(hostMatch[1]),
		Value: strings.TrimSpace(valMatch[1]),
	}, nil
}

func runPleskIssue(domain, email string) (*Challenge, error) {
	cmd := exec.Command("plesk", "ext", "sslit", "--certificate", "-issue",
		"-domain", domain,
		"-registrationEmail", email,
		"-secure-domain",
		"-wildcard",
	)

	out, err := cmd.CombinedOutput()
	log.Printf("[plesk issue] domain=%s out=\n%s", domain, string(out))
	if err != nil {
		return nil, fmt.Errorf("plesk issue failed: %w", err)
	}

	chal, perr := parseChallenge(string(out))
	if perr != nil {
		return nil, perr
	}
	return chal, nil
}

func runPleskContinue(domain, email string) error {
	cmd := exec.Command("plesk", "ext", "sslit", "--certificate", "-issue",
		"-domain", domain,
		"-registrationEmail", email,
		"-continue",
	)

	out, err := cmd.CombinedOutput()
	log.Printf("[plesk continue] domain=%s out=\n%s", domain, string(out))
	if err != nil {
		return fmt.Errorf("plesk continue failed: %w", err)
	}
	return nil
}

// ---------- Domain-Robot API ----------

func loginDomainRobot(baseURL, email, pass, otp string) (string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	if err := writer.WriteField("email", email); err != nil {
		return "", err
	}
	if err := writer.WriteField("password", pass); err != nil {
		return "", err
	}
	if otp != "" {
		if err := writer.WriteField("otp", otp); err != nil {
			return "", err
		}
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", baseURL+"/login", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: closing login response body failed: %v", cerr)
		}
	}()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login failed: %s: %s", resp.Status, string(b))
	}

	var lr LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}
	if lr.Token == "" {
		return "", errors.New("empty token in login response")
	}
	return lr.Token, nil
}

func authRequest(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
}

func getZoneID(baseURL, token, domain string) (int64, error) {
	url := baseURL + "/zones?full=true"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	authRequest(req, token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("zones request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: closing zones response body failed: %v", cerr)
		}
	}()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("zones failed: %s: %s", resp.Status, string(b))
	}

	var zr ZoneListResponse
	if err := json.NewDecoder(resp.Body).Decode(&zr); err != nil {
		return 0, err
	}

	for _, z := range zr.Data {
		if z.Domain == domain {
			return z.ID, nil
		}
	}
	return 0, fmt.Errorf("zone for domain %s not found", domain)
}

func getZoneDetails(baseURL, token string, zoneID int64) (*ZoneDetailResponse, error) {
	url := fmt.Sprintf("%s/zones/%d", baseURL, zoneID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	authRequest(req, token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zone detail request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: closing zone detail response body failed: %v", cerr)
		}
	}()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("zone detail failed: %s: %s", resp.Status, string(b))
	}

	var zd ZoneDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&zd); err != nil {
		return nil, err
	}
	if len(zd.Data) == 0 {
		return nil, errors.New("zone detail: empty data")
	}
	return &zd, nil
}

func upsertAcmeTXT(baseURL, token string, zoneID int64, subdomain, value string, ttl int) error {
	zd, err := getZoneDetails(baseURL, token, zoneID)
	if err != nil {
		return err
	}
	zone := zd.Data[0]

	var existing *ZoneRecord
	for _, r := range zone.Records {
		if r.Subdomain == subdomain && r.Type == "TXT" {
			rec := r
			existing = &rec
			break
		}
	}

	// 1) FALL: es gibt noch keinen _acme-challenge -> anlegen (JSON wie bisher)
	if existing == nil {
		log.Printf("[dns] creating TXT %s.%s", subdomain, zone.Domain)
		body := map[string]any{
			"name":    subdomain,
			"type":    "TXT",
			"content": value,
			"ttl":     ttl,
		}
		b, _ := json.Marshal(body)
		url := fmt.Sprintf("%s/zones/%d", baseURL, zoneID)
		req, err := http.NewRequest("POST", url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		authRequest(req, token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("create TXT request failed: %w", err)
		}
		defer func() {
			if cerr := resp.Body.Close(); cerr != nil {
				log.Printf("warning: closing create TXT response body failed: %v", cerr)
			}
		}()
		if resp.StatusCode != 200 {
			bb, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("create TXT failed: %s: %s", resp.Status, string(bb))
		}
		return nil
	}

	// 2) FALL: Record existiert -> nur den Inhalt aktualisieren (multipart/form-data)
	if existing.Content == value {
		log.Printf("[dns] TXT %s.%s already has expected value, nothing to update",
			subdomain, zone.Domain)
		return nil
	}

	log.Printf("[dns] updating TXT %s.%s (recordID=%d) to value=%s",
		subdomain, zone.Domain, existing.ID, value)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	// Feldname im API-Schema = "content"
	if err := w.WriteField("name", "content"); err != nil {
		return err
	}
	if err := w.WriteField("value", value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/zones/%d/%d", baseURL, zoneID, existing.ID)
	req, err := http.NewRequest("PUT", url, &buf)
	if err != nil {
		return err
	}
	authRequest(req, token)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update TXT request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: closing update TXT response body failed: %v", cerr)
		}
	}()
	if resp.StatusCode != 200 {
		bb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update TXT failed: %s: %s", resp.Status, string(bb))
	}

	return nil
}

// ---------- DNS-Check ----------

func waitForDNS(fqdn, expected string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		txts, err := net.LookupTXT(fqdn)
		if err == nil {
			for _, txt := range txts {
				if txt == expected {
					log.Printf("[dns] TXT for %s ok: %s", fqdn, txt)
					return nil
				}
			}
			log.Printf("[dns] TXT for %s present but different: %v", fqdn, txts)
		} else {
			log.Printf("[dns] lookup error for %s: %v", fqdn, err)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("dns timeout for %s", fqdn)
		}
		time.Sleep(interval)
	}
}

// ---------- Domain-Config lesen ----------

func loadDomainsConfig(path string) ([]DomainConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var res []DomainConfig
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			log.Printf("skip invalid line in domains.conf: %q", line)
			continue
		}
		res = append(res, DomainConfig{
			Domain: fields[0],
			Email:  fields[1],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------- Main-Flow pro Domain ----------

func processDomain(baseURL, token string, cfg DomainConfig, renewBeforeDays int, dnsTimeout, dnsInterval time.Duration, acmeTTL int) {
	log.Printf("=== processing domain %s ===", cfg.Domain)

	notAfter, err := getCertExpiry(cfg.Domain)
	if err != nil {
		log.Printf("[cert] could not get expiry for %s: %v (assuming we should try to issue)", cfg.Domain, err)
	} else {
		days := int(time.Until(notAfter).Hours() / 24)
		log.Printf("[cert] %s expires at %s (in %d days)", cfg.Domain, notAfter.Format(time.RFC3339), days)
		if days > renewBeforeDays {
			log.Printf("[cert] %s has > %d days left, skipping", cfg.Domain, renewBeforeDays)
			return
		}
	}

	// 1) ACME-Challenge von Plesk holen
	chal, err := runPleskIssue(cfg.Domain, cfg.Email)
	if err != nil {
		log.Printf("[plesk] issue failed for %s: %v", cfg.Domain, err)
		return
	}
	log.Printf("[plesk] challenge for %s: host=%s value=%s", cfg.Domain, chal.Host, chal.Value)

	// 2) TXT upserten
	zoneID, err := getZoneID(baseURL, token, cfg.Domain)
	if err != nil {
		log.Printf("[dns] getZoneID failed for %s: %v", cfg.Domain, err)
		return
	}
	if err := upsertAcmeTXT(baseURL, token, zoneID, chal.Host, chal.Value, acmeTTL); err != nil {
		log.Printf("[dns] upsert TXT failed for %s: %v", cfg.Domain, err)
		return
	}

	// 3) DNS warten
	fqdn := chal.Host + "." + cfg.Domain
	if err := waitForDNS(fqdn, chal.Value, dnsTimeout, dnsInterval); err != nil {
		log.Printf("[dns] waitForDNS failed for %s: %v", cfg.Domain, err)
		return
	}

	// 4) Plesk continue
	if err := runPleskContinue(cfg.Domain, cfg.Email); err != nil {
		log.Printf("[plesk] continue failed for %s: %v", cfg.Domain, err)
		return
	}

	log.Printf("=== done for %s ===", cfg.Domain)
}

// ---------- main ----------

func main() {
	log.SetOutput(os.Stdout)
	log.Println("dns01-bot starting")

	baseURL := strings.TrimRight(getEnvOrDefault("DR_BASE_URL", "https://domain-robot.de/api"), "/")
	drEmail := os.Getenv("DR_EMAIL")
	drPass := os.Getenv("DR_PASS")
	drOTP := os.Getenv("DR_OTP")
	if drEmail == "" || drPass == "" {
		log.Fatal("DR_EMAIL and DR_PASS must be set in environment")
	}

	renewBeforeDays := parseIntEnv("RENEW_BEFORE_DAYS", DefaultRenewBeforeDays)
	dnsTimeoutSec := parseIntEnv("DNS_TIMEOUT_SECONDS", DefaultDNSTimeoutSeconds)
	dnsTimeout := time.Duration(dnsTimeoutSec) * time.Second

	acmeTTLSec := parseIntEnv("ACME_TTL_SECONDS", DefaultACMETTLSecs)
	dnsCheckIntervalSec := parseIntEnv("DNS_CHECK_INTERVAL_SECONDS", DefaultDNSCheckIntervalSeconds)
	dnsInterval := time.Duration(dnsCheckIntervalSec) * time.Second

	domainsPath := getEnvOrDefault("DOMAINS_CONF", "/etc/dns01-bot/domains.conf")
	domains, err := loadDomainsConfig(domainsPath)
	if err != nil {
		log.Fatalf("could not load domains config: %v", err)
	}
	if len(domains) == 0 {
		log.Println("no domains configured, exiting")
		return
	}

	// Login
	token, err := loginDomainRobot(baseURL, drEmail, drPass, drOTP)
	if err != nil {
		log.Fatalf("login to Domain-Robot failed: %v", err)
	}
	log.Println("Domain-Robot login ok")

	for _, d := range domains {
		processDomain(baseURL, token, d, renewBeforeDays, dnsTimeout, dnsInterval, acmeTTLSec)
	}

	log.Println("dns01-bot finished")
}
