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

// ---------- Types ----------

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

type Config struct {
	DomainRobot struct {
		BaseURL  string
		Email    string
		Password string
		OTP      string
	}
	RenewBeforeDays       int
	DNSTimeout            time.Duration
	DNSCheckInterval      time.Duration
	ACMETTLSeconds        int
	DomainsConfigPath     string
}

type apiResponse struct {
	StatusCode int
	Body       []byte
}

// ---------- Constants ----------

const (
	DefaultRenewBeforeDays         = 31
	DefaultDNSTimeoutSeconds       = 600
	DefaultACMETTLSecs             = 60
	DefaultDNSCheckIntervalSeconds = 15
)

// ---------- HTTP Client ----------

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ---------- Config Loading ----------

func loadConfig() (*Config, error) {
	cfg := &Config{}
	
	cfg.DomainRobot.BaseURL = strings.TrimRight(getEnvOrDefault("DR_BASE_URL", "https://domain-robot.de/api"), "/")
	cfg.DomainRobot.Email = os.Getenv("DR_EMAIL")
	cfg.DomainRobot.Password = os.Getenv("DR_PASS")
	cfg.DomainRobot.OTP = os.Getenv("DR_OTP")
	
	if cfg.DomainRobot.Email == "" || cfg.DomainRobot.Password == "" {
		return nil, errors.New("DR_EMAIL and DR_PASS must be set")
	}
	
	cfg.RenewBeforeDays = parseIntEnv("RENEW_BEFORE_DAYS", DefaultRenewBeforeDays)
	cfg.DNSTimeout = time.Duration(parseIntEnv("DNS_TIMEOUT_SECONDS", DefaultDNSTimeoutSeconds)) * time.Second
	cfg.DNSCheckInterval = time.Duration(parseIntEnv("DNS_CHECK_INTERVAL_SECONDS", DefaultDNSCheckIntervalSeconds)) * time.Second
	cfg.ACMETTLSeconds = parseIntEnv("ACME_TTL_SECONDS", DefaultACMETTLSecs)
	cfg.DomainsConfigPath = getEnvOrDefault("DOMAINS_CONF", "/etc/dns01-bot/domains.conf")
	
	return cfg, nil
}

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

// ---------- HTTP Helpers ----------

func doRequest(req *http.Request) (*apiResponse, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("warning: closing response body failed: %v", cerr)
		}
	}()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	
	return &apiResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
	}, nil
}

func createMultipartForm(fields map[string]string) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	
	for key, val := range fields {
		if val != "" {
			if err := writer.WriteField(key, val); err != nil {
				return nil, "", err
			}
		}
	}
	
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	
	return &buf, writer.FormDataContentType(), nil
}

// ---------- TLS Certificate Check ----------

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

func shouldRenewCertificate(domain string, renewBeforeDays int) (bool, error) {
	notAfter, err := getCertExpiry(domain)
	if err != nil {
		log.Printf("[cert] could not get expiry for %s: %v (assuming renewal needed)", domain, err)
		return true, nil
	}
	
	days := int(time.Until(notAfter).Hours() / 24)
	log.Printf("[cert] %s expires at %s (in %d days)", domain, notAfter.Format(time.RFC3339), days)
	
	return days <= renewBeforeDays, nil
}

// ---------- Plesk SSL It! ----------

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

// ---------- Domain Robot Client ----------

type DomainRobotClient struct {
	baseURL string
	token   string
  //client  *http.Client
}

func NewDomainRobotClient(baseURL, email, password, otp string) (*DomainRobotClient, error) {
	buf, contentType, err := createMultipartForm(map[string]string{
		"email":    email,
		"password": password,
		"otp":      otp,
	})
	if err != nil {
		return nil, fmt.Errorf("create login form: %w", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/login", buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)

	apiResp, err := doRequest(req)
	if err != nil {
		return nil, err
	}

	if apiResp.StatusCode != 200 {
		return nil, fmt.Errorf("login failed: %d: %s", apiResp.StatusCode, string(apiResp.Body))
	}

	var lr LoginResponse
	if err := json.Unmarshal(apiResp.Body, &lr); err != nil {
		return nil, fmt.Errorf("decode login response: %w", err)
	}
	if lr.Token == "" {
		return nil, errors.New("empty token in login response")
	}

	return &DomainRobotClient{
		baseURL: baseURL,
		token:   lr.Token,
		client:  httpClient,
	}, nil
}

func (c *DomainRobotClient) authRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
}

func (c *DomainRobotClient) GetZoneID(domain string) (int64, error) {
	url := c.baseURL + "/zones?full=true"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	c.authRequest(req)

	apiResp, err := doRequest(req)
	if err != nil {
		return 0, err
	}

	if apiResp.StatusCode != 200 {
		return 0, fmt.Errorf("zones failed: %d: %s", apiResp.StatusCode, string(apiResp.Body))
	}

	var zr ZoneListResponse
	if err := json.Unmarshal(apiResp.Body, &zr); err != nil {
		return 0, err
	}

	for _, z := range zr.Data {
		if z.Domain == domain {
			return z.ID, nil
		}
	}
	return 0, fmt.Errorf("zone for domain %s not found", domain)
}

func (c *DomainRobotClient) getZoneDetails(zoneID int64) (*ZoneDetailResponse, error) {
	url := fmt.Sprintf("%s/zones/%d", c.baseURL, zoneID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.authRequest(req)

	apiResp, err := doRequest(req)
	if err != nil {
		return nil, err
	}

	if apiResp.StatusCode != 200 {
		return nil, fmt.Errorf("zone detail failed: %d: %s", apiResp.StatusCode, string(apiResp.Body))
	}

	var zd ZoneDetailResponse
	if err := json.Unmarshal(apiResp.Body, &zd); err != nil {
		return nil, err
	}
	if len(zd.Data) == 0 {
		return nil, errors.New("zone detail: empty data")
	}
	return &zd, nil
}

func (c *DomainRobotClient) UpsertAcmeTXT(zoneID int64, subdomain, value string, ttl int) error {
	zd, err := c.getZoneDetails(zoneID)
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

	if existing == nil {
		return c.createTXTRecord(zoneID, zone.Domain, subdomain, value, ttl)
	}

	if existing.Content == value {
		log.Printf("[dns] TXT %s.%s already has expected value, nothing to update",
			subdomain, zone.Domain)
		return nil
	}

	return c.updateTXTRecord(zoneID, existing.ID, zone.Domain, subdomain, value)
}

func (c *DomainRobotClient) createTXTRecord(zoneID int64, zoneDomain, subdomain, value string, ttl int) error {
	log.Printf("[dns] creating TXT %s.%s", subdomain, zoneDomain)
	
	body := map[string]any{
		"subdomain":    subdomain,
		"type":    "TXT",
		"content": value,
		"ttl":     ttl,
	}
	b, _ := json.Marshal(body)
	
	url := fmt.Sprintf("%s/zones/%d", c.baseURL, zoneID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.authRequest(req)
	req.Header.Set("Content-Type", "application/json")

	apiResp, err := doRequest(req)
	if err != nil {
		return err
	}
	
	if apiResp.StatusCode != 200 {
		return fmt.Errorf("create TXT failed: %d: %s", apiResp.StatusCode, string(apiResp.Body))
	}
	return nil
}

func (c *DomainRobotClient) updateTXTRecord(zoneID, recordID int64, zoneDomain, subdomain, value string) error {
	log.Printf("[dns] updating TXT %s.%s (recordID=%d) to value=%s",
		subdomain, zoneDomain, recordID, value)

	buf, contentType, err := createMultipartForm(map[string]string{
		"name":  "content",
		"value": value,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/zones/%d/%d", c.baseURL, zoneID, recordID)
	req, err := http.NewRequest("PUT", url, buf)
	if err != nil {
		return err
	}
	c.authRequest(req)
	req.Header.Set("Content-Type", contentType)

	apiResp, err := doRequest(req)
	if err != nil {
		return err
	}
	
	if apiResp.StatusCode != 200 {
		return fmt.Errorf("update TXT failed: %d: %s", apiResp.StatusCode, string(apiResp.Body))
	}

	return nil
}

// ---------- DNS Verification ----------

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

// ---------- Domain Config ----------

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

// ---------- Domain Processing ----------

func setupDNSChallenge(client *DomainRobotClient, domain string, chal *Challenge, acmeTTL int) error {
	zoneID, err := client.GetZoneID(domain)
	if err != nil {
		return fmt.Errorf("get zone ID: %w", err)
	}
	
	if err := client.UpsertAcmeTXT(zoneID, chal.Host, chal.Value, acmeTTL); err != nil {
		return fmt.Errorf("upsert TXT: %w", err)
	}
	
	return nil
}

func processDomain(client *DomainRobotClient, cfg DomainConfig, renewBeforeDays int, dnsTimeout, dnsInterval time.Duration, acmeTTL int) {
	log.Printf("=== processing domain %s ===", cfg.Domain)

	shouldRenew, err := shouldRenewCertificate(cfg.Domain, renewBeforeDays)
	if err != nil {
		log.Printf("[cert] error checking certificate for %s: %v", cfg.Domain, err)
		return
	}
	
	if !shouldRenew {
		log.Printf("[cert] %s has > %d days left, skipping", cfg.Domain, renewBeforeDays)
		return
	}

	// 1) Get ACME challenge from Plesk
	chal, err := runPleskIssue(cfg.Domain, cfg.Email)
	if err != nil {
		log.Printf("[plesk] issue failed for %s: %v", cfg.Domain, err)
		return
	}
	log.Printf("[plesk] challenge for %s: host=%s value=%s", cfg.Domain, chal.Host, chal.Value)

	// 2) Setup DNS challenge
	if err := setupDNSChallenge(client, cfg.Domain, chal, acmeTTL); err != nil {
		log.Printf("[dns] setup failed for %s: %v", cfg.Domain, err)
		return
	}

	// 3) Wait for DNS propagation
	fqdn := chal.Host + "." + cfg.Domain
	if err := waitForDNS(fqdn, chal.Value, dnsTimeout, dnsInterval); err != nil {
		log.Printf("[dns] waitForDNS failed for %s: %v", cfg.Domain, err)
		return
	}

	// 4) Complete Plesk certificate issuance
	if err := runPleskContinue(cfg.Domain, cfg.Email); err != nil {
		log.Printf("[plesk] continue failed for %s: %v", cfg.Domain, err)
		return
	}

	log.Printf("=== done for %s ===", cfg.Domain)
}

// ---------- Main ----------

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	domains, err := loadDomainsConfig(cfg.DomainsConfigPath)
	if err != nil {
		return fmt.Errorf("load domains config: %w", err)
	}
	if len(domains) == 0 {
		log.Println("no domains configured, exiting")
		return nil
	}

	client, err := NewDomainRobotClient(
		cfg.DomainRobot.BaseURL,
		cfg.DomainRobot.Email,
		cfg.DomainRobot.Password,
		cfg.DomainRobot.OTP,
	)
	if err != nil {
		return fmt.Errorf("login to Domain-Robot failed: %w", err)
	}
	log.Println("Domain-Robot login ok")

	for _, d := range domains {
		processDomain(client, d, cfg.RenewBeforeDays, cfg.DNSTimeout, cfg.DNSCheckInterval, cfg.ACMETTLSeconds)
	}

	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.Println("dns01-bot starting")
	
	if err := run(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
	
	log.Println("dns01-bot finished")
}
