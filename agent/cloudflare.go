package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var cfConfigPath = filepath.Join(state, "cloudflare.enc")
var cfKeyPath = filepath.Join(state, "cloudflare.key")

type cloudflareConfig struct {
	AccountID       string `json:"account_id"`
	APIToken        string `json:"api_token"`
	ZoneAPIToken    string `json:"zone_api_token"`
	ZoneTokenID     string `json:"zone_token_id"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	APIEndpoint     string `json:"api_endpoint"`
	ZoneName        string `json:"zone_name"`
	TunnelID        string `json:"tunnel_id"`
	UpdatedAt       int64  `json:"updated_at"`
}

type cloudflareConfigInput struct {
	AccountID       string `json:"account_id"`
	APIToken        string `json:"api_token"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	APIEndpoint     string `json:"api_endpoint"`
	ZoneName        string `json:"zone_name"`
	TunnelID        string `json:"tunnel_id"`
}

func cfMask(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

func cfKey() ([]byte, error) {
	if b, e := os.ReadFile(cfKeyPath); e == nil {
		k, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if e == nil && len(k) == 32 {
			return k, nil
		}
		return nil, fmt.Errorf("invalid cloudflare key")
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(cfKeyPath), 0700); e != nil {
		return nil, e
	}
	k := make([]byte, 32)
	if _, e := crand.Read(k); e != nil {
		return nil, e
	}
	tmp := cfKeyPath + ".tmp"
	if e := os.WriteFile(tmp, []byte(base64.RawStdEncoding.EncodeToString(k)+"\n"), 0600); e != nil {
		return nil, e
	}
	if e := os.Rename(tmp, cfKeyPath); e != nil {
		return nil, e
	}
	return k, nil
}

func saveCloudflareConfig(c cloudflareConfig) error {
	k, e := cfKey()
	if e != nil {
		return e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = crand.Read(nonce); e != nil {
		return e
	}
	sealed := gcm.Seal(nonce, nonce, b, []byte("xshoter-cloudflare-v1"))
	if e := os.MkdirAll(filepath.Dir(cfConfigPath), 0700); e != nil {
		return e
	}
	tmp := cfConfigPath + ".tmp"
	if e := os.WriteFile(tmp, []byte(base64.RawStdEncoding.EncodeToString(sealed)+"\n"), 0600); e != nil {
		return e
	}
	return os.Rename(tmp, cfConfigPath)
}

func loadCloudflareStored() (cloudflareConfig, bool, error) {
	var c cloudflareConfig
	b, e := os.ReadFile(cfConfigPath)
	if os.IsNotExist(e) {
		return c, false, nil
	}
	if e != nil {
		return c, false, e
	}
	k, e := cfKey()
	if e != nil {
		return c, false, e
	}
	raw, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil {
		return c, false, e
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return c, false, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return c, false, e
	}
	if len(raw) < gcm.NonceSize() {
		return c, false, fmt.Errorf("invalid cloudflare config")
	}
	plain, e := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte("xshoter-cloudflare-v1"))
	if e != nil {
		return c, false, e
	}
	if e := json.Unmarshal(plain, &c); e != nil {
		return c, false, e
	}
	return c, true, nil
}

func effectiveCloudflareConfig() cloudflareConfig {
	c, _, _ := loadCloudflareStored()
	if c.ZoneName == "" {
		c.ZoneName = cfZoneName
	}
	if c.APIToken == "" {
		for _, p := range []string{cfTokenFile, "/root/.cloudflare-api-token"} {
			if b, e := os.ReadFile(p); e == nil && strings.TrimSpace(string(b)) != "" {
				c.APIToken = strings.TrimSpace(string(b))
				break
			}
		}
	}
	if c.APIEndpoint == "" && regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(c.AccountID) {
		c.APIEndpoint = "https://" + strings.ToLower(c.AccountID) + ".r2.cloudflarestorage.com"
	}
	return c
}

func mergeCloudflareInput(base cloudflareConfig, in cloudflareConfigInput) cloudflareConfig {
	if strings.TrimSpace(in.AccountID) != "" {
		base.AccountID = strings.ToLower(strings.TrimSpace(in.AccountID))
	}
	if strings.TrimSpace(in.APIToken) != "" {
		base.APIToken = strings.TrimSpace(in.APIToken)
	}
	if strings.TrimSpace(in.AccessKeyID) != "" {
		base.AccessKeyID = strings.TrimSpace(in.AccessKeyID)
	}
	if strings.TrimSpace(in.SecretAccessKey) != "" {
		base.SecretAccessKey = strings.TrimSpace(in.SecretAccessKey)
	}
	if strings.TrimSpace(in.APIEndpoint) != "" {
		base.APIEndpoint = strings.TrimRight(strings.TrimSpace(in.APIEndpoint), "/")
	}
	if strings.TrimSpace(in.ZoneName) != "" {
		base.ZoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.ZoneName)), ".")
	}
	if strings.TrimSpace(in.TunnelID) != "" {
		base.TunnelID = strings.ToLower(strings.TrimSpace(in.TunnelID))
	}
	if base.APIEndpoint == "" && base.AccountID != "" {
		base.APIEndpoint = "https://" + base.AccountID + ".r2.cloudflarestorage.com"
	}
	return base
}

func validateCloudflareConfig(c cloudflareConfig) error {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(c.AccountID) {
		return fmt.Errorf("invalid Cloudflare account id")
	}
	if len(c.APIToken) < 20 || strings.ContainsAny(c.APIToken, " \t\r\n") {
		return fmt.Errorf("invalid Cloudflare API token")
	}
	if c.ZoneName != "" && !domainRE.MatchString(c.ZoneName) {
		return fmt.Errorf("invalid Cloudflare zone name")
	}
	if c.TunnelID != "" && !cfID(c.TunnelID) {
		return fmt.Errorf("invalid Cloudflare tunnel id")
	}
	r2Any := c.AccessKeyID != "" || c.SecretAccessKey != ""
	if r2Any {
		if len(c.AccessKeyID) < 12 || len(c.SecretAccessKey) < 20 {
			return fmt.Errorf("R2 access key and secret are required")
		}
		u, e := url.Parse(c.APIEndpoint)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("invalid R2 API endpoint")
		}
	}
	return nil
}

func cfTokenCapabilities(c cloudflareConfig) R {
	outv := R{"active": false, "kind": "unknown", "permissions_visible": false, "permissions": []string{}, "dns_write": false, "zone_write": false, "tunnel_write": false, "zone_settings_write": false, "cache_purge": false}
	if c.APIToken == "" {
		return outv
	}
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	}
	var tokenID string
	if c.AccountID != "" {
		if v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/tokens/verify", c.APIToken, nil); e == nil {
			if m, _ := v["result"].(map[string]any); m != nil {
				outv["kind"] = "account"
				outv["status"] = m["status"]
				outv["active"] = fmt.Sprint(m["status"]) == "active"
				tokenID = fmt.Sprint(m["id"])
			}
		}
	}
	if tokenID == "" {
		if v, e := cfRequestWithToken("GET", "/user/tokens/verify", c.APIToken, nil); e == nil {
			if m, _ := v["result"].(map[string]any); m != nil {
				outv["kind"] = "user"
				outv["status"] = m["status"]
				outv["active"] = fmt.Sprint(m["status"]) == "active"
				tokenID = fmt.Sprint(m["id"])
			}
		} else {
			outv["error"] = e.Error()
			return outv
		}
	}
	if outv["kind"] != "account" || c.AccountID == "" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(tokenID) {
		return outv
	}
	d, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/tokens/"+tokenID, c.APIToken, nil)
	if e != nil {
		return outv
	}
	tm, _ := d["result"].(map[string]any)
	if tm == nil {
		return outv
	}
	perms := []string{}
	if ps, ok := tm["policies"].([]any); ok {
		for _, pr := range ps {
			pm, _ := pr.(map[string]any)
			if pm == nil {
				continue
			}
			if gs, ok := pm["permission_groups"].([]any); ok {
				for _, gr := range gs {
					gm, _ := gr.(map[string]any)
					if gm == nil {
						continue
					}
					n := strings.TrimSpace(fmt.Sprint(gm["name"]))
					if n != "" && n != "<nil>" {
						perms = append(perms, n)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	uniq := []string{}
	for _, n := range perms {
		if !seen[n] {
			seen[n] = true
			uniq = append(uniq, n)
		}
	}
	outv["permissions_visible"] = true
	outv["permissions"] = uniq
	for _, n := range uniq {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "dns write":
			outv["dns_write"] = true
		case "zone write":
			outv["zone_write"] = true
		case "cloudflare tunnel write":
			outv["tunnel_write"] = true
		case "zone settings write", "zone dns settings write":
			outv["zone_settings_write"] = true
		case "cache purge":
			outv["cache_purge"] = true
		}
	}
	return outv
}

func cfEffectiveCapabilities(c cloudflareConfig) R {
	v := cfTokenCapabilities(c)
	v["zone_control_ready"] = c.ZoneAPIToken != ""
	if c.ZoneAPIToken != "" {
		v["dns_write"] = true
		v["zone_write"] = true
		v["zone_settings_write"] = true
		v["cache_purge"] = true
	}
	return v
}

func cloudflareSummary(c cloudflareConfig, stored bool) R {
	return R{"ok": true, "stored": stored, "configured": c.AccountID != "" && c.APIToken != "", "account_id": c.AccountID, "zone_name": c.ZoneName,
		"api_token_set": c.APIToken != "", "api_token_masked": cfMask(c.APIToken), "zone_control_token_set": c.ZoneAPIToken != "", "r2_configured": c.AccessKeyID != "" && c.SecretAccessKey != "" && c.APIEndpoint != "",
		"access_key_id_masked": cfMask(c.AccessKeyID), "api_endpoint": c.APIEndpoint, "tunnel_id": c.TunnelID, "updated_at": c.UpdatedAt}
}

func cloudflareConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, stored, _ := loadCloudflareStored()
		c := effectiveCloudflareConfig()
		accounts := []R{}
		if dc, a, e := detectCFAccounts(c); e == nil {
			c = dc
			accounts = a
		}
		s := cloudflareSummary(c, stored)
		s["accounts"] = accounts
		s["capabilities"] = cfEffectiveCapabilities(c)
		out(w, 200, s)
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var in cloudflareConfigInput
	if body(r, &in) != nil {
		fail(w, 400, "invalid json")
		return
	}
	c := mergeCloudflareInput(effectiveCloudflareConfig(), in)
	if c.AccountID == "" {
		if dc, _, e := detectCFAccounts(c); e == nil {
			c = dc
		}
	}
	if e := validateCloudflareConfig(c); e != nil {
		fail(w, 400, e.Error())
		return
	}
	c.UpdatedAt = time.Now().Unix()
	if e := saveCloudflareConfig(c); e != nil {
		fail(w, 500, e.Error())
		return
	}
	out(w, 200, cloudflareSummary(c, true))
}

func cfRequestWithToken(method, endpoint, token string, payload any) (map[string]any, error) {
	var bodyReader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		bodyReader = strings.NewReader(string(b))
	}
	req, e := http.NewRequest(method, "https://api.cloudflare.com/client/v4"+endpoint, bodyReader)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")
	resp, e := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	var v map[string]any
	if e := json.NewDecoder(resp.Body).Decode(&v); e != nil {
		return nil, e
	}
	if ok, _ := v["success"].(bool); !ok {
		parts := []string{}
		if a, ok := v["errors"].([]any); ok {
			for _, raw := range a {
				if m, ok := raw.(map[string]any); ok {
					msg := strings.TrimSpace(fmt.Sprint(m["message"]))
					code := strings.TrimSpace(fmt.Sprint(m["code"]))
					if msg != "" {
						if code != "" && code != "<nil>" {
							parts = append(parts, code+": "+msg)
						} else {
							parts = append(parts, msg)
						}
					}
				}
			}
		}
		if len(parts) == 0 {
			parts = append(parts, "cloudflare api error")
		}
		return v, fmt.Errorf("%s", strings.Join(parts, "; "))
	}
	return v, nil
}

func cfZoneAccessToken(c *cloudflareConfig) (string, error) {
	if c.APIToken == "" || c.AccountID == "" {
		return "", fmt.Errorf("cloudflare account API token is not configured")
	}
	if c.ZoneAPIToken == "" {
		if saved, ok, e := loadCloudflareStored(); e == nil && ok && saved.ZoneAPIToken != "" {
			c.ZoneAPIToken, c.ZoneTokenID = saved.ZoneAPIToken, saved.ZoneTokenID
		}
	}
	if c.ZoneAPIToken != "" {
		if v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/tokens/verify", c.ZoneAPIToken, nil); e == nil {
			if m, _ := v["result"].(map[string]any); m != nil && fmt.Sprint(m["status"]) == "active" {
				return c.ZoneAPIToken, nil
			}
		}
	}
	caps := cfTokenCapabilities(*c)
	if dns, _ := caps["dns_write"].(bool); dns {
		if zone, _ := caps["zone_write"].(bool); zone {
			if settings, _ := caps["zone_settings_write"].(bool); settings {
				if purge, _ := caps["cache_purge"].(bool); purge {
					return c.APIToken, nil
				}
			}
		}
	}
	v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/tokens/permission_groups", c.APIToken, nil)
	if e != nil {
		return "", fmt.Errorf("zone access unavailable and control token cannot be created: %w", e)
	}
	wanted := map[string]bool{"DNS Read": true, "DNS Write": true, "Zone Read": true, "Zone Write": true, "Zone Settings Read": true, "Zone Settings Write": true, "Zone DNS Settings Read": true, "Zone DNS Settings Write": true, "Cache Purge": true}
	groups := []map[string]any{}
	found := map[string]bool{}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			name := strings.TrimSpace(fmt.Sprint(m["name"]))
			if m != nil && wanted[name] {
				id := strings.TrimSpace(fmt.Sprint(m["id"]))
				if regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
					groups = append(groups, map[string]any{"id": id})
					found[name] = true
				}
			}
		}
	}
	for _, n := range []string{"DNS Write", "Zone Read", "Zone Write", "Zone Settings Write", "Cache Purge"} {
		if !found[n] {
			return "", fmt.Errorf("Cloudflare permission group unavailable: %s", n)
		}
	}
	resource := "com.cloudflare.api.account." + c.AccountID
	payload := map[string]any{
		"name": "Xshoter Control Zone Automation",
		"policies": []any{map[string]any{
			"effect":            "allow",
			"resources":         map[string]any{resource: map[string]any{"com.cloudflare.api.account.zone.*": "*"}},
			"permission_groups": groups,
		}},
	}
	created, e := cfRequestWithToken("POST", "/accounts/"+url.PathEscape(c.AccountID)+"/tokens", c.APIToken, payload)
	if e != nil {
		return "", fmt.Errorf("failed to create Xshoter zone control token: %w", e)
	}
	m, _ := created["result"].(map[string]any)
	value := strings.TrimSpace(fmt.Sprint(m["value"]))
	id := strings.TrimSpace(fmt.Sprint(m["id"]))
	if len(value) < 40 || value == "<nil>" {
		return "", fmt.Errorf("Cloudflare did not return the zone control token value")
	}
	c.ZoneAPIToken, c.ZoneTokenID = value, id
	c.UpdatedAt = time.Now().Unix()
	if e := saveCloudflareConfig(*c); e != nil {
		return "", fmt.Errorf("zone control token created but could not be stored: %w", e)
	}
	return value, nil
}

func cfZoneRequest(c cloudflareConfig, method, endpoint string, payload any) (map[string]any, error) {
	token, e := cfZoneAccessToken(&c)
	if e != nil {
		return nil, e
	}
	return cfRequestWithToken(method, endpoint, token, payload)
}

func resolveCFZone(c cloudflareConfig) (string, string, error) {
	if c.ZoneName == "" {
		return "", "", fmt.Errorf("cloudflare zone is not configured")
	}
	if cfZoneID != "" && c.ZoneName == cfZoneName {
		return cfZoneID, c.ZoneName, nil
	}
	v, e := cfZoneRequest(c, "GET", "/zones?name="+url.QueryEscape(c.ZoneName)+"&status=active&per_page=1", nil)
	if e != nil {
		return "", c.ZoneName, e
	}
	a, ok := v["result"].([]any)
	if !ok || len(a) == 0 {
		return "", c.ZoneName, fmt.Errorf("cloudflare zone not found: %s", c.ZoneName)
	}
	m, _ := a[0].(map[string]any)
	id, _ := m["id"].(string)
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
		return "", c.ZoneName, fmt.Errorf("invalid cloudflare zone id")
	}
	return id, c.ZoneName, nil
}

func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func hmacBytes(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}

func r2Test(c cloudflareConfig) (int, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.APIEndpoint == "" {
		return 0, fmt.Errorf("R2 is not configured")
	}
	u, e := url.Parse(c.APIEndpoint)
	if e != nil {
		return 0, e
	}
	endpoint := strings.TrimRight(c.APIEndpoint, "/") + "/"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	payloadHash := sha256Hex("")
	canonicalHeaders := "host:" + u.Host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n"
	canonicalRequest := "GET\n/\n\n" + canonicalHeaders + "\nhost;x-amz-content-sha256;x-amz-date\n" + payloadHash
	scope := day + "/auto/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex(canonicalRequest)
	kDate := hmacBytes([]byte("AWS4"+c.SecretAccessKey), day)
	kRegion := hmacBytes(kDate, "auto")
	kService := hmacBytes(kRegion, "s3")
	kSigning := hmacBytes(kService, "aws4_request")
	sig := hex.EncodeToString(hmacBytes(kSigning, stringToSign))
	req, e := http.NewRequest("GET", endpoint, nil)
	if e != nil {
		return 0, e
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)
	resp, e := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if e != nil {
		return 0, e
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("R2 API HTTP %d", resp.StatusCode)
	}
	return strings.Count(string(b), "<Bucket>"), nil
}

func cloudflareTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var in cloudflareConfigInput
	if body(r, &in) != nil {
		fail(w, 400, "invalid json")
		return
	}
	c := mergeCloudflareInput(effectiveCloudflareConfig(), in)
	if c.AccountID == "" {
		if dc, _, e := detectCFAccounts(c); e == nil {
			c = dc
		}
	}
	if e := validateCloudflareConfig(c); e != nil {
		fail(w, 400, e.Error())
		return
	}
	_, accounts, _ := detectCFAccounts(c)
	result := R{"ok": true, "account_ok": false, "zone_ok": false, "r2_ok": false, "zone_name": c.ZoneName, "accounts": accounts, "account_id": c.AccountID, "capabilities": cfEffectiveCapabilities(c)}
	if v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID), c.APIToken, nil); e == nil {
		result["account_ok"] = true
		if m, ok := v["result"].(map[string]any); ok {
			result["account_name"] = m["name"]
		}
	} else {
		result["account_error"] = e.Error()
	}
	if id, _, e := resolveCFZone(c); e == nil {
		result["zone_ok"] = true
		result["zone_id_masked"] = cfMask(id)
	} else if c.ZoneName != "" {
		result["zone_error"] = e.Error()
	}
	if c.AccessKeyID != "" || c.SecretAccessKey != "" {
		if n, e := r2Test(c); e == nil {
			result["r2_ok"] = true
			result["r2_buckets"] = n
		} else {
			result["r2_error"] = e.Error()
		}
	}
	out(w, 200, result)
}

// --- Cloudflare control-plane automation v1.0.2 ---

type cfZoneCreateInput struct {
	Name string `json:"name"`
}

type cfTunnelRouteInput struct {
	TunnelID    string `json:"tunnel_id"`
	Hostname    string `json:"hostname"`
	OldHost     string `json:"old_hostname"`
	Service     string `json:"service"`
	NoTLSVerify bool   `json:"no_tls_verify"`
	DeleteDNS   bool   `json:"delete_dns"`
}

func cfID(s string) bool {
	return regexp.MustCompile(`^[a-f0-9-]{32,36}$`).MatchString(strings.ToLower(strings.TrimSpace(s)))
}

func detectCFAccounts(c cloudflareConfig) (cloudflareConfig, []R, error) {
	if c.APIToken == "" {
		return c, nil, fmt.Errorf("cloudflare API token is not configured")
	}
	v, e := cfRequestWithToken("GET", "/accounts?per_page=100", c.APIToken, nil)
	if e != nil {
		return c, nil, e
	}
	rows := []R{}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			rows = append(rows, R{"id": m["id"], "name": m["name"]})
		}
	}
	if c.AccountID == "" && len(rows) == 1 {
		c.AccountID = fmt.Sprint(rows[0]["id"])
	}
	return c, rows, nil
}

func cloudflareZones(c cloudflareConfig) ([]R, error) {
	var e error
	c, _, e = detectCFAccounts(c)
	if e != nil {
		return nil, e
	}
	if c.AccountID == "" || c.APIToken == "" {
		return nil, fmt.Errorf("cloudflare account is not configured")
	}
	v, e := cfZoneRequest(c, "GET", "/zones?account.id="+url.QueryEscape(c.AccountID)+"&per_page=100&order=name&direction=asc", nil)
	if e != nil {
		return nil, e
	}
	rows := []R{}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			rows = append(rows, R{"id": m["id"], "name": m["name"], "status": m["status"], "paused": m["paused"], "name_servers": m["name_servers"], "original_name_servers": m["original_name_servers"], "activated_on": m["activated_on"]})
		}
	}
	return rows, nil
}

func cloudflareZonesHandler(w http.ResponseWriter, r *http.Request) {
	c := effectiveCloudflareConfig()
	if r.Method == "GET" {
		rows, e := cloudflareZones(c)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "items": rows})
		return
	}
	if r.Method == "POST" {
		var in cfZoneCreateInput
		if body(r, &in) != nil {
			fail(w, 400, "invalid json")
			return
		}
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Name)), ".")
		if !domainRE.MatchString(name) {
			fail(w, 400, "invalid domain")
			return
		}
		v, e := cfZoneRequest(c, "POST", "/zones", map[string]any{"account": map[string]any{"id": c.AccountID}, "name": name, "type": "full"})
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		m, _ := v["result"].(map[string]any)
		out(w, 201, R{"ok": true, "zone": m})
		return
	}
	if r.Method == "DELETE" {
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
			fail(w, 400, "invalid zone id")
			return
		}
		var in struct {
			Confirm string `json:"confirm"`
		}
		if body(r, &in) != nil {
			fail(w, 400, "confirmation required")
			return
		}
		v, e := cfZoneRequest(c, "GET", "/zones/"+id, nil)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		m, _ := v["result"].(map[string]any)
		name, _ := m["name"].(string)
		if strings.ToLower(strings.TrimSpace(in.Confirm)) != strings.ToLower(name) {
			fail(w, 400, "domain confirmation does not match")
			return
		}
		if _, e = cfZoneRequest(c, "DELETE", "/zones/"+id, nil); e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "deleted": name})
		return
	}
	fail(w, 405, "method not allowed")
}

func cfConfigForZone(c cloudflareConfig, zone string) (cloudflareConfig, string, error) {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone != "" {
		c.ZoneName = zone
	}
	id, name, e := resolveCFZone(c)
	return c, id + "|" + name, e
}

func cloudflareZoneSettingsHandler(w http.ResponseWriter, r *http.Request) {
	c := effectiveCloudflareConfig()
	zone := r.URL.Query().Get("zone")
	if zone != "" {
		c.ZoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	}
	id, name, e := resolveCFZone(c)
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	if r.Method == "GET" {
		v, e := cfZoneRequest(c, "GET", "/zones/"+id+"/settings", nil)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		want := map[string]bool{"ssl": true, "always_use_https": true, "automatic_https_rewrites": true, "brotli": true, "http3": true, "min_tls_version": true}
		items := []R{}
		if a, ok := v["result"].([]any); ok {
			for _, raw := range a {
				m, _ := raw.(map[string]any)
				key, _ := m["id"].(string)
				if want[key] {
					items = append(items, R{"id": key, "value": m["value"], "editable": m["editable"]})
				}
			}
		}
		out(w, 200, R{"ok": true, "zone": name, "items": items})
		return
	}
	if r.Method == "PATCH" {
		var in struct {
			Setting string `json:"setting"`
			Value   any    `json:"value"`
		}
		if body(r, &in) != nil {
			fail(w, 400, "invalid json")
			return
		}
		allowed := map[string]bool{"ssl": true, "always_use_https": true, "automatic_https_rewrites": true, "brotli": true, "http3": true, "min_tls_version": true}
		if !allowed[in.Setting] {
			fail(w, 400, "setting not allowed")
			return
		}
		v, e := cfZoneRequest(c, "PATCH", "/zones/"+id+"/settings/"+in.Setting, map[string]any{"value": in.Value})
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "zone": name, "result": v["result"]})
		return
	}
	fail(w, 405, "method not allowed")
}

func cloudflareCacheHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	c := effectiveCloudflareConfig()
	var in struct {
		Zone  string   `json:"zone"`
		Files []string `json:"files"`
	}
	if body(r, &in) != nil {
		fail(w, 400, "invalid json")
		return
	}
	c.ZoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Zone)), ".")
	id, name, e := resolveCFZone(c)
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	payload := map[string]any{"purge_everything": true}
	if len(in.Files) > 0 {
		if len(in.Files) > 30 {
			fail(w, 400, "too many URLs")
			return
		}
		payload = map[string]any{"files": in.Files}
	}
	if _, e = cfZoneRequest(c, "POST", "/zones/"+id+"/purge_cache", payload); e != nil {
		fail(w, 502, e.Error())
		return
	}
	out(w, 200, R{"ok": true, "zone": name})
}

func cloudflareTunnelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method not allowed")
		return
	}
	c := effectiveCloudflareConfig()
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	}
	if c.AccountID == "" {
		fail(w, 503, "cloudflare account is not configured")
		return
	}
	v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/cfd_tunnel?is_deleted=false&per_page=100", c.APIToken, nil)
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	items := []R{}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			items = append(items, R{"id": m["id"], "name": m["name"], "status": m["status"], "created_at": m["created_at"], "connections": m["connections"], "config_src": m["config_src"]})
		}
	}
	out(w, 200, R{"ok": true, "items": items})
}

func cfTunnelConfig(c cloudflareConfig, id string) (map[string]any, error) {
	v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/cfd_tunnel/"+url.PathEscape(id)+"/configurations", c.APIToken, nil)
	if e != nil {
		return nil, e
	}
	m, _ := v["result"].(map[string]any)
	if m == nil {
		return map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}}, nil
	}
	cfg, _ := m["config"].(map[string]any)
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func cfServiceOK(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 300 {
		return false
	}
	for _, p := range []string{"http://", "https://", "unix://", "unix+tls://", "tcp://", "ssh://", "rdp://", "smb://"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func cfIngressRows(cfg map[string]any) []map[string]any {
	rows := []map[string]any{}
	if a, ok := cfg["ingress"].([]any); ok {
		for _, raw := range a {
			if m, ok := raw.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	}
	if len(rows) == 0 || fmt.Sprint(rows[len(rows)-1]["service"]) != "http_status:404" {
		rows = append(rows, map[string]any{"service": "http_status:404"})
	}
	return rows
}

func cfZoneForHostname(c cloudflareConfig, host string) (string, string, error) {
	zones, e := cloudflareZones(c)
	if e != nil {
		return "", "", e
	}
	host = strings.ToLower(strings.TrimSpace(host))
	best := ""
	id := ""
	for _, z := range zones {
		n := fmt.Sprint(z["name"])
		if host == n || strings.HasSuffix(host, "."+n) {
			if len(n) > len(best) {
				best = n
				id = fmt.Sprint(z["id"])
			}
		}
	}
	if id == "" {
		return "", "", fmt.Errorf("no Cloudflare zone found for hostname")
	}
	return id, best, nil
}

func cfEnsureTunnelDNS(c cloudflareConfig, tunnelID, host string) error {
	zoneID, _, e := cfZoneForHostname(c, host)
	if e != nil {
		return e
	}
	target := tunnelID + ".cfargotunnel.com"
	v, e := cfZoneRequest(c, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(host)+"&per_page=20", nil)
	if e != nil {
		return e
	}
	if a, ok := v["result"].([]any); ok && len(a) > 0 {
		m, _ := a[0].(map[string]any)
		typ := fmt.Sprint(m["type"])
		rid := fmt.Sprint(m["id"])
		if typ != "CNAME" {
			return fmt.Errorf("hostname already has non-CNAME DNS record")
		}
		_, e = cfZoneRequest(c, "PATCH", "/zones/"+zoneID+"/dns_records/"+rid, map[string]any{"type": "CNAME", "name": host, "content": target, "ttl": 1, "proxied": true})
		return e
	}
	_, e = cfZoneRequest(c, "POST", "/zones/"+zoneID+"/dns_records", map[string]any{"type": "CNAME", "name": host, "content": target, "ttl": 1, "proxied": true})
	return e
}

func cfDeleteTunnelDNS(c cloudflareConfig, tunnelID, host string) error {
	zoneID, _, e := cfZoneForHostname(c, host)
	if e != nil {
		return e
	}
	v, e := cfZoneRequest(c, "GET", "/zones/"+zoneID+"/dns_records?name="+url.QueryEscape(host)+"&type=CNAME&per_page=20", nil)
	if e != nil {
		return e
	}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			if strings.EqualFold(fmt.Sprint(m["content"]), tunnelID+".cfargotunnel.com") {
				_, e = cfZoneRequest(c, "DELETE", "/zones/"+zoneID+"/dns_records/"+fmt.Sprint(m["id"]), nil)
				return e
			}
		}
	}
	return nil
}

func cfPickTunnel(c cloudflareConfig) (cloudflareConfig, string, error) {
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	} else {
		return c, "", e
	}
	if c.TunnelID != "" {
		return c, c.TunnelID, nil
	}
	v, e := cfRequestWithToken("GET", "/accounts/"+url.PathEscape(c.AccountID)+"/cfd_tunnel?is_deleted=false&per_page=100", c.APIToken, nil)
	if e != nil {
		return c, "", e
	}
	ids := []string{}
	if a, ok := v["result"].([]any); ok {
		for _, raw := range a {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			id := fmt.Sprint(m["id"])
			if cfID(id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 1 {
		return c, ids[0], nil
	}
	if len(ids) == 0 {
		return c, "", fmt.Errorf("no Cloudflare Tunnel found")
	}
	return c, "", fmt.Errorf("multiple Cloudflare Tunnels found; select a default tunnel in Cloudflare settings")
}

func cfEnsureZoneForHostname(c cloudflareConfig, host string) (cloudflareConfig, string, string, string, []string, error) {
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	} else {
		return c, "", "", "", nil, e
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if !domainRE.MatchString(host) {
		return c, "", "", "", nil, fmt.Errorf("invalid hostname")
	}
	zones, e := cloudflareZones(c)
	if e != nil {
		return c, "", "", "", nil, e
	}
	best := ""
	zid := ""
	status := ""
	ns := []string{}
	for _, z := range zones {
		n := fmt.Sprint(z["name"])
		if host == n || strings.HasSuffix(host, "."+n) {
			if len(n) > len(best) {
				best = n
				zid = fmt.Sprint(z["id"])
				status = fmt.Sprint(z["status"])
				if a, ok := z["name_servers"].([]string); ok {
					ns = a
				} else if aa, ok := z["name_servers"].([]any); ok {
					ns = nil
					for _, x := range aa {
						ns = append(ns, fmt.Sprint(x))
					}
				}
			}
		}
	}
	if zid != "" {
		return c, zid, best, status, ns, nil
	}
	v, e := cfZoneRequest(c, "POST", "/zones", map[string]any{"account": map[string]any{"id": c.AccountID}, "name": host, "type": "full"})
	if e != nil {
		return c, "", "", "", nil, e
	}
	m, _ := v["result"].(map[string]any)
	if m == nil {
		return c, "", "", "", nil, fmt.Errorf("invalid Cloudflare zone response")
	}
	zid = fmt.Sprint(m["id"])
	best = fmt.Sprint(m["name"])
	status = fmt.Sprint(m["status"])
	if aa, ok := m["name_servers"].([]any); ok {
		for _, x := range aa {
			ns = append(ns, fmt.Sprint(x))
		}
	}
	return c, zid, best, status, ns, nil
}

func cfUpsertTunnelRoute(c cloudflareConfig, id, host, old, service string, noTLSVerify bool) error {
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	} else {
		return e
	}
	if !cfID(id) {
		return fmt.Errorf("invalid tunnel id")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	old = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(old)), ".")
	if !domainRE.MatchString(host) || !cfServiceOK(service) {
		return fmt.Errorf("invalid tunnel route")
	}
	cfg, e := cfTunnelConfig(c, id)
	if e != nil {
		return e
	}
	rows := cfIngressRows(cfg)
	kept := []map[string]any{}
	for _, m := range rows {
		h := ""
		if raw, ok := m["hostname"]; ok && raw != nil {
			h = strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
		}
		if h == host || (old != "" && h == old) {
			continue
		}
		kept = append(kept, m)
	}
	route := map[string]any{"hostname": host, "service": strings.TrimSpace(service)}
	if noTLSVerify {
		route["originRequest"] = map[string]any{"noTLSVerify": true}
	}
	if len(kept) > 0 && fmt.Sprint(kept[len(kept)-1]["service"]) == "http_status:404" {
		kept = append(kept[:len(kept)-1], route, kept[len(kept)-1])
	} else {
		kept = append(kept, route, map[string]any{"service": "http_status:404"})
	}
	config := map[string]any{"ingress": kept}
	if o, ok := cfg["originRequest"]; ok {
		config["originRequest"] = o
	}
	if _, e = cfRequestWithToken("PUT", "/accounts/"+url.PathEscape(c.AccountID)+"/cfd_tunnel/"+url.PathEscape(id)+"/configurations", c.APIToken, map[string]any{"config": config}); e != nil {
		return e
	}
	if e = cfEnsureTunnelDNS(c, id, host); e != nil {
		return fmt.Errorf("tunnel route saved but DNS failed: %w", e)
	}
	if old != "" && old != host {
		_ = cfDeleteTunnelDNS(c, id, old)
	}
	return nil
}

func cfDeleteTunnelRoute(c cloudflareConfig, id, host string, deleteDNS bool) error {
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	} else {
		return e
	}
	if !cfID(id) {
		return fmt.Errorf("invalid tunnel id")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	cfg, e := cfTunnelConfig(c, id)
	if e != nil {
		return e
	}
	rows := cfIngressRows(cfg)
	kept := []map[string]any{}
	for _, m := range rows {
		h := ""
		if raw, ok := m["hostname"]; ok && raw != nil {
			h = strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
		}
		if h == host {
			continue
		}
		kept = append(kept, m)
	}
	if len(kept) == 0 || fmt.Sprint(kept[len(kept)-1]["service"]) != "http_status:404" {
		kept = append(kept, map[string]any{"service": "http_status:404"})
	}
	config := map[string]any{"ingress": kept}
	if o, ok := cfg["originRequest"]; ok {
		config["originRequest"] = o
	}
	if _, e = cfRequestWithToken("PUT", "/accounts/"+url.PathEscape(c.AccountID)+"/cfd_tunnel/"+url.PathEscape(id)+"/configurations", c.APIToken, map[string]any{"config": config}); e != nil {
		return e
	}
	if deleteDNS {
		return cfDeleteTunnelDNS(c, id, host)
	}
	return nil
}

func cloudflareTunnelRoutesHandler(w http.ResponseWriter, r *http.Request) {
	c := effectiveCloudflareConfig()
	if dc, _, e := detectCFAccounts(c); e == nil {
		c = dc
	}
	id := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("id")))
	if !cfID(id) {
		fail(w, 400, "invalid tunnel id")
		return
	}
	if r.Method == "GET" {
		cfg, e := cfTunnelConfig(c, id)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		items := []R{}
		for _, m := range cfIngressRows(cfg) {
			raw, ok := m["hostname"]
			if !ok || raw == nil {
				continue
			}
			host := strings.TrimSpace(fmt.Sprint(raw))
			if host == "" || host == "<nil>" {
				continue
			}
			items = append(items, R{"hostname": host, "service": m["service"], "origin_request": m["originRequest"]})
		}
		out(w, 200, R{"ok": true, "items": items})
		return
	}
	if r.Method != "POST" && r.Method != "PATCH" && r.Method != "DELETE" {
		fail(w, 405, "method not allowed")
		return
	}
	var in cfTunnelRouteInput
	if body(r, &in) != nil {
		fail(w, 400, "invalid json")
		return
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Hostname)), ".")
	if !domainRE.MatchString(host) {
		fail(w, 400, "invalid hostname")
		return
	}
	if r.Method == "DELETE" {
		if e := cfDeleteTunnelRoute(c, id, host, in.DeleteDNS); e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, 200, R{"ok": true})
		return
	}
	if !cfServiceOK(in.Service) {
		fail(w, 400, "invalid service URL")
		return
	}
	if e := cfUpsertTunnelRoute(c, id, host, in.OldHost, in.Service, in.NoTLSVerify); e != nil {
		fail(w, 502, e.Error())
		return
	}
	out(w, 200, R{"ok": true, "hostname": host, "dns": "managed"})
}
