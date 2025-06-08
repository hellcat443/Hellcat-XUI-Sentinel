package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

type ServerConfig struct {
	BaseURL   string `json:"baseUrl"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	InboundID int    `json:"inboundId"`
}

type ClientStat struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	Enable     bool   `json:"enable"`
	ExpiryTime int64  `json:"expiryTime"`
}

type ListResponse struct {
	Success bool `json:"success"`
	Msg     string `json:"msg"`
	Obj     []struct {
		ID          int          `json:"id"`
		ClientStats []ClientStat `json:"clientStats"`
		Settings    string       `json:"settings"`
	} `json:"obj"`
}

var (
	thresholdBytes  uint64
	intervalSeconds *int
	bannedUsers      map[string]bool
)

const (
	configFile    = "config.json"
	usageDataFile = "prev_usage.json"
	banFile       = "ban.json"
	logFile       = "monitor.log"
)

func init() {
	mb := flag.Uint64("threshold", 10, "Traffic limit MB")
	intervalSeconds = flag.Int("interval", 60, "Check interval sec")
	flag.Parse()
	thresholdBytes = *mb * 1024 * 1024
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	log.SetOutput(io.MultiWriter(f, os.Stdout))
	bannedUsers = loadBanned()
}

func main() {
	cfgs, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	prev := loadPrevUsage()
	for name, cfg := range cfgs {
		go monitorServer(name, cfg, prev)
	}
	select {}
}

func loadConfig() (map[string]ServerConfig, error) {
	b, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	m := map[string]ServerConfig{}
	err = json.Unmarshal(b, &m)
	return m, err
}

func loadPrevUsage() map[string]uint64 {
	m := map[string]uint64{}
	if b, err := os.ReadFile(usageDataFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func savePrevUsage(m map[string]uint64) {
	b, err := json.Marshal(m)
	if err != nil {
		log.Printf("marshal prev: %v", err)
		return
	}
	_ = os.WriteFile(usageDataFile, b, 0644)
}

func loadBanned() map[string]bool {
	m := map[string]bool{}
	if b, err := os.ReadFile(banFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveBanned(m map[string]bool) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Printf("marshal banned: %v", err)
		return
	}
	_ = os.WriteFile(banFile, b, 0644)
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}
}

func login(c *http.Client, cfg ServerConfig) error {
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/login"
	form := url.Values{
		"username":      {cfg.Username},
		"password":      {cfg.Password},
		"twoFactorCode": {""},
	}
	resp, err := c.PostForm(endpoint, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func fetchClientStats(c *http.Client, cfg ServerConfig) ([]ClientStat, string, error) {
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/panel/inbound/list"
	resp, err := c.Post(endpoint, "application/json", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var lr ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, "", err
	}
	if !lr.Success {
		return nil, "", fmt.Errorf(lr.Msg)
	}
	for _, inb := range lr.Obj {
		if inb.ID == cfg.InboundID {
			return inb.ClientStats, inb.Settings, nil
		}
	}
	return nil, "", fmt.Errorf("inbound %d not found", cfg.InboundID)
}

func changeClientEnable(c *http.Client, cfg ServerConfig, uuid string, stat ClientStat, enable bool) error {
	clientData := map[string]interface{}{
		"id":         uuid,
		"flow":       "xtls-rprx-vision",
		"email":      stat.Email,
		"limitIp":    0,
		"totalGB":    0,
		"expiryTime": 0,
		"enable":     enable,
		"tgId":       "",
		"subId":      "",
		"comment":    "",
		"reset":      0,
	}

	wrapped := map[string]interface{}{
		"clients": []interface{}{clientData},
	}

	jsonBytes, _ := json.Marshal(wrapped)
	form := url.Values{
		"id":       {fmt.Sprint(cfg.InboundID)},
		"settings": {string(jsonBytes)},
	}

	url := strings.TrimRight(cfg.BaseURL, "/") + "/panel/inbound/updateClient/" + uuid
	log.Printf("POST %s — %s", url, stat.Email)

	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s", body)
	}
	return nil
}

func restartPanel(c *http.Client, cfg ServerConfig) error {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/panel/setting/restartPanel"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("restart failed: %s", body)
	}
	return nil
}

func monitorServer(name string, cfg ServerConfig, prev map[string]uint64) {
	client := newClient()
	for {
		if err := login(client, cfg); err != nil {
			log.Printf("[%s] login err: %v", name, err)
			time.Sleep(10 * time.Second)
			continue
		}

		stats, settingsJSON, err := fetchClientStats(client, cfg)
		if err != nil {
			log.Printf("[%s] fetch stats err: %v", name, err)
			time.Sleep(10 * time.Second)
			continue
		}

		uuidMap := map[string]string{}
		var parsed struct {
			Clients []struct {
				Email string `json:"email"`
				ID    string `json:"id"`
			} `json:"clients"`
		}
		if err := json.Unmarshal([]byte(settingsJSON), &parsed); err != nil {
			log.Printf("[%s] failed to parse settings JSON: %v", name, err)
		} else {
			for _, client := range parsed.Clients {
				uuidMap[client.Email] = client.ID
				log.Printf("[%s] loaded UUID for %s: %s", name, client.Email, client.ID)
			}
		}

		for _, c := range stats {
			if !c.Enable || bannedUsers[c.Email] {
				continue
			}
			total := c.Up + c.Down
			key := fmt.Sprintf("%s|%s|%d", name, c.Email, c.ID)
			delta := total - prev[key]
			log.Printf("[%s] %s (ID:%d) ∆ %d", name, c.Email, c.ID, delta)

			if delta > thresholdBytes {
				log.Printf("[%s] %s exceeded", name, c.Email)
				uuid := uuidMap[c.Email]
				if uuid == "" {
					log.Printf("[%s] no uuid for %s", name, c.Email)
				} else {
					if err := changeClientEnable(client, cfg, uuid, c, false); err != nil {
						log.Printf("[%s] disable err: %v", name, err)
					} else {
						log.Printf("[%s] %s banned", name, c.Email)
						bannedUsers[c.Email] = true
						saveBanned(bannedUsers)
						restartPanel(client, cfg)
					}
					go func(u string, cc ClientStat) {
						time.Sleep(1 * time.Hour)
						login(client, cfg)
						changeClientEnable(client, cfg, u, cc, true)
					}(uuid, c)
				}
			}
			prev[key] = total
		}
		savePrevUsage(prev)
		time.Sleep(time.Duration(*intervalSeconds) * time.Second)
	}
}
