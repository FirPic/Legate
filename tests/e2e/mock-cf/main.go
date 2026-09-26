package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type cfResponse struct {
	Success  bool        `json:"success"`
	Errors   []string    `json:"errors"`
	Messages []string    `json:"messages"`
	Result   interface{} `json:"result"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecordReq struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

var (
	challtestsrvURL = "http://pebble-challtestsrv:8055"
	mu              sync.Mutex
	records         = make(map[string]string) // recordID -> host
	recCounter      = 1000
)

func main() {
	if u := os.Getenv("CHALLTESTSRV_URL"); u != "" {
		challtestsrvURL = strings.TrimRight(u, "/")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/zones", handleZones)
	mux.HandleFunc("/client/v4/zones/", handleZoneRecords)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("[mock-cf] starting on :%s (challtestsrv=%s)", port, challtestsrvURL)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("mock-cf server failed: %v", err)
	}
}

func handleZones(w http.ResponseWriter, r *http.Request) {
	zoneName := r.URL.Query().Get("name")
	if zoneName == "" {
		zoneName = "test.firpic.fr"
	}
	log.Printf("[mock-cf] GET /zones name=%s", zoneName)

	resp := cfResponse{
		Success: true,
		Errors:  []string{},
		Result: []cfZone{
			{
				ID:   "zone-test-12345",
				Name: zoneName,
			},
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleZoneRecords(w http.ResponseWriter, r *http.Request) {
	// Path format: /client/v4/zones/{zone_id}/dns_records or /client/v4/zones/{zone_id}/dns_records/{record_id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[3] != "dns_records" {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodPost && len(parts) == 4 {
		// Create DNS record
		var req cfRecordReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		recCounter++
		recID := fmt.Sprintf("rec-cf-%d", recCounter)
		host := req.Name
		if !strings.HasSuffix(host, ".") {
			host += "."
		}
		records[recID] = host
		mu.Unlock()

		log.Printf("[mock-cf] POST dns_record id=%s name=%s content=%s", recID, req.Name, req.Content)

		// Sync TXT to pebble-challtestsrv
		setPayload := map[string]string{
			"host":  host,
			"value": req.Content,
		}
		body, _ := json.Marshal(setPayload)
		if resp, err := http.Post(challtestsrvURL+"/set-txt", "application/json", bytes.NewReader(body)); err != nil {
			log.Printf("[mock-cf] WARNING: failed to call challtestsrv /set-txt: %v", err)
		} else {
			_ = resp.Body.Close()
			log.Printf("[mock-cf] successfully synchronized TXT with challtestsrv: %s -> %s", host, req.Content)
		}

		writeJSON(w, http.StatusOK, cfResponse{
			Success: true,
			Errors:  []string{},
			Result: cfRecord{
				ID:      recID,
				Type:    req.Type,
				Name:    req.Name,
				Content: req.Content,
			},
		})
		return
	}

	if r.Method == http.MethodDelete && len(parts) == 5 {
		// Delete DNS record
		recID := parts[4]
		mu.Lock()
		host, exists := records[recID]
		delete(records, recID)
		mu.Unlock()

		log.Printf("[mock-cf] DELETE dns_record id=%s (host=%s)", recID, host)

		if exists && host != "" {
			clearPayload := map[string]string{"host": host}
			body, _ := json.Marshal(clearPayload)
			if resp, err := http.Post(challtestsrvURL+"/clear-txt", "application/json", bytes.NewReader(body)); err != nil {
				log.Printf("[mock-cf] WARNING: failed to call challtestsrv /clear-txt: %v", err)
			} else {
				_ = resp.Body.Close()
				log.Printf("[mock-cf] cleared TXT in challtestsrv: %s", host)
			}
		}

		writeJSON(w, http.StatusOK, cfResponse{
			Success: true,
			Errors:  []string{},
			Result: map[string]string{
				"id": recID,
			},
		})
		return
	}

	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
