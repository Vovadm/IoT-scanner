package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

const (
	defaultAPIURL  = "http://localhost:8000/api"
	defaultNetwork = "192.168.1.0/24"
)

type DeviceResult struct {
	IPAddress   string   `json:"ip_address"`
	MACAddress  string   `json:"mac_address,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Vendor      string   `json:"vendor,omitempty"`
	OpenPorts   []int    `json:"open_ports,omitempty"`
	OS          string   `json:"os,omitempty"`
	DeviceType  string   `json:"device_type,omitempty"`
	PortDetails []string `json:"port_details,omitempty"`
}

type ScanCreateRequest struct {
	TargetNetwork string `json:"target_network"`
	Name          string `json:"name,omitempty"`
}

type ScanResponse struct {
	Scan struct {
		ID            int    `json:"id"`
		TargetNetwork string `json:"target_network"`
		Status        string `json:"status"`
	} `json:"scan"`
	Message string `json:"message"`
}

type PendingScan struct {
	ID            int    `json:"id"`
	TargetNetwork string `json:"target_network"`
	Name          string `json:"name"`
	Status        string `json:"status"`
}

type PendingScansResponse struct {
	Scans []PendingScan `json:"scans"`
}

func main() {
	apiURL := flag.String("api", defaultAPIURL, "Backend API URL")
	network := flag.String("network", "", "Target network (CIDR) - if empty, runs in watch mode")
	scanName := flag.String("name", "", "Scan name")
	watchMode := flag.Bool("watch", false, "Watch mode: poll API for pending scans")
	pollInterval := flag.Int("interval", 5, "Poll interval in seconds (watch mode)")
	flag.Parse()

	printBanner()

	// If network specified, run single scan
	if *network != "" {
		runSingleScan(*apiURL, *network, *scanName)
		return
	}

	// If watch flag or no network, run in watch mode
	if *watchMode || *network == "" {
		runWatchMode(*apiURL, *pollInterval)
		return
	}
}

func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           IoT Scanner - Go Native Edition v1.1               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func runWatchMode(apiURL string, pollInterval int) {
	log.Printf("👀 Starting WATCH MODE")
	log.Printf("🌐 API URL: %s", apiURL)
	log.Printf("⏱️  Poll interval: %d seconds", pollInterval)
	log.Printf("💡 Create scans via web UI - they will be picked up automatically!")
	fmt.Println()
	log.Printf("⏳ Waiting for pending scans... (Press Ctrl+C to stop)")
	fmt.Println()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Println()
			log.Printf("👋 Shutting down...")
			return
		case <-ticker.C:
			pendingScans, err := getPendingScans(apiURL)
			if err != nil {
				log.Printf("⚠️  Failed to check pending scans: %v", err)
				continue
			}

			for _, scan := range pendingScans {
				fmt.Println()
				log.Printf("🎯 Found pending scan ID=%d, network=%s", scan.ID, scan.TargetNetwork)
				executeScan(apiURL, scan.ID, scan.TargetNetwork)
				fmt.Println()
				log.Printf("⏳ Waiting for pending scans...")
			}
		}
	}
}

func getPendingScans(apiURL string) ([]PendingScan, error) {
	url := fmt.Sprintf("%s/scans/pending", apiURL)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Endpoint not found - might need to be added
		return nil, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var response PendingScansResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Scans, nil
}

func runSingleScan(apiURL, network, scanName string) {
	log.Printf("📡 Target network: %s", network)
	log.Printf("🌐 API URL: %s", apiURL)
	fmt.Println()

	// Create scan via API
	log.Printf("📝 Creating scan in database...")
	scan, err := createScan(apiURL, network, scanName)
	if err != nil {
		log.Fatalf("❌ Failed to create scan: %v", err)
	}
	log.Printf("✅ Created scan ID: %d", scan.Scan.ID)
	fmt.Println()

	executeScan(apiURL, scan.Scan.ID, network)
}

func executeScan(apiURL string, scanID int, network string) {
	// Mark scan as in_progress
	if err := updateScanStatus(apiURL, scanID, "in_progress"); err != nil {
		log.Printf("⚠️  Failed to update scan status: %v", err)
	}

	// Scan network
	devices, err := scanNetwork(network)
	if err != nil {
		log.Printf("⚠️  Scan error: %v", err)
	}

	fmt.Println()
	log.Printf("📊 Total devices found: %d", len(devices))
	fmt.Println()

	// Send results
	log.Printf("📤 Sending results to API...")
	successCount := 0
	for i, device := range devices {
		if err := sendDeviceResult(apiURL, scanID, device); err != nil {
			log.Printf("   ❌ [%d/%d] Failed: %s - %v", i+1, len(devices), device.IPAddress, err)
		} else {
			successCount++
			hostname := device.Hostname
			if hostname == "" {
				hostname = "(no hostname)"
			}
			log.Printf("   ✅ [%d/%d] %s | %s | %d ports | %s",
				i+1, len(devices), device.IPAddress, device.MACAddress, len(device.OpenPorts), hostname)
		}
	}

	fmt.Println()

	// Complete scan
	if err := completeScan(apiURL, scanID); err != nil {
		log.Printf("⚠️  Failed to complete scan: %v", err)
	} else {
		log.Printf("🎉 Scan completed! Sent %d/%d devices", successCount, len(devices))
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      Scan Complete                           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

func updateScanStatus(apiURL string, scanID int, status string) error {
	url := fmt.Sprintf("%s/scans/%d/status", apiURL, scanID)

	body, _ := json.Marshal(map[string]string{"status": status})
	req, _ := http.NewRequest("PATCH", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func createScan(apiURL, network, name string) (*ScanResponse, error) {
	url := fmt.Sprintf("%s/scans/", apiURL)

	reqBody := ScanCreateRequest{
		TargetNetwork: network,
		Name:          name,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var scan ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scan); err != nil {
		return nil, err
	}

	return &scan, nil
}

func sendDeviceResult(apiURL string, scanID int, device DeviceResult) error {
	url := fmt.Sprintf("%s/scans/%d/results", apiURL, scanID)

	body, _ := json.Marshal(device)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

func completeScan(apiURL string, scanID int) error {
	url := fmt.Sprintf("%s/scans/%d/complete", apiURL, scanID)

	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func scanNetwork(network string) ([]DeviceResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	devices := make(map[string]*DeviceResult)

	// Phase 1: ARP scan
	log.Printf("🔍 Phase 1/3: ARP scan for live hosts...")
	arpDevices := arpScan()
	log.Printf("   Found %d hosts in ARP table", len(arpDevices))
	for ip, mac := range arpDevices {
		devices[ip] = &DeviceResult{
			IPAddress:  ip,
			MACAddress: mac,
		}
	}

	// Phase 2: Nmap scan
	log.Printf("🔍 Phase 2/3: Nmap port scan...")
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(network),
		nmap.WithPorts("21,22,23,25,53,80,110,139,143,443,445,554,993,995,1433,1883,3306,3389,5432,5555,5900,8000,8008,8080,8443,8554,8888,9000,27017"),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
	)
	if err != nil {
		return nil, fmt.Errorf("nmap init failed: %w", err)
	}

	log.Printf("   Running nmap scan (this may take a few minutes)...")

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %w", err)
	}

	if warnings != nil && len(*warnings) > 0 {
		log.Printf("   ⚠️  Nmap warnings: %v", *warnings)
	}

	hostsUp := 0
	for _, host := range result.Hosts {
		if host.Status.State == "up" {
			hostsUp++
		}
	}
	log.Printf("   Nmap found %d hosts up", hostsUp)

	// Process nmap results
	for _, host := range result.Hosts {
		if host.Status.State != "up" {
			continue
		}

		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ip = addr.Addr
			}
		}

		if ip == "" {
			continue
		}

		device, exists := devices[ip]
		if !exists {
			device = &DeviceResult{IPAddress: ip}
			devices[ip] = device
		}

		// MAC address
		for _, addr := range host.Addresses {
			if addr.AddrType == "mac" {
				device.MACAddress = addr.Addr
				if addr.Vendor != "" {
					device.Vendor = addr.Vendor
				}
			}
		}

		// Hostname from nmap
		for _, hostname := range host.Hostnames {
			if hostname.Name != "" {
				device.Hostname = hostname.Name
				break
			}
		}

		// Open ports
		for _, port := range host.Ports {
			if port.State.State == "open" {
				device.OpenPorts = append(device.OpenPorts, int(port.ID))
				detail := fmt.Sprintf("%d/%s %s %s", port.ID, port.Protocol, port.Service.Name, port.Service.Product)
				device.PortDetails = append(device.PortDetails, detail)
			}
		}
	}

	// Phase 3: Hostname resolution
	log.Printf("🔍 Phase 3/3: Resolving hostnames...")
	resolved := 0
	for ip, device := range devices {
		if device.Hostname == "" {
			device.Hostname = resolveHostnameMulti(ip)
			if device.Hostname != "" {
				resolved++
			}
		}
	}
	log.Printf("   Resolved %d additional hostnames", resolved)

	// Filter real devices
	var results []DeviceResult
	for _, device := range devices {
		// Skip broadcast/multicast addresses
		if strings.HasPrefix(device.IPAddress, "224.") ||
			strings.HasSuffix(device.IPAddress, ".0") ||
			strings.HasSuffix(device.IPAddress, ".255") {
			continue
		}
		if device.MACAddress != "" || len(device.OpenPorts) > 0 || device.Hostname != "" {
			results = append(results, *device)
		}
	}

	return results, nil
}

func arpScan() map[string]string {
	devices := make(map[string]string)

	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		// macOS format: hostname (ip) at mac on interface
		re := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)`)
		for _, line := range lines {
			matches := re.FindStringSubmatch(line)
			if len(matches) == 3 {
				devices[matches[1]] = matches[2]
			}
		}
	}

	return devices
}

// resolveHostnameMulti tries multiple methods to resolve hostname
func resolveHostnameMulti(ip string) string {
	// Method 1: Reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		if name != "" && !strings.HasPrefix(name, ip) {
			return name
		}
	}

	// Method 2: NetBIOS (nmblookup) - works for Windows/Samba devices
	hostname := netbiosLookup(ip)
	if hostname != "" {
		return hostname
	}

	// Method 3: mDNS via dns-sd (macOS)
	hostname = mdnsLookup(ip)
	if hostname != "" {
		return hostname
	}

	return ""
}

func netbiosLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try nmblookup (Samba tool)
	cmd := exec.CommandContext(ctx, "nmblookup", "-A", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse output: Looking for lines with <00> which is the computer name
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "<00>") && !strings.Contains(line, "<GROUP>") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
	}

	return ""
}

func mdnsLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Reverse IP for PTR query
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	reverseIP := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])

	// Try dns-sd (macOS)
	cmd := exec.CommandContext(ctx, "dns-sd", "-Q", reverseIP, "PTR")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "PTR") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					name := fields[len(fields)-1]
					name = strings.TrimSuffix(name, ".")
					if name != "" && !strings.Contains(name, "in-addr.arpa") {
						return name
					}
				}
			}
		}
	}

	return ""
}
