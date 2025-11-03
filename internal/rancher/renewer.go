package rancher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TokenRenewer manages Rancher token renewal for kubeconfig files
type TokenRenewer struct {
	KubeconfigPath  string
	DryRun          bool
	Debug           bool
	Kubeconfig      map[string]interface{}
	RancherBaseURL  string
	logger          *log.Logger
}

// ClusterInfo contains information about a Rancher cluster
type ClusterInfo struct {
	Name        string
	ClusterID   string
	ServerURL   string
	UserName    string
	Token       string
	ContextName string
}

// RenewalResults tracks the results of token renewal operations
type RenewalResults struct {
	Success []string
	Failed  []string
	Skipped []string
}

// NewTokenRenewer creates a new TokenRenewer instance
func NewTokenRenewer(kubeconfigPath string, dryRun bool, debug bool) *TokenRenewer {
	if kubeconfigPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
	}

	// Expand ~ if present
	if strings.HasPrefix(kubeconfigPath, "~/") {
		homeDir, _ := os.UserHomeDir()
		kubeconfigPath = filepath.Join(homeDir, kubeconfigPath[2:])
	}

	logPrefix := ""
	if debug {
		logPrefix = "[DEBUG] "
	}

	return &TokenRenewer{
		KubeconfigPath: kubeconfigPath,
		DryRun:         dryRun,
		Debug:          debug,
		logger:         log.New(os.Stdout, logPrefix, log.LstdFlags),
	}
}

// LoadKubeconfig loads and parses the kubeconfig file
func (tr *TokenRenewer) LoadKubeconfig() error {
	data, err := os.ReadFile(tr.KubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to read kubeconfig: %w", err)
	}

	err = yaml.Unmarshal(data, &tr.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	tr.logger.Printf("Loaded kubeconfig from %s\n", tr.KubeconfigPath)
	return nil
}

// SaveKubeconfig saves the updated kubeconfig file
func (tr *TokenRenewer) SaveKubeconfig() error {
	if tr.DryRun {
		tr.logger.Println("DRY RUN: Would save kubeconfig (skipping)")
		return nil
	}

	// Use yaml.v3 to maintain order and formatting
	data, err := yaml.Marshal(tr.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to marshal kubeconfig: %w", err)
	}

	err = os.WriteFile(tr.KubeconfigPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	tr.logger.Printf("Saved updated kubeconfig to %s\n", tr.KubeconfigPath)
	return nil
}

// BackupKubeconfig creates a backup of the kubeconfig file
func (tr *TokenRenewer) BackupKubeconfig() (string, error) {
	if tr.DryRun {
		tr.logger.Println("DRY RUN: Would create backup (skipping)")
		return "", nil
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup_%s", tr.KubeconfigPath, timestamp)

	data, err := os.ReadFile(tr.KubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("failed to read kubeconfig for backup: %w", err)
	}

	err = os.WriteFile(backupPath, data, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	tr.logger.Printf("Created backup at %s\n", backupPath)
	return backupPath, nil
}

// GetRancherClusters extracts Rancher-managed clusters from kubeconfig
func (tr *TokenRenewer) GetRancherClusters() []ClusterInfo {
	var rancherClusters []ClusterInfo

	// Get cluster information
	clusters := make(map[string]map[string]interface{})
	if clustersData, ok := tr.Kubeconfig["clusters"].([]interface{}); ok {
		for _, c := range clustersData {
			if cluster, ok := c.(map[string]interface{}); ok {
				name := cluster["name"].(string)
				clusterData := cluster["cluster"].(map[string]interface{})
				clusters[name] = clusterData
			}
		}
	}

	// Get user tokens
	users := make(map[string]map[string]interface{})
	if usersData, ok := tr.Kubeconfig["users"].([]interface{}); ok {
		for _, u := range usersData {
			if user, ok := u.(map[string]interface{}); ok {
				name := user["name"].(string)
				if userData, ok := user["user"].(map[string]interface{}); ok {
					users[name] = userData
				}
			}
		}
	}

	// Get contexts to map clusters to users
	if contextsData, ok := tr.Kubeconfig["contexts"].([]interface{}); ok {
		for _, ctx := range contextsData {
			if context, ok := ctx.(map[string]interface{}); ok {
				contextData := context["context"].(map[string]interface{})
				clusterName := contextData["cluster"].(string)
				userName := contextData["user"].(string)
				contextName := context["name"].(string)

				// Skip AWS EKS clusters
				if strings.Contains(clusterName, "arn:aws:eks") {
					continue
				}

				clusterInfo, clusterExists := clusters[clusterName]
				if !clusterExists {
					continue
				}

				serverURL, ok := clusterInfo["server"].(string)
				if !ok {
					continue
				}

				// Check if it's a Rancher cluster
				if strings.Contains(serverURL, "rancher") {
					// Extract cluster ID from URL
					re := regexp.MustCompile(`/k8s/clusters/([^/]+)`)
					matches := re.FindStringSubmatch(serverURL)
					if len(matches) > 1 {
						clusterID := matches[1]

						// Extract Rancher base URL
						parsedURL, err := url.Parse(serverURL)
						if err == nil {
							tr.RancherBaseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
						}

						// Get token for this user
						userInfo, userExists := users[userName]
						if !userExists {
							continue
						}

						token, ok := userInfo["token"].(string)
						if ok && strings.HasPrefix(token, "kubeconfig-") {
							rancherClusters = append(rancherClusters, ClusterInfo{
								Name:        clusterName,
								ClusterID:   clusterID,
								ServerURL:   serverURL,
								UserName:    userName,
								Token:       token,
								ContextName: contextName,
							})
						}
					}
				}
			}
		}
	}

	tr.logger.Printf("Found %d Rancher-managed clusters\n", len(rancherClusters))
	return rancherClusters
}

// GenerateNewToken generates a new token for a specific cluster using Rancher API
func (tr *TokenRenewer) GenerateNewToken(clusterInfo ClusterInfo, ttlMinutes int) (string, error) {
	apiURL := fmt.Sprintf("%s/v3/clusters/%s?action=generateKubeconfig",
		tr.RancherBaseURL, clusterInfo.ClusterID)

	// Convert TTL to milliseconds
	ttlMilliseconds := ttlMinutes * 60 * 1000

	requestBody := map[string]interface{}{
		"ttl": ttlMilliseconds,
	}

	if tr.DryRun {
		tr.logger.Printf("DRY RUN: Would call API to renew token for %s\n", clusterInfo.Name)
		return fmt.Sprintf("dry-run-token-%s", clusterInfo.Name), nil
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", clusterInfo.Token))
	req.Header.Set("Content-Type", "application/json")

	tr.logger.Printf("Requesting new token for cluster: %s\n", clusterInfo.Name)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract the config from the response
	configStr, ok := result["config"].(string)
	if !ok {
		return "", fmt.Errorf("config not found in response")
	}

	// Parse the returned kubeconfig
	var kubeconfigYAML map[string]interface{}
	if err := yaml.Unmarshal([]byte(configStr), &kubeconfigYAML); err != nil {
		return "", fmt.Errorf("failed to parse returned kubeconfig: %w", err)
	}

	// Extract the token from the generated kubeconfig
	if usersData, ok := kubeconfigYAML["users"].([]interface{}); ok {
		for _, u := range usersData {
			if user, ok := u.(map[string]interface{}); ok {
				if userData, ok := user["user"].(map[string]interface{}); ok {
					if newToken, ok := userData["token"].(string); ok && strings.HasPrefix(newToken, "kubeconfig-") {
						tr.logger.Printf("Successfully generated new token for %s\n", clusterInfo.Name)
						return newToken, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not extract token from API response")
}

// UpdateTokenInConfig updates a specific user's token in the kubeconfig
func (tr *TokenRenewer) UpdateTokenInConfig(userName, newToken string) {
	if usersData, ok := tr.Kubeconfig["users"].([]interface{}); ok {
		for _, u := range usersData {
			if user, ok := u.(map[string]interface{}); ok {
				if user["name"].(string) == userName {
					if userData, ok := user["user"].(map[string]interface{}); ok {
						oldToken := "no-token"
						if tok, ok := userData["token"].(string); ok {
							oldToken = tok
						}
						userData["token"] = newToken
						tr.logger.Printf("Updated token for user: %s\n", userName)
						if tr.Debug {
							tr.logger.Printf("  Old token: %s...\n", oldToken[:min(20, len(oldToken))])
							tr.logger.Printf("  New token: %s...\n", newToken[:min(20, len(newToken))])
						}
					}
					break
				}
			}
		}
	}
}

// RenewTokens renews tokens for Rancher clusters
func (tr *TokenRenewer) RenewTokens(clusterFilter string, ttlMinutes int) (*RenewalResults, error) {
	results := &RenewalResults{
		Success: []string{},
		Failed:  []string{},
		Skipped: []string{},
	}

	// Load kubeconfig
	if err := tr.LoadKubeconfig(); err != nil {
		return results, err
	}

	// Create backup
	backupPath, err := tr.BackupKubeconfig()
	if err != nil {
		return results, err
	}

	// Get Rancher clusters
	rancherClusters := tr.GetRancherClusters()

	if len(rancherClusters) == 0 {
		tr.logger.Println("WARNING: No Rancher-managed clusters found in kubeconfig")
		return results, nil
	}

	// Filter clusters if specified
	if clusterFilter != "" {
		filtered := []ClusterInfo{}
		for _, c := range rancherClusters {
			if c.Name == clusterFilter {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return results, fmt.Errorf("cluster '%s' not found", clusterFilter)
		}
		rancherClusters = filtered
	}

	// Process each cluster
	for _, clusterInfo := range rancherClusters {
		tr.logger.Printf("\nProcessing cluster: %s\n", clusterInfo.Name)
		tr.logger.Printf("  Cluster ID: %s\n", clusterInfo.ClusterID)
		tr.logger.Printf("  Current token: %s...\n", clusterInfo.Token[:min(30, len(clusterInfo.Token))])

		// Generate new token
		newToken, err := tr.GenerateNewToken(clusterInfo, ttlMinutes)
		if err != nil {
			tr.logger.Printf("WARNING: Failed to renew token for %s: %v\n", clusterInfo.Name, err)
			results.Failed = append(results.Failed, clusterInfo.Name)
			continue
		}

		// Update token in config
		tr.UpdateTokenInConfig(clusterInfo.UserName, newToken)
		results.Success = append(results.Success, clusterInfo.Name)
	}

	// Save updated kubeconfig
	if len(results.Success) > 0 && !tr.DryRun {
		if err := tr.SaveKubeconfig(); err != nil {
			return results, err
		}
	}

	// Print summary
	tr.logger.Println("\n" + strings.Repeat("=", 50))
	tr.logger.Println("TOKEN RENEWAL SUMMARY")
	tr.logger.Println(strings.Repeat("=", 50))
	tr.logger.Printf("Successfully renewed: %d clusters\n", len(results.Success))
	for _, cluster := range results.Success {
		tr.logger.Printf("  ✓ %s\n", cluster)
	}

	if len(results.Failed) > 0 {
		tr.logger.Printf("Failed to renew: %d clusters\n", len(results.Failed))
		for _, cluster := range results.Failed {
			tr.logger.Printf("  ✗ %s\n", cluster)
		}
	}

	if backupPath != "" {
		tr.logger.Printf("\nBackup saved at: %s\n", backupPath)
	}

	return results, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
