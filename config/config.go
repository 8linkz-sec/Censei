package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds application configuration
type Config struct {
	// Legacy API credentials (for censys-cli tool)
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`

	// Platform API v3 credentials
	BearerToken    string `json:"bearer_token"`
	OrganizationID string `json:"organization_id"`

	// General settings
	OutputDir             string `json:"output_dir"`
	HTTPTimeoutSeconds    int    `json:"http_timeout_seconds"`
	MaxConcurrentRequests int    `json:"max_concurrent_requests"`
	LogLevel              string `json:"log_level"`
	LogFile               string `json:"log_file"`
	CheckDir              string `json:"check_dir"`
	BinaryOutputFile      string `json:"binary_output_file"`
	MaxLinksPerDirectory  int    `json:"max_links_per_directory"`
	MaxTotalLinks         int    `json:"max_total_links"`
	MaxSkipsBeforeBlock   int    `json:"max_skips_before_block"`
	MaxBodySizeMB         int    `json:"max_body_size_mb"`
	BlocklistFile         string `json:"blocklist_file"`
	EnableBlocklist       bool   `json:"enable_blocklist"`

	// Legacy CLI parameters (for censys-cli tool)
	LegacyPages        int    `json:"legacy_pages"`
	LegacyPerPage      int    `json:"legacy_per_page"`
	LegacyIndexType    string `json:"legacy_index_type"`
	LegacySortOrder    string `json:"legacy_sort_order"`
	LegacyVirtualHosts string `json:"legacy_virtual_hosts"`

	// Platform API v3 parameters
	V3MaxResults int `json:"v3_max_results"`

	// Query file paths
	QueriesFileV3     string `json:"queries_file_v3"`
	QueriesFileLegacy string `json:"queries_file_legacy"`
}

// Query represents a predefined Censys query with its filters
type Query struct {
	Name           string   `json:"name"`
	Query          string   `json:"query"`
	Filters        []string `json:"filters"`
	Check          bool     `json:"check"`
	TargetFileName string   `json:"target_filename"`
	Recursive      string   `json:"recursive"`
	MaxDepth       int      `json:"max-depth"`
}

// LoadConfig loads and validates the application configuration from a file
func LoadConfig(path string) (*Config, error) {
	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate common config (no mode-specific validation yet)
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Log successful config load (before logger is initialized)
	fmt.Printf("[INFO] Configuration loaded successfully from %s\n", path)

	return &config, nil
}

// ValidateForLegacy validates config fields required for legacy mode
func ValidateForLegacy(cfg *Config) error {
	if cfg.APIKey == "" {
		return fmt.Errorf("api_key is required for legacy mode")
	}
	if cfg.APISecret == "" {
		return fmt.Errorf("api_secret is required for legacy mode")
	}
	if cfg.LegacyPages <= 0 {
		return fmt.Errorf("legacy_pages must be greater than 0")
	}
	if cfg.LegacyPerPage <= 0 {
		return fmt.Errorf("legacy_per_page must be greater than 0")
	}
	if cfg.LegacyIndexType == "" {
		return fmt.Errorf("legacy_index_type cannot be empty")
	}
	if cfg.LegacySortOrder == "" {
		return fmt.Errorf("legacy_sort_order cannot be empty")
	}
	if cfg.LegacyVirtualHosts == "" {
		return fmt.Errorf("legacy_virtual_hosts cannot be empty")
	}
	return nil
}

// ValidateForV3 validates config fields required for Platform API v3 mode
func ValidateForV3(cfg *Config) error {
	if cfg.BearerToken == "" {
		return fmt.Errorf("bearer_token is required for Platform API v3 mode")
	}
	if cfg.V3MaxResults <= 0 {
		return fmt.Errorf("v3_max_results must be greater than 0")
	}
	// OrganizationID is optional, no validation needed
	return nil
}

// LoadQueries loads predefined queries from a file
func LoadQueries(path string) ([]Query, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read queries file: %w", err)
	}

	var queries []Query
	err = json.Unmarshal(data, &queries)
	if err != nil {
		return nil, fmt.Errorf("failed to parse queries file: %w", err)
	}

	// Log successful queries load (before logger is initialized)
	fmt.Printf("[INFO] Loaded %d queries from %s\n", len(queries), path)

	return queries, nil
}

// validateConfig ensures that required fields are present
func validateConfig(cfg *Config) error {
	// Common validation (required for both modes)
	if cfg.HTTPTimeoutSeconds <= 0 {
		return fmt.Errorf("http_timeout_seconds must be greater than 0")
	}
	if cfg.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("max_concurrent_requests must be greater than 0")
	}

	// Validate output directory path to prevent path traversal
	if cfg.OutputDir == "" {
		return fmt.Errorf("output_dir path in config cannot be empty")
	}

	// Clean and validate the path
	cleanPath := filepath.Clean(cfg.OutputDir)

	// Check for path traversal sequences after cleaning
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("output_dir contains invalid path traversal sequence")
	}

	// Update to cleaned path
	cfg.OutputDir = cleanPath

	// Create output directory if it doesn't exist (directory can be empty, that's fine)
	if _, err := os.Stat(cfg.OutputDir); os.IsNotExist(err) {
		err := os.MkdirAll(cfg.OutputDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Validate binary output file path is set
	if cfg.BinaryOutputFile == "" {
		return fmt.Errorf("binary_output_file cannot be empty")
	}

	// Default max body size: 5 MB
	if cfg.MaxBodySizeMB <= 0 {
		cfg.MaxBodySizeMB = 5
	}

	return nil
}
