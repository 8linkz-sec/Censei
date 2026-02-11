package crawler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"censei/api"
	"censei/config"
	"censei/logging"
)

// Client handles HTTP requests for crawling
type Client struct {
	httpClient  *http.Client
	logger      *logging.Logger
	maxBodySize int64
}

// NewClient creates a new crawler client with optimized connection pooling
func NewClient(timeoutSeconds int, logger *logging.Logger, cfg *config.Config) *Client {
	// Create a custom transport with optimized settings
	// These values are tuned for high-concurrency scanning with many workers
	transport := &http.Transport{
		MaxIdleConns:          200,               // Total idle connections across all hosts (was 100)
		MaxIdleConnsPerHost:   20,                // Idle connections per host (was 10, default was 2)
		MaxConnsPerHost:       0,                 // No limit on total connections per host
		IdleConnTimeout:       90 * time.Second,  // Keep connections alive longer
		ResponseHeaderTimeout: time.Duration(timeoutSeconds) * time.Second,
		DisableKeepAlives:     false,             // Enable keep-alives for performance (5-10x faster)
		DisableCompression:    true,              // Speed up response processing
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip SSL certificate verification
		},
		// Prevent "unsolicited response" errors by handling connection reuse properly
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		// Optimize dialing and keep-alive probing
		ForceAttemptHTTP2:     false,             // Disable HTTP/2 for scanning (simpler, faster for many small requests)
		MaxResponseHeaderBytes: 10 << 20,         // 10 MB max header size (prevent abuse)
	}

	client := &http.Client{
		// Use timeout from config (http_timeout_seconds)
		// Note: This applies to entire request including body read
		// For large directory listings, increase http_timeout_seconds in config.json
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}

	maxBody := int64(cfg.MaxBodySizeMB) << 20 // Convert MB to bytes
	if maxBody <= 0 {
		maxBody = 5 << 20 // 5 MB default
	}

	return &Client{
		httpClient:  client,
		logger:      logger,
		maxBodySize: maxBody,
	}
}

// CheckHostAndFetch combines checking if host is online and fetching its content
// Returns if the host is online, the HTML content (if any), and any error
func (c *Client) CheckHostAndFetch(host api.Host) (bool, string, error) {
	c.logger.Debug("Checking host and fetching content: %s", host.URL)

	ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", host.URL, nil)
	if err != nil {
		c.logger.Error("Failed to create HTTP request for %s: %v", host.URL, err)
		return false, "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers to avoid blocking
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CenseiBot/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug("Host offline or unreachable: %s (%s)", host.URL, err)
		return false, "", nil // Not an error, just offline
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("Host responded with non-OK status: %s (Status: %d)", host.URL, resp.StatusCode)
		return false, "", nil
	}

	// Read the response body with configurable size limit to prevent memory exhaustion
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
	if err != nil {
		// Timeout errors for large directories (e.g., /calls-old/) are common
		// Log as debug and continue - the host is online, just slow to respond
		c.logger.Debug("Failed to read response body for %s: %v (skipping)", host.URL, err)
		return true, "", nil // Return empty body, but mark host as online
	}

	// Warn when body was truncated - later links in the listing will be missed
	if int64(len(bodyBytes)) >= c.maxBodySize {
		c.logger.Info("Response body truncated at %d MB for %s - some links may be missed", c.maxBodySize>>20, host.URL)
	}

	c.logger.Debug("Host online: %s (Status: %d, Content length: %d bytes)",
		host.URL, resp.StatusCode, len(bodyBytes))

	return true, string(bodyBytes), nil
}
