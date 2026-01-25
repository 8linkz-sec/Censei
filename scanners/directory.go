package scanners

import (
	"net/url"
	"strings"
	"sync/atomic"

	"censei/api"
	"censei/config"
	"censei/logging"

	"github.com/PuerkitoBio/goquery"
)

// HTTPClient interface for HTTP requests in scanner
type HTTPClient interface {
	CheckHostAndFetch(host api.Host) (bool, string, error)
}

// HostTracker tracks skip events and blocking status for hosts
type HostTracker interface {
	RecordSkip(url string)     // Registriert einen Skip/Timeout für die URL
	IsBlocked(url string) bool // Prüft ob der Base-Host blockiert ist
}

// DirectoryScanner handles scanning of open directory listings
type DirectoryScanner struct {
	logger          *logging.Logger
	totalLinksCount int64
}

// NewDirectoryScanner creates a new directory scanner instance
func NewDirectoryScanner(logger *logging.Logger) *DirectoryScanner {
	return &DirectoryScanner{
		logger:          logger,
		totalLinksCount: 0,
	}
}

// ScanHost processes a host for directory listings and extracts file links
func (ds *DirectoryScanner) ScanHost(host api.Host, htmlContent string) []string {
	ds.logger.Debug("Scanning directory listing for host: %s", host.URL)

	// Extract links from HTML content
	links := ds.extractLinks(host.URL, htmlContent)

	ds.logger.Debug("Directory scan found %d links for %s", len(links), host.URL)
	return links
}

// ScanHostRecursive performs recursive directory scanning with configurable limits
func (ds *DirectoryScanner) ScanHostRecursive(host api.Host, htmlContent string, maxDepth int, client HTTPClient, cfg *config.Config, tracker HostTracker) []string {
	if maxDepth <= 0 {
		return ds.ScanHost(host, htmlContent)
	}
	// Reset counter for new scan
	atomic.StoreInt64(&ds.totalLinksCount, 0)
	visited := make(map[string]bool)
	allLinks := []string{}
	ds.scanRecursive(host.URL, htmlContent, 0, maxDepth, visited, &allLinks, client, cfg, tracker)
	return allLinks
}

// scanRecursive performs the actual recursive scanning
func (ds *DirectoryScanner) scanRecursive(baseURL, htmlContent string, currentDepth, maxDepth int, visited map[string]bool, allLinks *[]string, client HTTPClient, cfg *config.Config, tracker HostTracker) {
	// Check if host is already blocked before any processing
	if tracker != nil && tracker.IsBlocked(baseURL) {
		ds.logger.Debug("Host blocked, skipping recursion for: %s", baseURL)
		return
	}

	// Check total links limit with thread-safe counter
	currentCount := atomic.LoadInt64(&ds.totalLinksCount)
	ds.logger.Debug("Recursion check: current count=%d, limit=%d, depth=%d, URL=%s", currentCount, cfg.MaxTotalLinks, currentDepth, baseURL)

	if cfg.MaxTotalLinks > 0 && int(currentCount) > cfg.MaxTotalLinks {
		ds.logger.Info("Host reached maximum total links (%d >= %d), marking for skip", currentCount, cfg.MaxTotalLinks)
		if tracker != nil {
			tracker.RecordSkip(baseURL)
		}
		return
	}

	// Check if already visited or max depth reached first (before size check)
	if visited[baseURL] || currentDepth >= maxDepth {
		ds.logger.Debug("Skipping URL: visited=%t, depth=%d >= maxDepth=%d", visited[baseURL], currentDepth, maxDepth)
		return
	}

	// Prevent unbounded visited map growth - check BEFORE adding to map
	// Limit to 5x MaxTotalLinks to account for directories (typically 20-50% of total URLs)
	// This prevents memory exhaustion on hosts with deep directory structures
	maxVisited := cfg.MaxTotalLinks * 5
	if maxVisited <= 0 {
		maxVisited = 50000 // Default: 50k visited URLs if MaxTotalLinks not set
	}
	if len(visited) >= maxVisited {
		ds.logger.Info("Host reached maximum visited URLs (%d >= %d), stopping recursion to prevent memory exhaustion", len(visited), maxVisited)
		if tracker != nil {
			tracker.RecordSkip(baseURL)
		}
		return
	}

	// Mark as visited after all checks pass
	visited[baseURL] = true

	ds.logger.Debug("Scanning depth %d: %s", currentDepth, baseURL)

	// Extract links from current level
	links := ds.extractLinks(baseURL, htmlContent)
	ds.logger.Debug("Found %d raw links at depth %d", len(links), currentDepth)

	// Apply per-directory link limit
	if cfg.MaxLinksPerDirectory > 0 && len(links) > cfg.MaxLinksPerDirectory {
		ds.logger.Info("Directory has %d links, limiting to %d", len(links), cfg.MaxLinksPerDirectory)
		links = links[:cfg.MaxLinksPerDirectory]
		ds.logger.Debug("After directory limit: %d links", len(links))
	}

	// Separate files from directories
	// Pre-allocate with estimated capacity based on typical directory structure
	// Typical ratio: 60-80% files, 20-40% directories
	files := make([]string, 0, len(links)/2)
	directories := make([]string, 0, len(links)/4)

	for _, link := range links {
		if ds.isDirectory(link) {
			directories = append(directories, link)
		} else {
			files = append(files, link)
		}
	}

	ds.logger.Debug("Link separation: %d files, %d directories", len(files), len(directories))

	// Add files to results and update atomic counter
	*allLinks = append(*allLinks, files...)
	newCount := atomic.AddInt64(&ds.totalLinksCount, int64(len(files)))
	ds.logger.Debug("Added %d files, total count now: %d", len(files), newCount)

	// Recurse into directories if we haven't reached max depth
	if currentDepth+1 < maxDepth {
		ds.logger.Debug("Planning to recurse into %d directories", len(directories))
		for i, dirURL := range directories {
			// Check if host became blocked during iteration
			if tracker != nil && tracker.IsBlocked(dirURL) {
				ds.logger.Debug("Host blocked during recursion, stopping: %s", dirURL)
				return
			}

			ds.logger.Debug("Recursing into directory %d/%d: %s", i+1, len(directories), dirURL)

			// Create host object for directory
			dirHost := api.Host{URL: dirURL}

			// Fetch directory content
			online, dirContent, err := client.CheckHostAndFetch(dirHost)
			if err != nil || !online {
				ds.logger.Debug("Failed to fetch directory %s: %v", dirURL, err)
				// Signal timeout/failure to worker - this will increment skip counter
				// and eventually block the host after MaxSkipsBeforeBlock threshold
				if tracker != nil {
					tracker.RecordSkip(dirURL)
					// Check if this skip caused the host to be blocked
					if tracker.IsBlocked(dirURL) {
						ds.logger.Debug("Host now blocked after skip, stopping recursion")
						return
					}
				}
				continue
			}

			// Check if it's a directory listing
			if ds.IsDirectoryListing(dirContent) {
				ds.logger.Debug("Directory confirmed, recursing: %s", dirURL)
				ds.scanRecursive(dirURL, dirContent, currentDepth+1, maxDepth, visited, allLinks, client, cfg, tracker)
			} else {
				ds.logger.Debug("Not a directory listing, skipping: %s", dirURL)
			}
		}
	} else {
		ds.logger.Debug("Max depth reached, not recursing further")
	}
}

// extractLinks extracts file links from HTML directory listing content
func (ds *DirectoryScanner) extractLinks(baseURLStr string, htmlContent string) []string {
	// Pre-allocate with reasonable capacity for typical directory listings
	// Most directories have 10-100 entries
	links := make([]string, 0, 50)

	// Parse the HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		ds.logger.Error("Failed to parse HTML: %v", err)
		return links
	}

	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		ds.logger.Error("Failed to parse base URL: %v", err)
		return links
	}

	// Find all links in the directory listing
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		// Skip parent directory links and navigation elements
		if href == "../" || href == ".." || href == "." || href == "/" {
			return
		}

		// Skip Apache directory listing sort links
		if strings.HasPrefix(href, "?C=") {
			return
		}

		// Skip other sort parameter links
		if strings.HasPrefix(href, "/?sort=") {
			return
		}

		// Resolve relative URLs to absolute URLs
		fileURL, err := url.Parse(href)
		if err != nil {
			ds.logger.Debug("Failed to parse URL: %s", href)
			return
		}

		absoluteURL := baseURL.ResolveReference(fileURL).String()
		links = append(links, absoluteURL)
		ds.logger.Debug("Found directory link: %s", absoluteURL)
	})

	if len(links) > 0 {
		ds.logger.Info("Extracted %d links from directory index at %s", len(links), baseURLStr)
	} else {
		ds.logger.Debug("Extracted 0 links from directory index at %s", baseURLStr)
	}
	return links
}

// IsDirectoryListing checks if the HTML content appears to be a directory listing
func (ds *DirectoryScanner) IsDirectoryListing(htmlContent string) bool {
	// Check for common directory listing indicators
	content := strings.ToLower(htmlContent)

	// Common directory listing patterns
	directoryIndicators := []string{
		"index of",
		"directory listing",
		"parent directory",
		"<title>index of",
		"apache/", // Apache directory listings
		"nginx/",  // Nginx directory listings
	}

	for _, indicator := range directoryIndicators {
		if strings.Contains(content, indicator) {
			ds.logger.Debug("Directory listing detected: found indicator '%s'", indicator)
			return true
		}
	}

	// Check for multiple file links (heuristic)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return false
	}

	linkCount := 0
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href != "../" && href != ".." && href != "." && href != "/" {
			linkCount++
		}
	})

	// If we have many file links, it's probably a directory
	if linkCount > 5 {
		ds.logger.Debug("Directory listing detected: found %d file links", linkCount)
		return true
	}

	return false
}

// isDirectory tries to determine if a URL points to a directory
func (ds *DirectoryScanner) isDirectory(url string) bool {
	// Validate input
	if url == "" {
		return false
	}

	// Simple heuristic: URLs ending with / are directories
	// Also check for common directory patterns
	if strings.HasSuffix(url, "/") {
		return true
	}

	// Check for URLs without file extensions (likely directories)
	// Safely extract the last part after the last slash
	index := strings.LastIndex(url, "/")
	var lastPart string
	if index == -1 {
		// No slash found - treat entire URL as last part
		lastPart = url
	} else {
		lastPart = url[index+1:]
	}

	// If last part has no extension and is not empty, likely a directory
	if !strings.Contains(lastPart, ".") && lastPart != "" {
		return true
	}

	return false
}
