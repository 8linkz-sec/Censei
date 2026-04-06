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
	logger     *logging.Logger
	permissive bool // If true, use additional heuristics for directory detection
}

// NewDirectoryScanner creates a new directory scanner instance.
// If permissive is true, additional heuristics are used to detect custom directory pages.
func NewDirectoryScanner(logger *logging.Logger, permissive bool) *DirectoryScanner {
	return &DirectoryScanner{
		logger:     logger,
		permissive: permissive,
	}
}

// ScanHost processes a host for directory listings and extracts file links
func (ds *DirectoryScanner) ScanHost(host api.Host, htmlContent string, cfg *config.Config) []string {
	ds.logger.Debug("Scanning directory listing for host: %s", host.URL)

	// Extract links from HTML content
	links := ds.extractLinks(host.URL, htmlContent)

	// Apply per-directory link limit
	if cfg.MaxLinksPerDirectory > 0 && len(links) > cfg.MaxLinksPerDirectory {
		ds.logger.Info("Directory has %d links, limiting to %d", len(links), cfg.MaxLinksPerDirectory)
		links = links[:cfg.MaxLinksPerDirectory]
	}

	// Apply total links limit
	if cfg.MaxTotalLinks > 0 && len(links) > cfg.MaxTotalLinks {
		ds.logger.Info("Links exceed total limit, limiting to %d", cfg.MaxTotalLinks)
		links = links[:cfg.MaxTotalLinks]
	}

	ds.logger.Debug("Directory scan found %d links for %s", len(links), host.URL)
	return links
}

// ScanHostRecursive performs recursive directory scanning with configurable limits
func (ds *DirectoryScanner) ScanHostRecursive(host api.Host, htmlContent string, maxDepth int, client HTTPClient, cfg *config.Config, tracker HostTracker) []string {
	if maxDepth <= 0 {
		return ds.ScanHost(host, htmlContent, cfg)
	}
	// Host-local counter to avoid race conditions when scanning multiple hosts in parallel
	var totalLinksCount int64
	visited := make(map[string]bool)
	allLinks := []string{}
	ds.scanRecursive(host.URL, htmlContent, 0, maxDepth, visited, &allLinks, client, cfg, tracker, &totalLinksCount)
	return allLinks
}

// scanRecursive performs the actual recursive scanning
func (ds *DirectoryScanner) scanRecursive(baseURL, htmlContent string, currentDepth, maxDepth int, visited map[string]bool, allLinks *[]string, client HTTPClient, cfg *config.Config, tracker HostTracker, totalLinksCount *int64) {
	// Check if host is already blocked before any processing
	if tracker != nil && tracker.IsBlocked(baseURL) {
		ds.logger.Debug("Host blocked, skipping recursion for: %s", baseURL)
		return
	}

	// Check total links limit with thread-safe counter
	currentCount := atomic.LoadInt64(totalLinksCount)
	ds.logger.Debug("Recursion check: current count=%d, limit=%d, depth=%d, URL=%s", currentCount, cfg.MaxTotalLinks, currentDepth, baseURL)

	if cfg.MaxTotalLinks > 0 && int(currentCount) >= cfg.MaxTotalLinks {
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
	files := make([]string, 0, len(links)/2)
	directories := make([]string, 0, len(links)/4)

	for _, link := range links {
		if strings.HasSuffix(link, "/") {
			// Definite directory (trailing slash)
			directories = append(directories, link)
		} else if ds.isDirectory(link) {
			// Ambiguous: no extension, no trailing slash (e.g., README, LICENSE, backup)
			// Add to both: capture as file AND try as directory
			files = append(files, link)
			directories = append(directories, link)
		} else {
			files = append(files, link)
		}
	}

	ds.logger.Debug("Link separation: %d files, %d directories", len(files), len(directories))

	// Enforce total links limit before appending
	if cfg.MaxTotalLinks > 0 {
		currentTotal := int(atomic.LoadInt64(totalLinksCount))
		remaining := cfg.MaxTotalLinks - currentTotal
		if remaining <= 0 {
			return
		}
		if remaining < len(files) {
			files = files[:remaining]
		}
	}

	// Add files to results and update atomic counter
	*allLinks = append(*allLinks, files...)
	newCount := atomic.AddInt64(totalLinksCount, int64(len(files)))
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

			// Re-check if host was blocked while we were fetching
			if tracker != nil && tracker.IsBlocked(dirURL) {
				ds.logger.Debug("Host became blocked during fetch, stopping recursion: %s", dirURL)
				return
			}

			// Check if it's a directory listing
			if ds.IsDirectoryListing(dirContent) {
				ds.logger.Debug("Directory confirmed, recursing: %s", dirURL)
				ds.scanRecursive(dirURL, dirContent, currentDepth+1, maxDepth, visited, allLinks, client, cfg, tracker, totalLinksCount)
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

		resolved := baseURL.ResolveReference(fileURL)

		// Only follow links on the same host to prevent scope creep
		// Compare Hostname() (without port) to avoid false mismatches on default ports
		if resolved.Hostname() != baseURL.Hostname() {
			ds.logger.Debug("Skipping external link: %s (host %s != %s)", href, resolved.Hostname(), baseURL.Hostname())
			return
		}

		absoluteURL := resolved.String()
		links = append(links, absoluteURL)
		ds.logger.Debug("Found directory link: %s", absoluteURL)
	})

	ds.logger.Debug("Extracted %d links from directory index at %s", len(links), baseURLStr)
	return links
}

// IsDirectoryListing checks if the HTML content appears to be a directory listing.
// In strict mode (default): returns true for strong indicators, weak indicators
// corroborated by link structure, or strong structural evidence (parent link + many
// file-extension links). In permissive mode: also detects <pre>/<table>-based pages
// with lower thresholds and pages with many file-extension links even without parent link.
func (ds *DirectoryScanner) IsDirectoryListing(htmlContent string) bool {
	content := strings.ToLower(htmlContent)

	// Strong directory listing indicators (title/header patterns from web servers)
	strongIndicators := []string{
		"<title>index of",
		"directory listing for",
		"directory listing of",
		"[to parent directory]", // IIS
	}

	for _, indicator := range strongIndicators {
		if strings.Contains(content, indicator) {
			ds.logger.Debug("Directory listing detected: found strong indicator '%s'", indicator)
			return true
		}
	}

	// Weaker indicators that need corroboration from link structure
	weakIndicators := []string{
		"index of",
		"parent directory",
		"apache/",
		"nginx/",
		"lighttpd/",
		"last modified", // Common column header in autoindex pages
	}

	hasWeakIndicator := false
	for _, indicator := range weakIndicators {
		if strings.Contains(content, indicator) {
			hasWeakIndicator = true
			ds.logger.Debug("Directory listing: found weak indicator '%s'", indicator)
			break
		}
	}

	// Always parse HTML and analyze link structure (no early bail-out)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return false
	}

	hasParentLink := false
	fileLinkCount := 0
	fileExtLinkCount := 0
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		if href == "../" || href == ".." {
			hasParentLink = true
			return
		}
		if href != "." && href != "/" && !strings.HasPrefix(href, "?C=") && !strings.HasPrefix(href, "/?sort=") {
			fileLinkCount++
			if looksLikeFile(href) {
				fileExtLinkCount++
			}
		}
	})

	// Weak indicator + parent link + file links → confirmed
	if hasWeakIndicator && hasParentLink && fileLinkCount > 2 {
		ds.logger.Debug("Directory listing confirmed: weak indicator + parent link + %d file links", fileLinkCount)
		return true
	}

	// Structural detection (both modes): parent link + many file-extension links
	// is strong evidence even without any text marker
	if hasParentLink && fileExtLinkCount > 10 {
		ds.logger.Debug("Directory listing detected (structural): parent link + %d file-extension links", fileExtLinkCount)
		return true
	}

	// Permissive mode: additional heuristics for custom/non-standard directory pages
	if ds.permissive {
		// <pre> block with parent link and some links → typical autoindex without title indicator
		hasPreBlock := strings.Contains(content, "<pre>")
		if hasPreBlock && hasParentLink && fileLinkCount > 2 {
			ds.logger.Debug("Directory listing detected (permissive): <pre> block + parent link + %d file links", fileLinkCount)
			return true
		}

		// Table layout with parent link and some links → custom directory page
		hasTable := strings.Contains(content, "<table")
		if hasTable && hasParentLink && fileLinkCount > 2 {
			ds.logger.Debug("Directory listing detected (permissive): <table> + parent link + %d file links", fileLinkCount)
			return true
		}

		// Many file-extension links even without parent link → likely a file listing
		if fileExtLinkCount > 10 {
			ds.logger.Debug("Directory listing detected (permissive): %d file-extension links (no parent link required)", fileExtLinkCount)
			return true
		}
	}

	return false
}

// looksLikeFile checks if a URL's last path segment has a file extension.
func looksLikeFile(href string) bool {
	// Strip query and fragment
	if idx := strings.IndexAny(href, "?#"); idx != -1 {
		href = href[:idx]
	}
	// Trailing slash → directory, not a file
	if strings.HasSuffix(href, "/") {
		return false
	}
	// Extract last path segment
	idx := strings.LastIndex(href, "/")
	lastPart := href
	if idx != -1 {
		lastPart = href[idx+1:]
	}
	return lastPart != "" && strings.Contains(lastPart, ".")
}

// isDirectory tries to determine if a URL points to a directory.
// Only trailing-slash URLs are treated as directories to avoid false positives
// with dynamic pages (e.g. /products?id=123&page=1).
func (ds *DirectoryScanner) isDirectory(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	// URLs with query parameters are not directories (dynamic/catalog pages)
	if strings.Contains(rawURL, "?") {
		return false
	}

	// URLs ending with / are directories
	if strings.HasSuffix(rawURL, "/") {
		return true
	}

	// Check if the last path segment has no file extension — but only for
	// path-only URLs (no query string, which we already excluded above).
	index := strings.LastIndex(rawURL, "/")
	var lastPart string
	if index == -1 {
		lastPart = rawURL
	} else {
		lastPart = rawURL[index+1:]
	}

	// If last part has no extension and is not empty, likely a directory
	if lastPart != "" && !strings.Contains(lastPart, ".") {
		return true
	}

	return false
}
