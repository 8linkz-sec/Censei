package crawler

import (
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"censei/api"
	"censei/config"
	"censei/filechecker"
	"censei/filter"
	"censei/logging"
	"censei/output"
	"censei/scanners"
)

// Worker coordinates parallel crawling of hosts
type Worker struct {
	client           *Client
	filter           *filter.Filter
	writer           *output.Writer
	logger           *logging.Logger
	fileChecker      *filechecker.FileChecker
	directoryScanner *scanners.DirectoryScanner
	queryConfig      *config.Query
	config           *config.Config
	maxWorkers       int
	checkEnabled     bool
	targetFileName   string
	skippedHosts     *sync.Map // Track hosts that hit limits
	blockedHosts     *sync.Map // In-memory cache of blocked hosts
	skipCounters     *sync.Map // Skip counters per base host
	stats            *ScanStats
	blocklist        *filter.Blocklist
	processedCount   int64 // Atomic counter for progress tracking
}

// ScanStats tracks statistics during scanning
type ScanStats struct {
	totalHosts       int
	onlineHosts      int
	totalFiles       int
	filteredFiles    int
	checkedFiles     int
	binaryFilesFound int
	writeErrors      int // Count of file write errors
	mu               sync.Mutex
}

// NewWorker creates a new worker for coordinating crawling
func NewWorker(
	client *Client,
	fileFilter *filter.Filter,
	writer *output.Writer,
	logger *logging.Logger,
	queryConfig *config.Query,
	config *config.Config,
	maxWorkers int,
) *Worker {
	// Initialize blocklist
	blocklist := filter.NewBlocklist(config.BlocklistFile, config.EnableBlocklist, logger)
	if err := blocklist.Load(); err != nil {
		logger.Error("Failed to load blocklist from %s: %v - continuing with empty blocklist (previously blocked hosts may be rescanned)", config.BlocklistFile, err)
	}

	return &Worker{
		client:           client,
		filter:           fileFilter,
		writer:           writer,
		logger:           logger,
		directoryScanner: scanners.NewDirectoryScanner(logger),
		queryConfig:      queryConfig,
		config:           config,
		maxWorkers:       maxWorkers,
		skippedHosts:     &sync.Map{},
		blockedHosts:     &sync.Map{},
		skipCounters:     &sync.Map{},
		stats:            &ScanStats{},
		blocklist:        blocklist,
	}
}

// SetFileChecker configures the file checker for the worker
func (w *Worker) SetFileChecker(checker *filechecker.FileChecker, enabled bool, targetFileName string) {
	w.fileChecker = checker
	w.checkEnabled = enabled
	w.targetFileName = targetFileName

	// Configure file checker if present
	if w.fileChecker != nil {
		w.fileChecker.Configure(enabled, targetFileName)
	}
}

// ProcessHosts crawls each host in parallel
func (w *Worker) ProcessHosts(hosts []api.Host) {
	w.logger.Info("Starting to process %d hosts", len(hosts))
	w.stats.totalHosts = len(hosts)

	// Create channels for parallel processing
	hostChan := make(chan api.Host, len(hosts))
	var wg sync.WaitGroup

	// Fill the channel with hosts
	for _, host := range hosts {
		hostChan <- host
	}
	close(hostChan)

	// Start workers
	for i := 0; i < w.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for host := range hostChan {
				w.processHost(host)
			}
		}()
	}

	// Wait for all workers to finish
	wg.Wait()

	// Close blocklist (triggers final save and shutdown of save worker)
	if err := w.blocklist.Close(); err != nil {
		w.logger.Error("Failed to close blocklist: %v", err)
	}

	w.logger.Info("Finished processing all hosts")
}

// processHost handles a single host's crawling and scanning
func (w *Worker) processHost(host api.Host) {
	// Increment processed counter and log progress periodically
	count := atomic.AddInt64(&w.processedCount, 1)
	if count%10 == 0 {
		w.logger.Info("Progress: %d/%d hosts processed", count, w.stats.totalHosts)
	}

	// Log the host we're processing - INFO level for user visibility
	w.logger.Info("Processing host: %s", host.URL)

	// Extract base host for blocking checks
	baseHost := w.extractBaseHost(host.URL)

	// Check if host is in persistent blocklist
	if w.blocklist.IsBlocked(baseHost) {
		w.logger.Debug("Skipping host - in persistent blocklist: %s", host.URL)
		return
	}

	// Check if entire base host is blocked
	if _, isBlocked := w.blockedHosts.Load(baseHost); isBlocked {
		w.logger.Debug("Skipping host - base host is blocked: %s", host.URL)
		return
	}

	// Check if this host should be skipped due to limits
	if _, shouldSkip := w.skippedHosts.Load(host.URL); shouldSkip {
		w.logger.Debug("Skipping host due to previous limit exceeded: %s", host.URL)
		return
	}

	// Check if host is online and fetch content
	online, htmlContent, err := w.client.CheckHostAndFetch(host)
	if err != nil {
		w.logger.Error("Error checking host %s: %v", host.URL, err)
		return
	}

	if !online {
		w.logger.Debug("Host is offline: %s", host.URL)
		return
	}

	// Update stats for online host
	w.stats.mu.Lock()
	w.stats.onlineHosts++
	w.stats.mu.Unlock()

	// Host is online, write to output
	if err := w.writer.WriteRawOutput(host.URL); err != nil {
		w.logger.Error("Failed to write output for host %s: %v", host.URL, err)
		w.stats.mu.Lock()
		w.stats.writeErrors++
		w.stats.mu.Unlock()
	}

	// Check if this is a targeted check mode
	targetedCheckMode := w.checkEnabled && w.fileChecker != nil && w.targetFileName != ""
	foundTargetFile := false

	// Try to check for a specific file if configured
	if targetedCheckMode {
		w.logger.Debug("Checking for specific file %s at %s", w.targetFileName, host.URL)

		found, contentType, err := w.fileChecker.CheckSpecificFile(host.URL, w.targetFileName)
		if err == nil && found {
			w.logger.Info("Found binary file '%s' at %s with Content-Type: %s",
				w.targetFileName, host.URL, contentType)
			binaryURL := fmt.Sprintf("%s/%s", host.URL, w.targetFileName)

			// Write to raw output
			if err := w.writer.WriteRawOutput(fmt.Sprintf("Found binary file: %s with Content-Type: %s", binaryURL, contentType)); err != nil {
				w.logger.Error("Failed to write raw output for binary file %s: %v", binaryURL, err)
				w.stats.mu.Lock()
				w.stats.writeErrors++
				w.stats.mu.Unlock()
			}

			// Write to binary output
			binaryLine := fmt.Sprintf("%s with Content-Type: %s", binaryURL, contentType)
			if err := w.writer.WriteBinaryOutput(binaryLine); err != nil {
				w.logger.Error("Failed to write binary output for %s: %v", binaryURL, err)
				w.stats.mu.Lock()
				w.stats.writeErrors++
				w.stats.mu.Unlock()
			}

			// Update check statistics
			w.stats.mu.Lock()
			w.stats.checkedFiles++
			w.stats.binaryFilesFound++
			w.stats.mu.Unlock()

			// Mark that we found the target file for this host
			foundTargetFile = true
		} else if err != nil {
			w.logger.Debug("Failed to check for specific file: %v", err)
		}
	}

	// Process directory content if not in targeted mode or if target file was not found
	if !targetedCheckMode || !foundTargetFile {
		w.processDirectoryContent(host, htmlContent)
	}
}

// processDirectoryContent handles directory listing scanning and file processing
func (w *Worker) processDirectoryContent(host api.Host, htmlContent string) {
	// Extract base host and check if blocked
	baseHost := w.extractBaseHost(host.URL)

	// Early check for blocked host
	if w.blocklist.IsBlocked(baseHost) {
		w.logger.Debug("Skipping directory processing - host in blocklist: %s", host.URL)
		return
	}

	if _, isBlocked := w.blockedHosts.Load(baseHost); isBlocked {
		w.logger.Debug("Skipping directory processing - host blocked: %s", host.URL)
		return
	}

	// Check if content is a directory listing
	if !w.directoryScanner.IsDirectoryListing(htmlContent) {
		w.logger.Debug("Host content is not a directory listing: %s", host.URL)
		return
	}

	// Create local deduplication map for this host
	// This map will be garbage collected after this function returns
	foundUrls := make(map[string]bool)

	var fileURLs []string

	// Check if recursive scanning is enabled
	recursive := w.queryConfig.Recursive == "yes"
	maxDepth := w.queryConfig.MaxDepth

	if recursive && maxDepth > 1 {
		w.logger.Info("Starting recursive scan with max-depth %d for %s", maxDepth, host.URL)
		// Pass worker as HostTracker - implements RecordSkip and IsBlocked
		fileURLs = w.directoryScanner.ScanHostRecursive(host, htmlContent, maxDepth, w.client, w.config, w)
	} else {
		w.logger.Info("Scanning directory listing: %s", host.URL)
		fileURLs = w.directoryScanner.ScanHost(host, htmlContent)
	}

	// Log found files for user visibility
	if len(fileURLs) > 0 {
		w.logger.Info("Found %d files at %s", len(fileURLs), host.URL)
	}

	// Process each found file with local deduplication map
	for _, fileURL := range fileURLs {
		w.processFoundFile(fileURL, foundUrls)
	}
}

// processFoundFile handles individual file processing including filtering and checking
func (w *Worker) processFoundFile(fileURL string, foundUrls map[string]bool) {
	// Check if we've already found this URL (local deduplication for this host)
	if foundUrls[fileURL] {
		w.logger.Debug("Skipping duplicate URL: %s", fileURL)
		return
	}
	foundUrls[fileURL] = true

	// Update stats for file found
	w.stats.mu.Lock()
	w.stats.totalFiles++
	w.stats.mu.Unlock()

	// Write to raw output
	if err := w.writer.WriteRawOutput("Found file: " + fileURL); err != nil {
		w.logger.Error("Failed to write raw output for file %s: %v", fileURL, err)
		w.stats.mu.Lock()
		w.stats.writeErrors++
		w.stats.mu.Unlock()
	}

	// Apply filters
	if w.filter.ShouldFilter(fileURL) {
		w.logger.Debug("File matched filter: %s", fileURL)

		// Update stats for filtered file
		w.stats.mu.Lock()
		w.stats.filteredFiles++
		w.stats.mu.Unlock()

		// Write to filtered output
		if err := w.writer.WriteFilteredOutput(fileURL); err != nil {
			w.logger.Error("Failed to write filtered output for %s: %v", fileURL, err)
			w.stats.mu.Lock()
			w.stats.writeErrors++
			w.stats.mu.Unlock()
		}

		// Check file content type if enabled
		if w.checkEnabled && w.fileChecker != nil && w.fileChecker.ShouldCheck(fileURL) {
			w.checkFileContent(fileURL)
		}
	}
}

// checkFileContent verifies if a file contains binary content
func (w *Worker) checkFileContent(fileURL string) {
	// Increment checked files counter (only once per check)
	w.stats.mu.Lock()
	w.stats.checkedFiles++
	w.stats.mu.Unlock()

	found, contentType, err := w.fileChecker.CheckFileURL(fileURL)
	if err == nil && found {
		w.logger.Info("Found binary file at %s with Content-Type: %s", fileURL, contentType)

		// Write to raw output
		if err := w.writer.WriteRawOutput(fmt.Sprintf("Found binary file: %s with Content-Type: %s", fileURL, contentType)); err != nil {
			w.logger.Error("Failed to write raw output for binary file %s: %v", fileURL, err)
			w.stats.mu.Lock()
			w.stats.writeErrors++
			w.stats.mu.Unlock()
		}

		// Write to binary output
		binaryLine := fmt.Sprintf("%s with Content-Type: %s", fileURL, contentType)
		if err := w.writer.WriteBinaryOutput(binaryLine); err != nil {
			w.logger.Error("Failed to write binary output for %s: %v", fileURL, err)
			w.stats.mu.Lock()
			w.stats.writeErrors++
			w.stats.mu.Unlock()
		}

		// Update binary files found statistic
		w.stats.mu.Lock()
		w.stats.binaryFilesFound++
		w.stats.mu.Unlock()
	} else if err != nil {
		w.logger.Debug("File check failed for %s: %v", fileURL, err)
	}
}

// GetStats returns the current scan statistics
func (w *Worker) GetStats() (int, int, int, int, int, int, int) {
	w.stats.mu.Lock()
	defer w.stats.mu.Unlock()
	return w.stats.totalHosts, w.stats.onlineHosts, w.stats.totalFiles,
		w.stats.filteredFiles, w.stats.checkedFiles, w.stats.binaryFilesFound, w.stats.writeErrors
}

// extractBaseHost extracts the base host (IP only) from a full URL
func (w *Worker) extractBaseHost(fullURL string) string {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		w.logger.Debug("Failed to parse URL %s: %v", fullURL, err)
		return fullURL // Fallback to full URL if parsing fails
	}

	// Extract hostname without port
	hostname := parsedURL.Hostname()
	if hostname == "" {
		w.logger.Debug("Failed to extract hostname from URL %s", fullURL)
		return parsedURL.Host // Fallback to host with port
	}

	w.logger.Debug("Extracted base host: %s from URL: %s", hostname, fullURL)
	return hostname
}

// RecordSkip implements scanners.HostTracker.RecordSkip
// Records a skip/timeout event for a URL and blocks the host if threshold is reached
func (w *Worker) RecordSkip(hostURL string) {
	baseHost := w.extractBaseHost(hostURL)
	w.logger.Debug("Skip triggered for: %s (base: %s)", hostURL, baseHost)

	// Increment skip counter for base host
	skipCountPtr, _ := w.skipCounters.LoadOrStore(baseHost, new(int64))
	newSkipCount := atomic.AddInt64(skipCountPtr.(*int64), 1)

	w.logger.Debug("Skip count for base host %s: %d", baseHost, newSkipCount)

	// Check if we should block entire base host
	if w.config.MaxSkipsBeforeBlock > 0 && newSkipCount >= int64(w.config.MaxSkipsBeforeBlock) {
		w.logger.Info("Blocking entire base host after %d skips: %s", newSkipCount, baseHost)
		w.blockedHosts.Store(baseHost, true)
		w.blocklist.AddHost(baseHost)
	}
}

// IsBlocked implements scanners.HostTracker.IsBlocked
// Checks if a host is blocked (either in persistent blocklist or in-memory)
func (w *Worker) IsBlocked(hostURL string) bool {
	baseHost := w.extractBaseHost(hostURL)

	// Check persistent blocklist
	if w.blocklist.IsBlocked(baseHost) {
		return true
	}

	// Check in-memory blocked hosts
	_, isBlocked := w.blockedHosts.Load(baseHost)
	return isBlocked
}
