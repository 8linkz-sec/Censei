package filter

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"censei/logging"
)

// Blocklist manages a persistent list of blocked hosts
type Blocklist struct {
	hosts      map[string]time.Time // hostname -> timestamp when blocked
	filePath   string
	enabled    bool
	logger     *logging.Logger
	mu         sync.RWMutex
	saveChan   chan struct{} // Signal channel for save requests
	stopChan   chan struct{} // Channel to stop the save worker
	saveWg     sync.WaitGroup
}

// NewBlocklist creates a new blocklist instance
func NewBlocklist(filePath string, enabled bool, logger *logging.Logger) *Blocklist {
	b := &Blocklist{
		hosts:    make(map[string]time.Time),
		filePath: filePath,
		enabled:  enabled,
		logger:   logger,
		saveChan: make(chan struct{}, 1), // Buffered channel to avoid blocking
		stopChan: make(chan struct{}),
	}

	// Start background save worker if blocklist is enabled
	if enabled {
		b.saveWg.Add(1)
		go b.saveWorker()
	}

	return b
}

// Load reads the blocklist from file if it exists
func (b *Blocklist) Load() error {
	if !b.enabled {
		b.logger.Debug("Blocklist is disabled, skipping load")
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if file exists
	if _, err := os.Stat(b.filePath); os.IsNotExist(err) {
		b.logger.Info("Blocklist file does not exist, starting with empty blocklist: %s", b.filePath)
		return nil
	}

	// Open and read file
	file, err := os.Open(b.filePath)
	if err != nil {
		return fmt.Errorf("failed to open blocklist file: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Parse line format: "hostname timestamp" or just "hostname"
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		hostname := parts[0]
		var timestamp time.Time

		if len(parts) >= 2 {
			// Try to parse timestamp
			if ts, err := time.Parse(time.RFC3339, parts[1]); err == nil {
				timestamp = ts
			} else {
				timestamp = time.Now() // Fallback to current time
			}
		} else {
			timestamp = time.Now()
		}

		b.hosts[hostname] = timestamp
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist file: %w", err)
	}

	b.logger.Info("Loaded %d blocked hosts from %s", count, b.filePath)
	return nil
}

// Save writes the current blocklist to file
func (b *Blocklist) Save() error {
	if !b.enabled {
		return nil
	}

	// Use read lock since we're only reading the map, not modifying it
	// File I/O happens outside the map access
	b.mu.RLock()

	// Copy data to avoid holding lock during I/O
	hostsCopy := make(map[string]time.Time, len(b.hosts))
	for hostname, timestamp := range b.hosts {
		hostsCopy[hostname] = timestamp
	}
	hostCount := len(b.hosts)

	b.mu.RUnlock()

	// Perform file I/O without holding any locks
	file, err := os.Create(b.filePath)
	if err != nil {
		return fmt.Errorf("failed to create blocklist file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Write header comment
	_, _ = fmt.Fprintf(file, "# Censei Blocklist - Generated on %s\n", time.Now().Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "# Format: hostname timestamp\n")
	_, _ = fmt.Fprintf(file, "# Hosts that exceeded skip limits and are permanently blocked\n\n")

	// Write hosts from the copy
	for hostname, timestamp := range hostsCopy {
		fmt.Fprintf(file, "%s %s\n", hostname, timestamp.Format(time.RFC3339))
	}

	b.logger.Info("Saved %d blocked hosts to %s", hostCount, b.filePath)
	return nil
}

// IsBlocked checks if a host is in the blocklist
func (b *Blocklist) IsBlocked(hostname string) bool {
	if !b.enabled {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	_, exists := b.hosts[hostname]
	return exists
}

// AddHost adds a host to the blocklist
func (b *Blocklist) AddHost(hostname string) {
	if !b.enabled {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.hosts[hostname]; !exists {
		b.hosts[hostname] = time.Now()
		b.logger.Info("Added host to blocklist: %s", hostname)

		// Signal the save worker to save (non-blocking)
		select {
		case b.saveChan <- struct{}{}:
			// Successfully signaled save
		default:
			// Channel already has a pending save signal, skip
		}
	}
}

// saveWorker runs in background and handles debounced saves
func (b *Blocklist) saveWorker() {
	defer b.saveWg.Done()

	saveTimer := time.NewTimer(0)
	<-saveTimer.C // Drain initial timer

	pendingSave := false

	for {
		select {
		case <-b.saveChan:
			// New save request received
			if !pendingSave {
				// Start debounce timer (wait 500ms for more changes)
				saveTimer.Reset(500 * time.Millisecond)
				pendingSave = true
			}
			// If already pending, just wait for the timer

		case <-saveTimer.C:
			// Timer expired, perform save
			if pendingSave {
				if err := b.Save(); err != nil {
					b.logger.Error("Failed to save blocklist: %v", err)
				}
				pendingSave = false
			}

		case <-b.stopChan:
			// Shutdown requested
			saveTimer.Stop()

			// Perform final save if there were pending changes
			if pendingSave {
				b.logger.Info("Performing final blocklist save before shutdown")
				if err := b.Save(); err != nil {
					b.logger.Error("Failed to save blocklist on shutdown: %v", err)
				}
			}
			return
		}
	}
}

// Close gracefully shuts down the blocklist and performs a final save
func (b *Blocklist) Close() error {
	if !b.enabled {
		return nil
	}

	// Signal the save worker to stop
	close(b.stopChan)

	// Wait for save worker to finish
	b.saveWg.Wait()

	b.logger.Debug("Blocklist closed successfully")
	return nil
}

// GetBlockedCount returns the number of blocked hosts
func (b *Blocklist) GetBlockedCount() int {
	if !b.enabled {
		return 0
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.hosts)
}

// GetBlockedHosts returns a copy of all blocked hosts with timestamps
func (b *Blocklist) GetBlockedHosts() map[string]time.Time {
	if !b.enabled {
		return make(map[string]time.Time)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]time.Time)
	for hostname, timestamp := range b.hosts {
		result[hostname] = timestamp
	}

	return result
}
