package output

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"censei/logging"
)

// Writer handles output file operations with buffered I/O for performance
type Writer struct {
	rawFile      *os.File
	filteredFile *os.File
	binaryFile   *os.File
	rawWriter      *bufio.Writer
	filteredWriter *bufio.Writer
	binaryWriter   *bufio.Writer
	mu           sync.Mutex
	logger       *logging.Logger

	// Track seen binary URLs for deduplication (immediate write to file)
	seenBinaryURLs map[string]bool
	binaryFilePath string // path to binary_found.txt for post-scan sorting
}

// NewWriter creates a new output writer
func NewWriter(outputDir string, logger *logging.Logger) (*Writer, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create raw output file
	rawPath := filepath.Join(outputDir, "raw.txt")
	rawFile, err := os.Create(rawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw output file: %w", err)
	}

	// Create filtered output file
	filteredPath := filepath.Join(outputDir, "filtered.txt")
	filteredFile, err := os.Create(filteredPath)
	if err != nil {
		rawFile.Close()
		return nil, fmt.Errorf("failed to create filtered output file: %w", err)
	}

	// Create binary output file
	binaryPath := filepath.Join(outputDir, "binary_found.txt")
	binaryFile, err := os.Create(binaryPath)
	if err != nil {
		rawFile.Close()
		filteredFile.Close()
		return nil, fmt.Errorf("failed to create binary output file: %w", err)
	}

	logger.Info("Output files created: %s, %s and %s", rawPath, filteredPath, binaryPath)

	// Create buffered writers for 10-100x faster writes
	// Default buffer size: 4096 bytes (bufio.defaultBufSize)
	// For high-throughput scanning, use 64KB buffers
	const bufferSize = 64 * 1024 // 64 KB

	return &Writer{
		rawFile:        rawFile,
		filteredFile:   filteredFile,
		binaryFile:     binaryFile,
		rawWriter:      bufio.NewWriterSize(rawFile, bufferSize),
		filteredWriter: bufio.NewWriterSize(filteredFile, bufferSize),
		binaryWriter:   bufio.NewWriterSize(binaryFile, bufferSize),
		logger:         logger,
		seenBinaryURLs: make(map[string]bool),
		binaryFilePath: binaryPath,
	}, nil
}

// WriteRawOutput writes a line to the raw output file using buffered I/O
func (w *Writer) WriteRawOutput(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := fmt.Fprintln(w.rawWriter, line)
	if err != nil {
		w.logger.Error("Failed to write to raw output: %v", err)
		return err
	}

	return nil
}

// WriteFilteredOutput writes a line to the filtered output file using buffered I/O
func (w *Writer) WriteFilteredOutput(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := fmt.Fprintln(w.filteredWriter, line)
	if err != nil {
		w.logger.Error("Failed to write to filtered output: %v", err)
		return err
	}

	return nil
}

// WriteBinaryOutput writes binary findings immediately to file (one URL per line)
// Expected line format: "URL with Content-Type: CONTENT_TYPE"
func (w *Writer) WriteBinaryOutput(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Parse the line to extract URL
	// Format: "http://example.com/file.exe with Content-Type: application/x-msdownload"
	parts := strings.Split(line, " with Content-Type: ")
	if len(parts) != 2 {
		w.logger.Error("Invalid binary output format: %s", line)
		return fmt.Errorf("invalid binary output format")
	}

	fileURL := strings.TrimSpace(parts[0])

	// Check for duplicates
	if w.seenBinaryURLs[fileURL] {
		return nil
	}
	w.seenBinaryURLs[fileURL] = true

	// Write immediately to file
	_, err := fmt.Fprintln(w.binaryWriter, fileURL)
	if err != nil {
		w.logger.Error("Failed to write to binary output: %v", err)
		return err
	}

	// Flush immediately to ensure data is written to disk
	// This ensures data is not lost on abort
	if err := w.binaryWriter.Flush(); err != nil {
		w.logger.Error("Failed to flush binary output: %v", err)
		return err
	}

	return nil
}

// SortAndGroupBinaryFile reads the binary_found.txt file, groups URLs by host,
// sorts them alphabetically, and overwrites the file with the grouped format.
// This should be called after a successful scan completion.
func (w *Writer) SortAndGroupBinaryFile() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// First flush the buffer to ensure all data is written
	if w.binaryWriter != nil {
		if err := w.binaryWriter.Flush(); err != nil {
			return fmt.Errorf("failed to flush binary buffer: %w", err)
		}
	}

	// Read the file
	data, err := os.ReadFile(w.binaryFilePath)
	if err != nil {
		return fmt.Errorf("failed to read binary file: %w", err)
	}

	// Parse URLs and group by host
	lines := strings.Split(string(data), "\n")
	hostFindings := make(map[string][]string) // host -> list of URLs

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Extract host from URL
		parsedURL, err := url.Parse(line)
		if err != nil {
			w.logger.Error("Failed to parse URL during sorting: %s", line)
			continue
		}

		host := parsedURL.Scheme + "://" + parsedURL.Host
		hostFindings[host] = append(hostFindings[host], line)
	}

	if len(hostFindings) == 0 {
		return nil
	}

	// Sort hosts alphabetically
	hosts := make([]string, 0, len(hostFindings))
	for host := range hostFindings {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	// Rewrite the file with grouped format
	file, err := os.Create(w.binaryFilePath)
	if err != nil {
		return fmt.Errorf("failed to recreate binary file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, host := range hosts {
		urls := hostFindings[host]
		if len(urls) == 0 {
			continue
		}

		// Write host separator
		separator := fmt.Sprintf("\n=== %s (%d files) ===\n", host, len(urls))
		if _, err := writer.WriteString(separator); err != nil {
			return fmt.Errorf("failed to write host separator: %w", err)
		}

		// Write all URLs for this host
		for _, fileURL := range urls {
			if _, err := fmt.Fprintln(writer, fileURL); err != nil {
				return fmt.Errorf("failed to write URL: %w", err)
			}
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush sorted output: %w", err)
	}

	w.logger.Info("Binary findings sorted and grouped by %d hosts", len(hosts))
	return nil
}

// Close flushes buffers and closes all output files
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.logger.Info("Closing output files and flushing buffers")

	var rawFlushErr, filteredFlushErr, binaryFlushErr error
	var rawErr, filteredErr, binaryErr error

	// Flush all buffers first to ensure data is written
	if w.rawWriter != nil {
		rawFlushErr = w.rawWriter.Flush()
		if rawFlushErr != nil {
			w.logger.Error("Failed to flush raw output buffer: %v", rawFlushErr)
		}
		w.rawWriter = nil
	}

	if w.filteredWriter != nil {
		filteredFlushErr = w.filteredWriter.Flush()
		if filteredFlushErr != nil {
			w.logger.Error("Failed to flush filtered output buffer: %v", filteredFlushErr)
		}
		w.filteredWriter = nil
	}

	// Flush binary buffer (sorting happens separately via SortAndGroupBinaryFile)
	if w.binaryWriter != nil {
		binaryFlushErr = w.binaryWriter.Flush()
		if binaryFlushErr != nil {
			w.logger.Error("Failed to flush binary output buffer: %v", binaryFlushErr)
		}
		w.binaryWriter = nil
	}

	// Close files after flushing
	if w.rawFile != nil {
		rawErr = w.rawFile.Close()
		if rawErr != nil {
			w.logger.Error("Failed to close raw output file: %v", rawErr)
		}
		w.rawFile = nil
	}

	if w.filteredFile != nil {
		filteredErr = w.filteredFile.Close()
		if filteredErr != nil {
			w.logger.Error("Failed to close filtered output file: %v", filteredErr)
		}
		w.filteredFile = nil
	}

	if w.binaryFile != nil {
		binaryErr = w.binaryFile.Close()
		if binaryErr != nil {
			w.logger.Error("Failed to close binary output file: %v", binaryErr)
		}
		w.binaryFile = nil
	}

	// Return first error encountered
	if rawFlushErr != nil {
		return rawFlushErr
	}
	if filteredFlushErr != nil {
		return filteredFlushErr
	}
	if binaryFlushErr != nil {
		return binaryFlushErr
	}
	if rawErr != nil {
		return rawErr
	}
	if filteredErr != nil {
		return filteredErr
	}
	if binaryErr != nil {
		return binaryErr
	}

	w.logger.Info("Output files closed successfully")
	return nil
}
