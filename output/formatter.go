package output

import (
	"fmt"
	"strings"
	"time"
)

// FormatTimestamp formats a time for display in outputs
func FormatTimestamp(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// FormatSummary creates a summary of the scan results
func FormatSummary(
	query string,
	totalHosts int,
	onlineHosts int,
	totalFiles int,
	filteredFiles int,
	checkedFiles int,
	binaryFilesFound int,
	filters []string,
	startTime time.Time,
	endTime time.Time,
	downloadEnabled bool,
	targetFileName string,
	binaryOutputFile string,
) string {
	duration := endTime.Sub(startTime)

	var filterStr string
	if len(filters) > 0 {
		filterStr = strings.Join(filters, ", ")
	} else {
		filterStr = "None"
	}

	summary := strings.Builder{}
	summary.WriteString("=== Censei Scan Summary ===\n")
	summary.WriteString(fmt.Sprintf("Query: %s\n", query))
	summary.WriteString(fmt.Sprintf("Start time: %s\n", FormatTimestamp(startTime)))
	summary.WriteString(fmt.Sprintf("End time: %s\n", FormatTimestamp(endTime)))
	summary.WriteString(fmt.Sprintf("Duration: %s\n", duration.Round(time.Second)))
	summary.WriteString(fmt.Sprintf("Total hosts found: %d\n", totalHosts))
	summary.WriteString(fmt.Sprintf("Online hosts: %d\n", onlineHosts))
	summary.WriteString(fmt.Sprintf("Total files found: %d\n", totalFiles))
	summary.WriteString(fmt.Sprintf("Filtered files: %d\n", filteredFiles))
	summary.WriteString(fmt.Sprintf("Applied filters: %s\n", filterStr))

	// Add download information to summary
	if downloadEnabled {
		summary.WriteString("File check enabled: Yes\n")
		if targetFileName != "" {
			summary.WriteString(fmt.Sprintf("Target filename: %s\n", targetFileName))
		}
		summary.WriteString(fmt.Sprintf("Files checked: %d\n", checkedFiles))
		summary.WriteString(fmt.Sprintf("Binary files found: %d\n", binaryFilesFound))
		if binaryFilesFound > 0 {
			summary.WriteString(fmt.Sprintf("Binary files list: %s\n", binaryOutputFile))
		}
	} else {
		summary.WriteString("File check enabled: No\n")
	}

	summary.WriteString("===========================\n")

	return summary.String()
}
