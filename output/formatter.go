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
	fmt.Fprintf(&summary, "Query: %s\n", query)
	fmt.Fprintf(&summary, "Start time: %s\n", FormatTimestamp(startTime))
	fmt.Fprintf(&summary, "End time: %s\n", FormatTimestamp(endTime))
	fmt.Fprintf(&summary, "Duration: %s\n", duration.Round(time.Second))
	fmt.Fprintf(&summary, "Total hosts found: %d\n", totalHosts)
	fmt.Fprintf(&summary, "Online hosts: %d\n", onlineHosts)
	fmt.Fprintf(&summary, "Total files found: %d\n", totalFiles)
	fmt.Fprintf(&summary, "Filtered files: %d\n", filteredFiles)
	fmt.Fprintf(&summary, "Applied filters: %s\n", filterStr)

	// Add download information to summary
	if downloadEnabled {
		summary.WriteString("File check enabled: Yes\n")
		if targetFileName != "" {
			fmt.Fprintf(&summary, "Target filename: %s\n", targetFileName)
		}
		fmt.Fprintf(&summary, "Files checked: %d\n", checkedFiles)
		fmt.Fprintf(&summary, "Binary files found: %d\n", binaryFilesFound)
		if binaryFilesFound > 0 {
			fmt.Fprintf(&summary, "Binary files list: %s\n", binaryOutputFile)
		}
	} else {
		summary.WriteString("File check enabled: No\n")
	}

	summary.WriteString("===========================\n")

	return summary.String()
}
