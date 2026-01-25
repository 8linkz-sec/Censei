package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"censei/api"
	"censei/cli"
	"censei/config"
	"censei/crawler"
	"censei/filechecker"
	"censei/filter"
	"censei/logging"
	"censei/output"
)

// checkCensysCLI checks if the censys-cli tool is available
func checkCensysCLI(logger *logging.Logger) bool {
	logger.Info("Checking if censys-cli is installed...")

	cmd := exec.Command("censys", "--version")
	err := cmd.Run()

	if err != nil {
		logger.Error("censys-cli is not available or not in PATH: %v", err)
		fmt.Println("ERROR: The censys-cli tool was not found. Please install it with:")
		fmt.Println("pip install censys-command-line")
		fmt.Println("or visit https://github.com/censys/censys-command-line for installation instructions.")
		return false
	}

	logger.Info("censys-cli is installed and available")
	return true
}

func main() {
	// Parse command line arguments
	configPath := flag.String("config", "./config.json", "Path to config file")
	queriesPath := flag.String("queries", "", "Path to queries file (overrides default)")
	filterStr := flag.String("filter", "", "Custom file extensions to filter (comma-separated, e.g. .pdf,.exe)")
	queryStr := flag.String("query", "", "Run specific query directly")
	outputPath := flag.String("output", "", "Override output directory")
	logLevel := flag.String("log-level", "", "Override log level (DEBUG, INFO, ERROR)")
	checkFlag := flag.Bool("check", false, "Enable targeted file checking mode - skips HTML processing and link extraction, directly checks hosts for specific binary files")
	targetFile := flag.String("target-file", "", "Specific file to check for on hosts")
	recursiveFlag := flag.Bool("recursive", false, "Enable recursive directory scanning")
	maxDepthFlag := flag.Int("max-depth", 1, "Maximum depth for recursive scanning")
	legacyFlag := flag.Bool("legacy", false, "Use legacy CLI-based Censys API instead of Platform API v3")
	flag.Parse()

	// Initialize logging system
	logger := logging.NewLogger()

	// Load configuration first to get query file paths
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Determine which queries file to use
	var finalQueriesPath string
	if *queriesPath != "" {
		// User explicitly specified a queries file
		finalQueriesPath = *queriesPath
	} else if *legacyFlag {
		// Legacy mode: use queries_file_legacy from config or default
		if cfg.QueriesFileLegacy != "" {
			finalQueriesPath = cfg.QueriesFileLegacy
		} else {
			finalQueriesPath = "./legacy_queries.json"
		}
		logger.Info("Legacy mode enabled - using %s", finalQueriesPath)
	} else {
		// Default: use queries_file_v3 from config or default
		if cfg.QueriesFileV3 != "" {
			finalQueriesPath = cfg.QueriesFileV3
		} else {
			finalQueriesPath = "./queriesv3.json"
		}
		logger.Info("Platform API v3 mode - using %s", finalQueriesPath)
	}

	// Check if censys-cli is installed (only required for legacy mode)
	if *legacyFlag {
		if !checkCensysCLI(logger) {
			os.Exit(1)
		}
	}

	// Validate mode-specific configuration
	if *legacyFlag {
		if err := config.ValidateForLegacy(cfg); err != nil {
			logger.Error("Legacy mode configuration validation failed: %v", err)
			os.Exit(1)
		}
	} else {
		if err := config.ValidateForV3(cfg); err != nil {
			logger.Error("Platform API v3 configuration validation failed: %v", err)
			os.Exit(1)
		}
	}

	// Override config with command line arguments if provided
	if *outputPath != "" {
		cfg.OutputDir = *outputPath
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	// Apply log level from config
	logger.SetLevel(cfg.LogLevel)
	logger.SetOutputFile(cfg.LogFile)

	// Initialize the application
	logger.Info("Censei Scanner starting up...")

	// Load queries configuration with helpful error messages
	queries, err := config.LoadQueries(finalQueriesPath)
	if err != nil {
		logger.Error("Failed to load queries from %s: %v", finalQueriesPath, err)

		// Provide helpful error messages based on the context
		if *queriesPath != "" {
			// User specified a custom queries file
			fmt.Printf("\nERROR: Custom queries file '%s' not found or invalid.\n", *queriesPath)
			fmt.Println("Please check the file path and ensure it contains valid JSON.")
		} else if *legacyFlag {
			// Legacy mode but legacy_queries.json is missing
			fmt.Println("\nERROR: legacy_queries.json not found.")
			fmt.Println("Please create this file or use -queries to specify a custom queries file.")
			fmt.Println("See README for query file examples.")
		} else {
			// Platform API mode but queriesv3.json is missing
			fmt.Println("\nERROR: queriesv3.json not found.")
			fmt.Println("Please create this file or use -queries to specify a custom queries file.")
			fmt.Println("For legacy CLI mode, use the -legacy flag with legacy_queries.json.")
			fmt.Println("See README for query file examples.")
		}

		os.Exit(1)
	}

	// If a direct query is provided, run it
	if *queryStr != "" {
		logger.Info("Running direct query: %s", *queryStr)

		// Create query config from command line parameters
		var filters []string
		if *filterStr != "" {
			filters = cli.ParseFilters(*filterStr)
		}

		// Create query object for command line query
		queryConfig := &config.Query{
			Name:           "Command Line Query",
			Query:          *queryStr,
			Filters:        filters,
			Check:          *checkFlag,
			TargetFileName: *targetFile,
			Recursive:      boolToYesNo(*recursiveFlag),
			MaxDepth:       *maxDepthFlag,
		}

		runQueryConfig(cfg, queryConfig, logger, *legacyFlag)
	} else {
		// Start interactive mode
		selectedQuery, selectedFilters, checkEnabled, targetFileName := cli.ShowMenuWithCheck(
			queries, *filterStr, *checkFlag, *targetFile, *legacyFlag)
		if selectedQuery == "" {
			logger.Error("No query selected, exiting")
			os.Exit(0)
		}

		// Find the selected query config
		var queryConfig *config.Query
		for _, q := range queries {
			if q.Query == selectedQuery {
				queryConfig = &q
				// Override with command line parameters if provided
				if *filterStr != "" {
					queryConfig.Filters = selectedFilters
				}
				if *checkFlag {
					queryConfig.Check = checkEnabled
				}
				if *targetFile != "" {
					queryConfig.TargetFileName = targetFileName
				}
				if *recursiveFlag {
					queryConfig.Recursive = "yes"
				}
				if *maxDepthFlag > 1 {
					queryConfig.MaxDepth = *maxDepthFlag
				}
				break
			}
		}

		// If no predefined query found, create custom query
		if queryConfig == nil {
			queryConfig = &config.Query{
				Name:           "Custom Query",
				Query:          selectedQuery,
				Filters:        selectedFilters,
				Check:          checkEnabled,
				TargetFileName: targetFileName,
				Recursive:      boolToYesNo(*recursiveFlag),
				MaxDepth:       *maxDepthFlag,
			}
		}

		runQueryConfig(cfg, queryConfig, logger, *legacyFlag)
	}
}

// boolToYesNo converts a boolean to "yes"/"no" string
func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// runQueryConfig runs a query using a complete Query configuration object
func runQueryConfig(cfg *config.Config, queryConfig *config.Query, logger *logging.Logger, useLegacy bool) {
	startTime := time.Now()

	// Initialize statistics
	stats := struct {
		totalHosts       int
		onlineHosts      int
		totalFiles       int
		filteredFiles    int
		checkedFiles     int
		binaryFilesFound int
		writeErrors      int
	}{
		totalHosts:       0,
		onlineHosts:      0,
		totalFiles:       0,
		filteredFiles:    0,
		checkedFiles:     0,
		binaryFilesFound: 0,
		writeErrors:      0,
	}

	// Log query configuration
	logger.Info("Query: %s", queryConfig.Query)
	logger.Info("Recursive: %s", queryConfig.Recursive)
	if queryConfig.Recursive == "yes" {
		logger.Info("Max Depth: %d", queryConfig.MaxDepth)
	}

	// Log API mode
	if useLegacy {
		logger.Info("Using Legacy CLI-based API")
	} else {
		logger.Info("Using Platform API v3")
	}

	var hosts []api.Host
	var err error

	if useLegacy {
		// Legacy mode: Use CLI-based Censys client
		censysClient := api.NewCensysClient(cfg.APIKey, cfg.APISecret, cfg, logger)

		// Execute Censys query
		jsonPath, err := censysClient.ExecuteQuery(queryConfig.Query, cfg.OutputDir)
		if err != nil {
			logger.Error("Failed to execute Censys query: %v", err)
			os.Exit(1)
		}

		// Extract hosts from results
		hosts, err = censysClient.ExtractHostsFromResults(jsonPath)
		if err != nil {
			logger.Error("Failed to extract hosts from results: %v", err)
			os.Exit(1)
		}
	} else {
		// Platform API v3 mode
		censysV3Client, err := api.NewCensysV3Client(cfg.BearerToken, cfg, logger)
		if err != nil {
			logger.Error("Failed to initialize Platform API v3 client: %v", err)
			os.Exit(1)
		}

		// Execute Censys query
		jsonPath, err := censysV3Client.ExecuteQuery(queryConfig.Query, cfg.OutputDir)
		if err != nil {
			logger.Error("Failed to execute Platform API v3 query: %v", err)
			os.Exit(1)
		}

		// Extract hosts from results
		hosts, err = censysV3Client.ExtractHostsFromResults(jsonPath)
		if err != nil {
			logger.Error("Failed to extract hosts from Platform API v3 results: %v", err)
			os.Exit(1)
		}
	}

	logger.Info("Extracted %d hosts from Censys results", len(hosts))

	// Initialize output writer
	writer, err := output.NewWriter(cfg.OutputDir, logger)
	if err != nil {
		logger.Error("Failed to initialize output writer: %v", err)
		os.Exit(1)
	}
	defer writer.Close()

	// Initialize filter
	fileFilter := filter.NewFilter(queryConfig.Filters, logger)
	logger.Info("Using filters: %v", fileFilter.GetFilterExtensions())

	// Initialize crawler components
	client := crawler.NewClient(cfg.HTTPTimeoutSeconds, logger)

	// Initialize worker with query config
	worker := crawler.NewWorker(
		client,
		fileFilter,
		writer,
		logger,
		queryConfig,
		cfg,
		cfg.MaxConcurrentRequests,
	)

	// Initialize file checker if enabled
	if queryConfig.Check {
		logger.Info("File checking functionality enabled, looking for binary files")
		if queryConfig.TargetFileName != "" {
			logger.Info("Target filename: %s", queryConfig.TargetFileName)
		}

		// Create file checker
		fileChecker := filechecker.NewFileChecker(cfg.HTTPTimeoutSeconds, logger)

		// Set file checker in worker
		worker.SetFileChecker(fileChecker, true, queryConfig.TargetFileName)
	}

	// Process hosts
	worker.ProcessHosts(hosts)

	// Sort and group binary findings after successful scan
	if err := writer.SortAndGroupBinaryFile(); err != nil {
		logger.Error("Could not sort binary findings: %v", err)
		// Not fatal - unsorted file is better than none
	}

	// Get updated statistics
	stats.totalHosts, stats.onlineHosts, stats.totalFiles, stats.filteredFiles, stats.checkedFiles, stats.binaryFilesFound, stats.writeErrors = worker.GetStats()

	// Generate and write summary
	endTime := time.Now()
	summary := output.FormatSummary(
		queryConfig.Query,
		stats.totalHosts,
		stats.onlineHosts,
		stats.totalFiles,
		stats.filteredFiles,
		stats.checkedFiles,
		stats.binaryFilesFound,
		fileFilter.GetFilterExtensions(),
		startTime,
		endTime,
		queryConfig.Check,
		queryConfig.TargetFileName,
		cfg.BinaryOutputFile,
	)

	logger.Info("\n%s", summary)
	writer.WriteRawOutput("\n" + summary)

	// Check for write errors and warn user
	if stats.writeErrors > 0 {
		warningMsg := fmt.Sprintf("\n⚠️  WARNING: %d file write errors occurred during execution!", stats.writeErrors)
		warningMsg += "\n   Some results may not have been saved to output files."
		warningMsg += "\n   Check the logs above for details about which files failed."
		warningMsg += "\n   Common causes: disk full, permission errors, or network issues."
		logger.Error("%s", warningMsg)
		// Don't fail on write error to raw output here - best effort
		writer.WriteRawOutput(warningMsg)
	}

	logger.Info("Query execution complete")
}
