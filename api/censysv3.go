package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"censei/config"
	"censei/logging"

	censyssdkgo "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
)

// CensysV3Client handles interactions with the Censys Platform API v3
type CensysV3Client struct {
	sdk    *censyssdkgo.SDK
	Config *config.Config
	Logger *logging.Logger
}

// NewCensysV3Client creates a new client for Censys Platform API v3 interactions
func NewCensysV3Client(bearerToken string, cfg *config.Config, logger *logging.Logger) (*CensysV3Client, error) {
	// Build SDK options
	sdkOpts := []censyssdkgo.SDKOption{
		censyssdkgo.WithSecurity(bearerToken),
	}

	// Add organization ID if provided
	if cfg.OrganizationID != "" {
		logger.Debug("Using Organization ID: %s", cfg.OrganizationID)
		sdkOpts = append(sdkOpts, censyssdkgo.WithOrganizationID(cfg.OrganizationID))
	}

	// Initialize SDK
	sdk := censyssdkgo.New(sdkOpts...)

	return &CensysV3Client{
		sdk:    sdk,
		Config: cfg,
		Logger: logger,
	}, nil
}

// ExecuteQuery runs a Censys search query and saves results to a JSON file
func (c *CensysV3Client) ExecuteQuery(query, outputDir string) (string, error) {
	// Create output filename
	outputPath := filepath.Join(outputDir, "censys_results.json")

	c.Logger.Info("Executing Censys Platform API v3 query: %s", query)
	c.Logger.Debug("Output will be saved to: %s", outputPath)

	ctx := context.Background()

	// Prepare search request
	searchRequest := operations.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: components.SearchQueryInputBody{
			Query:    query,
			PageSize: censyssdkgo.Pointer[int64](100), // Max results per page
		},
	}

	// Pre-allocate slice with expected capacity to avoid reallocations
	// This prevents expensive memory copies as the slice grows
	expectedCapacity := c.Config.V3MaxResults
	if expectedCapacity <= 0 {
		expectedCapacity = 1000 // Default reasonable size
	}
	allResults := make([]components.SearchQueryHit, 0, expectedCapacity)
	var pageToken *string
	totalFetched := 0

	c.Logger.Debug("Starting paginated search with max results: %d", c.Config.V3MaxResults)

	// Paginate through results
	for {
		// Set page token if we have one from previous iteration
		if pageToken != nil {
			searchRequest.SearchQueryInputBody.PageToken = pageToken
			c.Logger.Debug("Fetching next page with token: %s", *pageToken)
		}

		// Execute search
		response, err := c.sdk.GlobalData.Search(ctx, searchRequest)
		if err != nil {
			c.Logger.Error("Platform API v3 search failed: %v", err)
			return "", fmt.Errorf("platform API v3 search error: %w", err)
		}

		// Check for API errors in response
		if response.ResponseEnvelopeSearchQueryResponse == nil {
			c.Logger.Error("Empty response from Platform API v3")
			return "", fmt.Errorf("empty response from platform API v3")
		}

		// Add results from this page
		if response.ResponseEnvelopeSearchQueryResponse.Result != nil &&
			response.ResponseEnvelopeSearchQueryResponse.Result.Hits != nil {

			hits := response.ResponseEnvelopeSearchQueryResponse.Result.Hits

			// Enforce max results limit before appending
			remaining := c.Config.V3MaxResults - totalFetched
			if remaining < len(hits) {
				hits = hits[:remaining]
			}

			allResults = append(allResults, hits...)
			totalFetched += len(hits)
			c.Logger.Debug("Fetched %d results (total: %d)", len(hits), totalFetched)
		}

		// Check if we've reached the limit
		if totalFetched >= c.Config.V3MaxResults {
			c.Logger.Info("Reached configured max results limit: %d", c.Config.V3MaxResults)
			break
		}

		// Check if there are more pages
		if response.ResponseEnvelopeSearchQueryResponse.Result == nil ||
			response.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken == "" {
			c.Logger.Debug("No more pages available")
			break
		}

		// Get token for next page
		nextToken := response.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken
		pageToken = &nextToken
	}

	c.Logger.Info("Platform API v3 query completed successfully, fetched %d results", totalFetched)

	// Save results to JSON file
	c.Logger.Debug("Saving results to file: %s", outputPath)
	file, err := os.Create(outputPath)
	if err != nil {
		c.Logger.Error("Failed to create output file: %v", err)
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(allResults); err != nil {
		c.Logger.Error("Failed to encode results to JSON: %v", err)
		return "", fmt.Errorf("failed to encode results to JSON: %w", err)
	}

	// Verify the output file
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		c.Logger.Error("Error getting file info: %v", err)
	} else {
		c.Logger.Debug("Output file size: %d bytes", fileInfo.Size())
	}

	return outputPath, nil
}

// ExtractHostsFromResults processes Censys JSON results and extracts hosts for crawling
func (c *CensysV3Client) ExtractHostsFromResults(jsonPath string) ([]Host, error) {
	c.Logger.Info("Extracting hosts from Censys Platform API v3 results")

	// Read the JSON file
	c.Logger.Debug("Reading JSON file: %s", jsonPath)
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		c.Logger.Error("Failed to read results file: %v", err)
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	c.Logger.Debug("Read %d bytes from JSON file", len(data))

	// Parse the JSON as generic maps since the structure can vary
	var results []map[string]interface{}
	c.Logger.Debug("Attempting to parse JSON")
	err = json.Unmarshal(data, &results)
	if err != nil {
		c.Logger.Error("Failed to parse results JSON: %v", err)
		return nil, fmt.Errorf("failed to parse results JSON: %w", err)
	}

	c.Logger.Debug("Successfully parsed JSON with %d results", len(results))

	// Extract hosts - pre-allocate with estimated capacity
	// Estimate: results × average services/endpoints per result (typically 2-5)
	estimatedHosts := len(results) * 3
	hosts := make([]Host, 0, estimatedHosts)

	for i, result := range results {
		// Navigate to host_v1 → resource → ip
		hostV1Interface, ok := result["host_v1"]
		if !ok {
			c.Logger.Debug("Result #%d has no host_v1, skipping", i)
			continue
		}

		hostV1Map, ok := hostV1Interface.(map[string]interface{})
		if !ok {
			c.Logger.Debug("Result #%d host_v1 is not a map, skipping", i)
			continue
		}

		resourceInterface, ok := hostV1Map["resource"]
		if !ok {
			c.Logger.Debug("Result #%d has no resource in host_v1, skipping", i)
			continue
		}

		resourceMap, ok := resourceInterface.(map[string]interface{})
		if !ok {
			c.Logger.Debug("Result #%d resource is not a map, skipping", i)
			continue
		}

		// Extract IP
		ipInterface, ok := resourceMap["ip"]
		if !ok {
			c.Logger.Debug("Result #%d has no IP in resource, skipping", i)
			continue
		}

		ip, ok := ipInterface.(string)
		if !ok {
			c.Logger.Debug("Result #%d IP is not a string, skipping", i)
			continue
		}

		c.Logger.Debug("Processing result #%d: IP=%s", i, ip)

		// Debug: Check what keys exist in hostV1Map
		if i == 0 {
			c.Logger.Debug("=== DEBUG: Structure of first result ===")
			c.Logger.Debug("Keys in hostV1Map:")
			for key := range hostV1Map {
				c.Logger.Debug("  - %s (type: %T)", key, hostV1Map[key])
			}

			c.Logger.Debug("Keys in resourceMap:")
			for key := range resourceMap {
				c.Logger.Debug("  - %s (type: %T)", key, resourceMap[key])
			}

			// Check if services exists and what's inside
			if servicesInterface, ok := resourceMap["services"]; ok {
				c.Logger.Debug("Services found in resource, type: %T", servicesInterface)
				if servicesMap, ok := servicesInterface.(map[string]interface{}); ok {
					c.Logger.Debug("Keys in services map:")
					for key := range servicesMap {
						c.Logger.Debug("  - %s (type: %T)", key, servicesMap[key])
					}
				}
			}
			c.Logger.Debug("=== END DEBUG ===")
		}

		// Determine base address (hostname or IP)
		baseAddress := ip

		// Try to get DNS name from resource → dns → reverse_dns → names
		if dnsInterface, ok := resourceMap["dns"].(map[string]interface{}); ok {
			if rdnsInterface, ok := dnsInterface["reverse_dns"].(map[string]interface{}); ok {
				if namesInterface, ok := rdnsInterface["names"].([]interface{}); ok && len(namesInterface) > 0 {
					if name, ok := namesInterface[0].(string); ok {
						baseAddress = name
						c.Logger.Debug("Using DNS name for host: %s", baseAddress)
					}
				}
			}
		}

		// Process services - it's an array directly in resource → services
		servicesInterface, ok := resourceMap["services"]
		if !ok {
			c.Logger.Debug("No 'services' key found in resource for result #%d", i)
			continue
		}
		c.Logger.Debug("Found services in resource for result #%d", i)

		services, ok := servicesInterface.([]interface{})
		if !ok {
			c.Logger.Debug("Services is not an array for result #%d, it's type: %T", i, servicesInterface)
			continue
		}
		c.Logger.Debug("Services array has %d entries for result #%d", len(services), i)

		// Also check matched_services if available
		var matchedServices []interface{}
		if matchedInterface, ok := hostV1Map["matched_services"]; ok {
			if matched, ok := matchedInterface.([]interface{}); ok && len(matched) > 0 {
				matchedServices = matched
				c.Logger.Debug("Using %d matched_services instead of all services", len(matchedServices))
			}
		}

		// Use matched services if available, otherwise use all services
		servicesToProcess := services
		if len(matchedServices) > 0 {
			servicesToProcess = matchedServices
		}

		for j, serviceInterface := range servicesToProcess {
			service, ok := serviceInterface.(map[string]interface{})
			if !ok {
				c.Logger.Debug("Service #%d is not a map, skipping", j)
				continue
			}

			// Debug first service structure
			if i == 0 && j == 0 {
				c.Logger.Debug("=== DEBUG: First service structure ===")
				c.Logger.Debug("Keys in service:")
				for key := range service {
					c.Logger.Debug("  - %s (type: %T)", key, service[key])
				}
				c.Logger.Debug("=== END DEBUG ===")
			}

			// Check if this service has endpoints
			endpointsInterface, hasEndpoints := service["endpoints"]
			if hasEndpoints {
				c.Logger.Debug("Service #%d has endpoints field", j)
				endpoints, ok := endpointsInterface.([]interface{})
				if !ok {
					c.Logger.Debug("Endpoints is not an array, type: %T", endpointsInterface)
					continue
				}

				c.Logger.Debug("Processing %d endpoints from service #%d", len(endpoints), j)
				for k, endpointInterface := range endpoints {
					endpoint, ok := endpointInterface.(map[string]interface{})
					if !ok {
						continue
					}

					// Get port from endpoint
					portInterface, ok := endpoint["port"]
					if !ok {
						c.Logger.Debug("Endpoint #%d has no port, skipping", k)
						continue
					}

					var port int
					switch v := portInterface.(type) {
					case float64:
						port = int(v)
					case int:
						port = v
					default:
						c.Logger.Debug("Port is not a number, type: %T", v)
						continue
					}

					// Get transport protocol
					transportProtocol, _ := endpoint["transport_protocol"].(string)
					if transportProtocol != "tcp" && transportProtocol != "" {
						c.Logger.Debug("Skipping non-TCP endpoint: %s", transportProtocol)
						continue
					}

					// Determine protocol based on port
					protocol := "http"
					if port == 443 {
						protocol = "https"
					}

					// Format address for URL (add brackets for IPv6)
					addressForURL := baseAddress
					if isIPv6(baseAddress) {
						addressForURL = fmt.Sprintf("[%s]", baseAddress)
					}

					host := Host{
						BaseAddress: baseAddress,
						IP:          ip,
						Port:        port,
						Protocol:    protocol,
						URL:         fmt.Sprintf("%s://%s:%d", protocol, addressForURL, port),
					}

					// Special case for standard ports
					switch port {
					case 443:
						host.URL = fmt.Sprintf("https://%s", addressForURL)
					case 80:
						host.URL = fmt.Sprintf("http://%s", addressForURL)
					}

					endpointType, _ := endpoint["endpoint_type"].(string)
					c.Logger.Debug("Created host #%d.%d.%d: %s (endpoint_type: %s)", i, j, k, host.URL, endpointType)
					hosts = append(hosts, host)
				}
			} else {
				// V3 API format: service has port and protocol directly
				c.Logger.Debug("Service #%d has no endpoints, checking for direct port", j)

				// Check protocol field (v3 API uses "protocol")
				protocol, ok := service["protocol"].(string)
				if !ok || (protocol != "HTTP" && protocol != "HTTPS") {
					c.Logger.Debug("Service is not HTTP/HTTPS - protocol: %s", protocol)
					continue
				}

				// Get port from service
				portInterface, ok := service["port"]
				if !ok {
					c.Logger.Debug("Service has no port field")
					continue
				}

				var port int
				switch v := portInterface.(type) {
				case float64:
					port = int(v)
				case int:
					port = v
				default:
					c.Logger.Debug("Port is not a number, type: %T", v)
					continue
				}

				httpProtocol := "http"
				if protocol == "HTTPS" || port == 443 {
					httpProtocol = "https"
				}

				// Format address for URL (add brackets for IPv6)
				addressForURL := baseAddress
				if isIPv6(baseAddress) {
					addressForURL = fmt.Sprintf("[%s]", baseAddress)
				}

				host := Host{
					BaseAddress: baseAddress,
					IP:          ip,
					Port:        port,
					Protocol:    httpProtocol,
					URL:         fmt.Sprintf("%s://%s:%d", httpProtocol, addressForURL, port),
				}

				// Special case for standard ports
				switch port {
				case 443:
					host.URL = fmt.Sprintf("https://%s", addressForURL)
				case 80:
					host.URL = fmt.Sprintf("http://%s", addressForURL)
				}

				c.Logger.Debug("Created host #%d.%d: %s (protocol: %s)", i, j, host.URL, protocol)
				hosts = append(hosts, host)
			}
		}
	}

	c.Logger.Debug("Extracted %d hosts from Censys Platform API v3 results", len(hosts))
	return hosts, nil
}
