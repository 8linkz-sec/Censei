# Censei

**Censei** is a powerful tool for identifying and analyzing open directories on the internet using the Censys API. The focus is on efficiency, adaptability, and detailed output.

## Project Description

### What is Censei?

Censei (pronounced like "Sensei") is a command-line tool written in Go that uses the Censys API to search for suspicious open directories. It automates the process of identifying hosts, checking their availability, crawling directory indexes, and filtering files according to specific criteria.

### Key Features

- Efficient search for open directories with Censys
- Automatic host availability checking
- Intelligent crawling of directory indexes
- Recursive directory scanning with configurable depth
- Flexible filtering by file extensions
- Parallel processing for higher speed
- Smart host blocking with persistent blocklist
- Performance limits to prevent resource exhaustion
- Detailed outputs (raw and filtered)
- Configurable logging
- Interactive and automated modes
- Special verification mode for binary files without HTML processing
- File content verification for binary detection
- Target-specific file search functionality

### Use Cases

- Security research
- Identification of exposed files
- Open-Source Intelligence (OSINT)
- Security audits
- Automated scanning processes

## Installation

### Prerequisites

- Go 1.24 or higher
- **Censys subscription** for API access (important: This tool does not work without a valid Censys subscription and API credentials!)
- **For Platform API v3 mode (default):** Censys API credentials (API ID and Secret)
- **For Legacy mode (optional):** Censys CLI ([Installation via pip](https://github.com/censys/censys-command-line))

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/8linkz/censei.git
   cd censei
   ```

2. Compile the program:
   ```bash
   go build
   ```

3. (Optional) Install Censys CLI for legacy mode:
   ```bash
   pip install censys-command-line
   ```

4. Verify installation:
   ```bash
   ./censei --help
   ```

### Setting up configuration files

Censei supports two API modes:

- **Platform API v3 (default):** Uses the modern Censys Platform API with bearer token authentication
- **Legacy mode:** Uses the older Censys CLI tool (activated with `--legacy` flag)

Create the configuration files:

1. **config.json** - Basic settings:
   ```json
   {
     "api_key": "your-censys-api-key",
     "api_secret": "your-censys-api-secret",
     "bearer_token": "your-platform-api-bearer-token",
     "organization_id": "",
     "v3_max_results": 500,
     "legacy_pages": 25,
     "legacy_per_page": 100,
     "legacy_index_type": "hosts",
     "legacy_sort_order": "DESCENDING",
     "legacy_virtual_hosts": "INCLUDE",
     "queries_file_v3": "./ressources/queriesv3.json",
     "queries_file_legacy": "./ressources/legacy_queries.json",
     "output_dir": "./scan_output",
     "binary_output_file": "./scan_output/binary_found.txt",
     "http_timeout_seconds": 5,
     "max_concurrent_requests": 10,
     "log_level": "INFO",
     "log_file": "./censei.log",
     "max_links_per_directory": 500,
     "max_total_links": 10000,
     "max_skips_before_block": 5,
     "enable_blocklist": false,
     "blocklist_file": "./blocklist.txt"
   }
   ```

   > **Note**: The `queries_file_v3` and `queries_file_legacy` fields are optional. If not specified, they default to `./ressources/queriesv3.json` and `./ressources/legacy_queries.json` respectively. Adjust these paths to match your directory structure.

2. **queriesv3.json** (for Platform API v3 mode) OR **legacy_queries.json** (for legacy mode) - Predefined queries:
   ```json
   [
     {
       "name": "Russia Suspicious OpenDir",
       "query": "labels:suspicious-open-dir and location.country_code:RU",
       "recursive": "yes",
       "max-depth": 3,
       "filters": [".pdf", ".lnk", ".exe", ".elf"]
     },
     {
       "name": "US OpenDir",
       "query": "labels:open-dir and location.country_code:US",
       "recursive": "yes",
       "max-depth": 3,
       "filters": [".docx", ".zip", ".xlsx"]
     },
     {
       "name": "Cobalt Strike Scanner",
       "query": "services.labels:`open-dir` and services.labels:`c2`",
       "filters": [],
       "check": true,
       "target_filename": "02.08.2022.exe"
     }
   ]
   ```

> **IMPORTANT**:
> - For **Platform API v3 mode (default)**: Use `queriesv3.json` and provide API credentials in config.json
> - For **Legacy mode**: Use `legacy_queries.json`, install Censys CLI, and use the `--legacy` flag
> - Visit [https://censys.io/plans](https://censys.io/plans) for subscription information

## Usage

### Basic Usage

Start Censei in interactive mode:

```bash
./censei
```

### Examples for different scenarios

**Direct query with specific filters:**
```bash
./censei --query="labels:suspicious-open-dir and location.country_code:RU" --filter=".pdf,.exe"
```

**Recursive scanning with depth limit:**
```bash
./censei --recursive --max-depth=3 --query="labels:open-dir and location.country_code:US"
```

**Query with custom output path:**
```bash
./censei --output=/path/to/results
```

**Query with different log level:**
```bash
./censei --log-level=DEBUG
```

**Using alternative configuration files:**
```bash
./censei --config=/path/to/config.json --queries=/path/to/queries.json
```

**Using legacy mode with Censys CLI:**
```bash
./censei --legacy --queries=legacy_queries.json
```

**Enabling File Checker mode:**
```bash
./censei --check --target-file="suspicious.exe"
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config` | Path to configuration file | `./ressources/config.json` |
| `--queries` | Path to queries file | `./ressources/queriesv3.json` (or `./ressources/legacy_queries.json` in legacy mode) |
| `--query` | Direct execution of a specific query | - |
| `--filter` | Specification of file extensions to filter (comma-separated) | - |
| `--output` | Override output directory | From configuration |
| `--log-level` | Set log level (DEBUG, INFO, ERROR) | From configuration |
| `--legacy` | Use legacy Censys CLI mode instead of Platform API v3 | `false` |
| `--check` | Enables the File Checker mode - checks hosts for specific binary files (still processes directories if target not found) | `false` |
| `--target-file` | Specifies the specific file to search for in File Checker mode | - |
| `--recursive` | Enable recursive directory scanning | `false` |
| `--max-depth` | Maximum depth for recursive scanning (requires --recursive) | `1` |

### Interactive Mode vs. Direct Queries

When the tool is started without the `--query` parameter, Censei starts in interactive mode and presents a menu with predefined queries from your queries.json file. This mode is user-friendly and ideal for exploration.

**Interactive Menu Features:**
- Displays up to 25 queries per page with pagination
- Shows query details (filters, recursive settings, target files)
- Navigation commands:
  - `[1-N]` - Select a query by number
  - `[c]` - Enter a custom query
  - `[n]` - Next page (if more queries available)
  - `[p]` - Previous page (if on page 2+)

For automation or scripts, use the `--query` parameter to execute a specific query directly without user interaction.

## Configuration

### config.json Structure

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api_key` | Your Censys API key (legacy mode) | - |
| `api_secret` | Your Censys API secret (legacy mode) | - |
| `bearer_token` | Your Platform API v3 bearer token | - |
| `organization_id` | Organization ID for Platform API v3 (optional) | `""` |
| `v3_max_results` | Maximum results for Platform API v3 queries | `500` |
| `legacy_pages` | Number of pages for legacy CLI queries | `25` |
| `legacy_per_page` | Results per page for legacy CLI | `100` |
| `legacy_index_type` | Index type for legacy CLI (hosts, certificates) | `hosts` |
| `legacy_sort_order` | Sort order for legacy CLI (ASCENDING, DESCENDING) | `DESCENDING` |
| `legacy_virtual_hosts` | Virtual hosts setting for legacy CLI (INCLUDE, EXCLUDE, ONLY) | `INCLUDE` |
| `queries_file_v3` | Path to Platform API v3 queries file (optional) | `./ressources/queriesv3.json` |
| `queries_file_legacy` | Path to legacy mode queries file (optional) | `./ressources/legacy_queries.json` |
| `output_dir` | Directory for output files | `./scan_output` |
| `binary_output_file` | Path for binary file outputs | `./scan_output/binary_found.txt` |
| `http_timeout_seconds` | Timeout for HTTP requests | `5` |
| `max_concurrent_requests` | Maximum parallel requests | `10` |
| `log_level` | Logging level (DEBUG, INFO, ERROR) | `INFO` |
| `log_file` | Path to log file | `./censei.log` |
| `max_links_per_directory` | Maximum links to process per directory | `500` |
| `max_total_links` | Total link limit per host before skipping | `10000` |
| `max_skips_before_block` | Number of skips before blocking entire host | `5` |
| `enable_blocklist` | Enable persistent host blocking functionality | `false` |
| `blocklist_file` | Path to file storing permanently blocked hosts | `./blocklist.txt` |

### queries.json Structure

The queries.json file contains an array of query objects, each with:

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Display name for the query | `"Russia Suspicious OpenDir"` |
| `query` | Censys search query | `"labels:suspicious-open-dir and location.country_code:RU"` |
| `filters` | Array of file extensions to filter | `[".pdf", ".exe", ".elf"]` |
| `check` | Enables File Checker mode for this query | `true` |
| `target_filename` | Specific file to search for in File Checker mode | `"02.08.2022.exe"` |
| `recursive` | Enable recursive scanning ("yes"/"no") | `"yes"` |
| `max-depth` | Maximum scanning depth for recursive mode | `3` |

## Output Files

Censei generates three main output files in the configured output directory:

### raw.txt

Contains all discovered URLs and files, formatted as:

```
http://example.com
Found file: http://example.com/index.html
Found file: http://example.com/data/
Found file: http://example.com/backup.zip
```

With File Checker mode enabled, binary files found will be displayed as:

```
http://example.com
Found binary file: http://example.com/02.08.2022.exe with Content-Type: application/x-msdownload
```

### filtered.txt

Contains only files that match the filter criteria:

```
http://example.com/backup.zip
http://example.com/documents/secret.pdf
```

### binary_found.txt

Contains URLs of binary files identified during scanning:

```
http://example.com/02.08.2022.exe
http://example.com/tools/app.exe
```

At the end of the raw.txt file, a summary of the scan with statistics and configuration details is appended.

## Advanced Features

### Recursive Directory Scanning

Censei supports recursive directory scanning to automatically explore subdirectories:

- **Enable recursion**: Set `"recursive": "yes"` in queries.json or use `--recursive` flag
- **Control depth**: Configure `"max-depth": 3` or use `--max-depth=3` to limit scanning depth
- **Performance protection**: Built-in limits prevent infinite recursion and resource exhaustion

### Smart Host Blocking

The tool includes intelligent host management to improve scanning efficiency:

- **Automatic blocking**: Hosts exceeding limits are automatically blocked
- **Persistent blocklist**: Blocked hosts are saved to file and persist between sessions
- **Configurable thresholds**: Adjust `max_skips_before_block` to control blocking sensitivity
- **Performance optimization**: Prevents wasting time on problematic hosts

### Performance Limits

Built-in safeguards prevent resource exhaustion:

- **Per-directory limits**: `max_links_per_directory` controls links processed per directory
- **Total link limits**: `max_total_links` sets overall limit per host
- **Memory protection**: Prevents excessive memory usage during large directory scans

### File Checker Mode

The File Checker mode is a special operating mode optimized for targeted searching for binary files:

- Activated by `check: true` in queries.json or `--check` on the command line
- When a `target_filename` is specified, checks hosts for that specific file first
- If the target file is found, skips further HTML processing for that host
- If the target file is NOT found, continues with normal directory scanning
- Uses GET requests with partial reads (512 bytes) to determine file type
- Does not save files to disk
- Optimized for quick identification of potentially harmful binary files

This mode is especially useful for security analysts looking for specific binary files without having to search through entire directory contents.

### Binary File Detection

Censei can detect binary files based on their Content-Type headers, including:
- **Generic binary**: application/octet-stream, application/binary
- **Executables**: application/x-executable, application/x-msdownload, application/exe, application/x-dosexec
- **Archives (ZIP)**: application/zip, application/x-zip-compressed
- **Archives (RAR, 7Z, TAR, GZ)**: application/x-rar, application/x-7z-compressed, application/x-tar, application/gzip
- **Scripts**: application/x-sh, application/x-bat

**Detection Methods:**
- **General file checking**: Uses HEAD requests to check Content-Type headers without downloading files
- **Targeted file checking** (with `--target-file`): Uses GET requests with partial reads (512 bytes) to verify file type and content

### Customizing Filters

You can customize filters in three ways:

1. In the queries.json file for predefined queries
2. With the `--filter` option on the command line
3. In interactive mode when selecting "Custom query"

The filter format is a comma-separated list of file extensions (e.g. `.pdf,.exe,.zip`).

### Customizing Log Levels

Available log levels:

- `DEBUG`: Detailed information for troubleshooting
- `INFO`: General operational information
- `ERROR`: Error messages only

Set the log level in config.json or with the `--log-level` parameter.

### Optimizing Parallelization

Adjust the `max_concurrent_requests` setting in config.json based on your system capabilities and network conditions. Higher values increase performance but may lead to rate limiting or resource exhaustion.

## Troubleshooting

### Common Problems

**Censys CLI not found:**
```
ERROR: The censys-cli tool was not found. Please install it with:
pip install censys-command-line
```
Solution: Install the Censys CLI as indicated.

**API credentials invalid:**
```
Failed to execute Censys query: censys CLI error: Invalid API ID or Secret
```
Solution: Check your API credentials in config.json.

**No results found:**
```
Extracted 0 hosts from Censys results
```
Solution: Check your query string or try a broader search.

### Debugging Tips

1. Set the log level to DEBUG for detailed information:
   ```bash
   ./censei --log-level=DEBUG
   ```

2. Check the generated JSON file to ensure Censys is returning results:
   ```bash
   cat scan_output/censys_results.json
   ```

3. Test the Censys CLI manually to verify API functionality:
   ```bash
   censys search "labels:open-dir" --output test.json
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.