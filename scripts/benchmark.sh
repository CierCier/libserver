#!/usr/bin/env bash
#
# Server Benchmark Script for libserver using wrk
#
# This script provides comprehensive benchmarking capabilities to stress test
# the server under various conditions using the wrk HTTP benchmarking tool.
#
# Dependencies: wrk (https://github.com/wg/wrk)
#   Install: apt install wrk / pacman -S wrk / brew install wrk
#
# Usage:
#   ./benchmark.sh [OPTIONS]
#
# Examples:
#   ./benchmark.sh -u http://127.0.0.1:8080/
#   ./benchmark.sh -u http://127.0.0.1:8080/api/ping -c 100 -d 30s
#   ./benchmark.sh -u http://127.0.0.1:8080 --suite

set -euo pipefail

# Colors for output
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
CYAN='\033[0;96m'
BOLD='\033[1m'
RESET='\033[0m'

# Default values
DEFAULT_URL="http://127.0.0.1:8080"
DEFAULT_THREADS=4
DEFAULT_CONNECTIONS=10
DEFAULT_DURATION="10s"
DEFAULT_TIMEOUT="30s"

# Script variables
URL=""
PATH_SUFFIX="/"
THREADS=$DEFAULT_THREADS
CONNECTIONS=$DEFAULT_CONNECTIONS
DURATION=$DEFAULT_DURATION
TIMEOUT=$DEFAULT_TIMEOUT
METHOD="GET"
BODY=""
HEADERS=""
RUN_SUITE=false
JSON_OUTPUT=false
QUIET=false
SCRIPT_FILE=""
LATENCY_FLAG=""

# Temporary files
TMP_DIR=$(mktemp -d)
RESULTS_FILE="$TMP_DIR/results.txt"
LUA_SCRIPT="$TMP_DIR/request.lua"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

usage() {
    cat << EOF
${BOLD}Server Benchmark Script for libserver${RESET}

${BOLD}USAGE:${RESET}
    $(basename "$0") [OPTIONS]

${BOLD}OPTIONS:${RESET}
    -u, --url URL           Base URL of the server (default: $DEFAULT_URL)
    -p, --path PATH         Request path (default: /)
    -t, --threads NUM       Number of threads (default: $DEFAULT_THREADS)
    -c, --connections NUM   Number of connections (default: $DEFAULT_CONNECTIONS)
    -d, --duration TIME     Test duration (e.g., 10s, 1m) (default: $DEFAULT_DURATION)
    -T, --timeout TIME      Request timeout (default: $DEFAULT_TIMEOUT)
    -m, --method METHOD     HTTP method: GET, POST, PUT, DELETE (default: GET)
    -b, --body DATA         Request body for POST/PUT
    -H, --header HEADER     Add header (format: 'Key: Value'), can be repeated
    -s, --script FILE       Custom wrk Lua script
    -l, --latency           Print detailed latency statistics
    --suite                 Run full benchmark suite
    --json                  Output results as JSON (single test only)
    -q, --quiet             Minimal output
    -h, --help              Show this help message

${BOLD}EXAMPLES:${RESET}
    # Basic test
    $(basename "$0") -u http://127.0.0.1:8080/

    # High concurrency test
    $(basename "$0") -u http://127.0.0.1:8080/api/ping -c 100 -t 8 -d 30s

    # Run full benchmark suite
    $(basename "$0") -u http://127.0.0.1:8080 --suite

    # POST with JSON body
    $(basename "$0") -u http://127.0.0.1:8080/api/data -m POST -b '{"key":"value"}' -H 'Content-Type: application/json'

    # With latency percentiles
    $(basename "$0") -u http://127.0.0.1:8080/ -l

${BOLD}DEPENDENCIES:${RESET}
    wrk - Modern HTTP benchmarking tool
    Install: apt install wrk / pacman -S wrk / brew install wrk
EOF
}

check_dependencies() {
    if ! command -v wrk &> /dev/null; then
        echo -e "${RED}Error: wrk is not installed.${RESET}"
        echo "Please install wrk:"
        echo "  Ubuntu/Debian: sudo apt install wrk"
        echo "  Arch Linux:    sudo pacman -S wrk"
        echo "  macOS:         brew install wrk"
        echo "  From source:   https://github.com/wg/wrk"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                URL="$2"
                shift 2
                ;;
            -p|--path)
                PATH_SUFFIX="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -c|--connections)
                CONNECTIONS="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -T|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -m|--method)
                METHOD="${2^^}"
                shift 2
                ;;
            -b|--body)
                BODY="$2"
                shift 2
                ;;
            -H|--header)
                if [[ -n "$HEADERS" ]]; then
                    HEADERS="$HEADERS|$2"
                else
                    HEADERS="$2"
                fi
                shift 2
                ;;
            -s|--script)
                SCRIPT_FILE="$2"
                shift 2
                ;;
            -l|--latency)
                LATENCY_FLAG="--latency"
                shift
                ;;
            --suite)
                RUN_SUITE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${RESET}"
                usage
                exit 1
                ;;
        esac
    done

    # Set default URL if not provided
    if [[ -z "$URL" ]]; then
        URL="$DEFAULT_URL"
    fi

    # Remove trailing slash from URL
    URL="${URL%/}"
}

generate_lua_script() {
    local method="$1"
    local body="$2"
    local headers="$3"

    cat > "$LUA_SCRIPT" << 'LUAEOF'
-- wrk benchmark script
wrk.method = "METHOD_PLACEHOLDER"
LUAEOF

    # Replace method
    sed -i "s/METHOD_PLACEHOLDER/$method/" "$LUA_SCRIPT"

    # Add body if provided
    if [[ -n "$body" ]]; then
        cat >> "$LUA_SCRIPT" << LUAEOF
wrk.body = [[$body]]
LUAEOF
    fi

    # Add headers if provided
    if [[ -n "$headers" ]]; then
        echo "wrk.headers = {}" >> "$LUA_SCRIPT"
        IFS='|' read -ra HEADER_ARRAY <<< "$headers"
        for header in "${HEADER_ARRAY[@]}"; do
            key="${header%%:*}"
            value="${header#*:}"
            value="${value# }"  # trim leading space
            echo "wrk.headers[\"$key\"] = \"$value\"" >> "$LUA_SCRIPT"
        done
    fi

    # Add response handling for statistics
    cat >> "$LUA_SCRIPT" << 'LUAEOF'

-- Track response status codes
response_codes = {}

response = function(status, headers, body)
    response_codes[status] = (response_codes[status] or 0) + 1
end

done = function(summary, latency, requests)
    io.write("------------------------------\n")
    io.write("Status code distribution:\n")
    for code, count in pairs(response_codes) do
        io.write(string.format("  [%d] %d responses\n", code, count))
    end
end
LUAEOF

    echo "$LUA_SCRIPT"
}

run_single_benchmark() {
    local url="$1"
    local threads="$2"
    local connections="$3"
    local duration="$4"
    local method="${5:-GET}"
    local body="${6:-}"
    local headers="${7:-}"
    local title="${8:-Benchmark}"

    local full_url="$url"
    local script_arg=""

    # Generate Lua script if needed (for non-GET or with body/headers)
    if [[ "$method" != "GET" ]] || [[ -n "$body" ]] || [[ -n "$headers" ]]; then
        local script_path
        script_path=$(generate_lua_script "$method" "$body" "$headers")
        script_arg="-s $script_path"
    fi

    if [[ "$QUIET" != true ]]; then
        echo -e "\n${BOLD}${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${CYAN}$(printf '%60s' "$title" | sed 's/^ *//')${RESET}"
        echo -e "${BOLD}${CYAN}============================================================${RESET}\n"
        echo -e "${BOLD}Configuration:${RESET}"
        echo "  URL:         $full_url"
        echo "  Method:      $method"
        echo "  Threads:     $threads"
        echo "  Connections: $connections"
        echo "  Duration:    $duration"
        echo "  Timeout:     $TIMEOUT"
        [[ -n "$body" ]] && echo "  Body:        ${body:0:50}..."
        echo ""
    fi

    # Run wrk
    local wrk_cmd="wrk -t$threads -c$connections -d$duration --timeout $TIMEOUT $LATENCY_FLAG $script_arg \"$full_url\""
    
    if [[ "$QUIET" != true ]]; then
        echo -e "${BOLD}Running:${RESET} $wrk_cmd\n"
    fi

    local output
    output=$(eval "$wrk_cmd" 2>&1) || true

    if [[ "$JSON_OUTPUT" == true ]]; then
        parse_wrk_to_json "$output"
    else
        echo "$output"
        echo ""
        
        # Extract and highlight key metrics
        local rps latency_avg latency_max
        rps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
        latency_avg=$(echo "$output" | grep "Latency" | head -1 | awk '{print $2}')
        latency_max=$(echo "$output" | grep "Latency" | head -1 | awk '{print $4}')
        
        if [[ -n "$rps" ]]; then
            echo -e "${BOLD}${GREEN}Key Metrics:${RESET}"
            echo -e "  Requests/sec: ${GREEN}$rps${RESET}"
            echo -e "  Avg Latency:  ${CYAN}$latency_avg${RESET}"
            echo -e "  Max Latency:  ${YELLOW}$latency_max${RESET}"
        fi
    fi

    # Return the output for suite aggregation
    echo "$output" > "$RESULTS_FILE"
}

parse_wrk_to_json() {
    local output="$1"
    
    # Extract values using grep and awk
    local threads connections duration
    local latency_avg latency_stdev latency_max
    local rps transfer
    local total_requests total_duration
    local errors_connect errors_read errors_write errors_timeout

    threads=$(echo "$output" | grep -oP '\d+(?= threads)')
    connections=$(echo "$output" | grep -oP '\d+(?= connections)')
    
    latency_avg=$(echo "$output" | grep "Latency" | head -1 | awk '{print $2}')
    latency_stdev=$(echo "$output" | grep "Latency" | head -1 | awk '{print $3}')
    latency_max=$(echo "$output" | grep "Latency" | head -1 | awk '{print $4}')
    
    rps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
    transfer=$(echo "$output" | grep "Transfer/sec:" | awk '{print $2}')
    
    total_requests=$(echo "$output" | grep -oP '\d+(?= requests in)')
    total_duration=$(echo "$output" | grep -oP '(?<=requests in )\S+')
    
    # Socket errors (if any)
    errors_connect=$(echo "$output" | grep -oP '(?<=connect )\d+' || echo "0")
    errors_read=$(echo "$output" | grep -oP '(?<=read )\d+' || echo "0")
    errors_write=$(echo "$output" | grep -oP '(?<=write )\d+' || echo "0")
    errors_timeout=$(echo "$output" | grep -oP '(?<=timeout )\d+' || echo "0")

    cat << EOF
{
  "config": {
    "threads": ${threads:-0},
    "connections": ${connections:-0}
  },
  "latency": {
    "avg": "${latency_avg:-0}",
    "stdev": "${latency_stdev:-0}",
    "max": "${latency_max:-0}"
  },
  "throughput": {
    "requests_per_sec": ${rps:-0},
    "transfer_per_sec": "${transfer:-0}"
  },
  "totals": {
    "requests": ${total_requests:-0},
    "duration": "${total_duration:-0}"
  },
  "errors": {
    "connect": ${errors_connect:-0},
    "read": ${errors_read:-0},
    "write": ${errors_write:-0},
    "timeout": ${errors_timeout:-0}
  }
}
EOF
}

run_benchmark_suite() {
    local base_url="$1"

    echo -e "\n${BOLD}${MAGENTA}############################################################${RESET}"
    echo -e "${BOLD}${MAGENTA}$(printf '%60s' "LIBSERVER BENCHMARK SUITE" | sed 's/^ *//')${RESET}"
    echo -e "${BOLD}${MAGENTA}############################################################${RESET}"
    echo -e "\nTarget: $base_url"
    echo -e "Date:   $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # Array of test cases: "name|path|threads|connections|duration"
    local test_cases=(
        "Warmup (light load)|/|2|10|5s"
        "GET / - Low Concurrency|/|4|10|10s"
        "GET / - Medium Concurrency|/|4|50|10s"
        "GET / - High Concurrency|/|8|100|10s"
        "GET / - Very High Concurrency|/|8|200|10s"
        "GET /api/ping - API Endpoint|/api/ping|4|50|10s"
        "GET /api/users/:id - Param Route|/api/users/123|4|50|10s"
        "Sustained Load Test|/|8|100|30s"
        "Connection Stress Test|/|4|500|10s"
        "Thread Scaling Test|/|16|100|10s"
    )

    # Results storage for summary
    declare -a results_name
    declare -a results_rps
    declare -a results_latency_avg
    declare -a results_latency_max

    local idx=0
    for test_case in "${test_cases[@]}"; do
        IFS='|' read -r name path threads connections duration <<< "$test_case"
        
        local full_url="${base_url}${path}"
        
        # Run the benchmark
        run_single_benchmark "$full_url" "$threads" "$connections" "$duration" "GET" "" "" "$name"

        # Extract metrics from results
        if [[ -f "$RESULTS_FILE" ]]; then
            local output
            output=$(cat "$RESULTS_FILE")
            local rps latency_avg latency_max
            rps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
            latency_avg=$(echo "$output" | grep "Latency" | head -1 | awk '{print $2}')
            latency_max=$(echo "$output" | grep "Latency" | head -1 | awk '{print $4}')

            results_name[$idx]="$name"
            results_rps[$idx]="${rps:-N/A}"
            results_latency_avg[$idx]="${latency_avg:-N/A}"
            results_latency_max[$idx]="${latency_max:-N/A}"
            ((idx++))
        fi

        # Small delay between tests
        sleep 1
    done

    # Print summary comparison
    echo -e "\n${BOLD}${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${CYAN}$(printf '%60s' "SUMMARY COMPARISON" | sed 's/^ *//')${RESET}"
    echo -e "${BOLD}${CYAN}============================================================${RESET}\n"

    printf "${BOLD}%-35s %12s %12s %12s${RESET}\n" "Test Name" "RPS" "Avg Lat" "Max Lat"
    printf "%s\n" "$(printf '%.0s-' {1..73})"

    for ((i=0; i<idx; i++)); do
        printf "%-35s %12s %12s %12s\n" \
            "${results_name[$i]:0:35}" \
            "${results_rps[$i]}" \
            "${results_latency_avg[$i]}" \
            "${results_latency_max[$i]}"
    done

    echo ""
    echo -e "${BOLD}Legend:${RESET}"
    echo "  RPS      = Requests per second (higher is better)"
    echo "  Avg Lat  = Average latency (lower is better)"
    echo "  Max Lat  = Maximum latency (lower is better)"
}

# Quick connectivity test
test_connectivity() {
    local url="$1"
    
    if ! command -v curl &> /dev/null; then
        return 0  # Skip test if curl not available
    fi

    if [[ "$QUIET" != true ]]; then
        echo -e "${CYAN}Testing connectivity to $url...${RESET}"
    fi

    if ! curl -s --connect-timeout 5 -o /dev/null "$url" 2>/dev/null; then
        echo -e "${YELLOW}Warning: Could not connect to $url${RESET}"
        echo -e "${YELLOW}Make sure the server is running.${RESET}"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        if [[ "$QUIET" != true ]]; then
            echo -e "${GREEN}Connection successful!${RESET}\n"
        fi
    fi
}

main() {
    check_dependencies
    parse_args "$@"

    local full_url="${URL}${PATH_SUFFIX}"

    # Test connectivity first (unless quiet)
    if [[ "$QUIET" != true ]]; then
        test_connectivity "$URL"
    fi

    if [[ "$RUN_SUITE" == true ]]; then
        run_benchmark_suite "$URL"
    else
        if [[ -n "$SCRIPT_FILE" ]]; then
            # Use custom script
            LUA_SCRIPT="$SCRIPT_FILE"
        fi
        run_single_benchmark "$full_url" "$THREADS" "$CONNECTIONS" "$DURATION" "$METHOD" "$BODY" "$HEADERS" "Benchmark Results"
    fi
}

main "$@"
