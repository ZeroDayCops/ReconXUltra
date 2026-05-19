#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Async Pipeline Orchestrator
# ============================================================================
# Provides high-speed parallel module execution, adaptive concurrency,
# worker queues, and intelligent batching for massive recon throughput.
# ============================================================================

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi
source "${RECONX_CORE}/logger.sh"

# ── Performance Modes ───────────────────────────────────────────────────────
# safe       = 10 threads,  50 rate,   sequential modules
# balanced   = 50 threads, 150 rate,   2 parallel module groups
# aggressive = 100 threads, 300 rate,  3 parallel module groups
# ultra      = 200 threads, 500 rate,  4 parallel module groups
# nuclear    = 500 threads, 1000 rate, max parallel everything

declare -A PERF_MODES=(
    ["safe.threads"]="10"
    ["safe.rate"]="50"
    ["safe.parallel_groups"]="1"
    ["safe.max_fuzz_hosts"]="10"
    ["safe.timeout"]="30"
    ["safe.retries"]="3"

    ["balanced.threads"]="50"
    ["balanced.rate"]="150"
    ["balanced.parallel_groups"]="2"
    ["balanced.max_fuzz_hosts"]="30"
    ["balanced.timeout"]="25"
    ["balanced.retries"]="3"

    ["aggressive.threads"]="100"
    ["aggressive.rate"]="300"
    ["aggressive.parallel_groups"]="3"
    ["aggressive.max_fuzz_hosts"]="50"
    ["aggressive.timeout"]="20"
    ["aggressive.retries"]="2"

    ["ultra.threads"]="200"
    ["ultra.rate"]="500"
    ["ultra.parallel_groups"]="4"
    ["ultra.max_fuzz_hosts"]="100"
    ["ultra.timeout"]="15"
    ["ultra.retries"]="2"

    ["nuclear.threads"]="500"
    ["nuclear.rate"]="1000"
    ["nuclear.parallel_groups"]="6"
    ["nuclear.max_fuzz_hosts"]="200"
    ["nuclear.timeout"]="10"
    ["nuclear.retries"]="1"
)

# Current performance mode
PERF_MODE="${PERF_MODE:-balanced}"

# ── Auto-Detect System Resources ────────────────────────────────────────────
detect_system_resources() {
    local cpu_cores
    cpu_cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

    local total_ram_mb
    total_ram_mb="$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo 4096)"

    local available_ram_mb
    available_ram_mb="$(free -m 2>/dev/null | awk '/^Mem:/{print $7}' || echo 2048)"

    export SYS_CPU_CORES="$cpu_cores"
    export SYS_TOTAL_RAM_MB="$total_ram_mb"
    export SYS_AVAILABLE_RAM_MB="$available_ram_mb"

    log_debug "System: ${cpu_cores} CPU cores, ${total_ram_mb}MB RAM (${available_ram_mb}MB free)"
}

# ── Adaptive Concurrency ────────────────────────────────────────────────────
auto_tune_concurrency() {
    detect_system_resources

    local base_threads="${PERF_MODES[${PERF_MODE}.threads]:-50}"
    local base_rate="${PERF_MODES[${PERF_MODE}.rate]:-150}"

    # Scale threads based on CPU cores
    local cpu_factor=$((SYS_CPU_CORES * 10))
    if [[ "$cpu_factor" -lt "$base_threads" ]]; then
        base_threads="$cpu_factor"
    fi

    # Scale down if low memory
    if [[ "$SYS_AVAILABLE_RAM_MB" -lt 1024 ]]; then
        base_threads=$((base_threads / 2))
        base_rate=$((base_rate / 2))
        log_warn "Low memory detected — reducing concurrency"
    fi

    THREADS="$base_threads"
    RATE_LIMIT="$base_rate"
    TIMEOUT="${PERF_MODES[${PERF_MODE}.timeout]:-25}"
    RETRIES="${PERF_MODES[${PERF_MODE}.retries]:-3}"

    export MAX_FUZZ_HOSTS="${PERF_MODES[${PERF_MODE}.max_fuzz_hosts]:-30}"
    export PARALLEL_GROUPS="${PERF_MODES[${PERF_MODE}.parallel_groups]:-2}"

    log_info "Performance mode: ${PERF_MODE} | Threads: ${THREADS} | Rate: ${RATE_LIMIT} | Timeout: ${TIMEOUT}s"
}

# ── Apply Performance Mode ──────────────────────────────────────────────────
apply_perf_mode() {
    local mode="${1:-$PERF_MODE}"
    PERF_MODE="$mode"

    if [[ -z "${PERF_MODES[${mode}.threads]:-}" ]]; then
        log_warn "Unknown performance mode: $mode — using balanced"
        PERF_MODE="balanced"
    fi

    auto_tune_concurrency
}

# ── Parallel Module Group Execution ─────────────────────────────────────────
# Define which modules can safely run in parallel
declare -A PARALLEL_MODULE_GROUPS=(
    ["group_1"]="subdomains"
    ["group_2"]="live"
    ["group_3"]="urls js"
    ["group_4"]="content api"
    ["group_5"]="ports nuclei"
    ["group_6"]="screenshots takeover cors wordpress"
    ["group_7"]="intelligence"
    ["group_8"]="exploit"
    ["group_9"]="reporting"
)

# ── Run Modules In Parallel Groups ──────────────────────────────────────────
run_parallel_pipeline() {
    local domain="$1"
    local modules_csv="${2:-}"

    local pipeline=()
    if [[ -n "$modules_csv" ]]; then
        IFS=',' read -ra pipeline <<< "$modules_csv"
    else
        pipeline=("${DEFAULT_PIPELINE[@]}")
    fi

    local total=${#pipeline[@]}
    local current=0
    local failed=0

    log_info "Starting PARALLEL recon pipeline with ${total} modules (mode: ${PERF_MODE})"
    echo ""

    # Determine max parallel based on mode
    local max_parallel="${PERF_MODES[${PERF_MODE}.parallel_groups]:-2}"

    # Group modules that can run simultaneously
    local -a current_batch=()
    local batch_idx=0

    for module in "${pipeline[@]}"; do
        current=$((current + 1))
        current_batch+=("$module")

        # Check if this module must run before next one (dependency chain)
        local must_barrier=false
        case "$module" in
            subdomains) must_barrier=true ;;  # live depends on subdomains
            live)       must_barrier=true ;;  # urls depends on live
            urls)       ;;                     # js can run with urls
            js)         must_barrier=true ;;  # content needs urls+js
            intelligence) must_barrier=true ;; # exploit depends on intelligence
        esac

        if [[ "$must_barrier" == true ]] || [[ "${#current_batch[@]}" -ge "$max_parallel" ]]; then
            # Execute this batch
            _execute_batch "$domain" "${current_batch[@]}"
            local batch_exit=$?
            [[ "$batch_exit" -ne 0 ]] && failed=$((failed + batch_exit))
            current_batch=()
            batch_idx=$((batch_idx + 1))
        fi
    done

    # Execute remaining batch
    if [[ "${#current_batch[@]}" -gt 0 ]]; then
        _execute_batch "$domain" "${current_batch[@]}"
        local batch_exit=$?
        [[ "$batch_exit" -ne 0 ]] && failed=$((failed + batch_exit))
    fi

    echo ""
    if [[ "$failed" -eq 0 ]]; then
        log_success "Parallel pipeline completed — all modules passed"
    else
        log_warn "Pipeline completed with ${failed} module(s) having errors"
    fi
}

# ── Execute a Batch of Modules in Parallel ──────────────────────────────────
_execute_batch() {
    local domain="$1"
    shift
    local modules=("$@")
    local pids=()
    local module_names=()
    local batch_failed=0

    if [[ "${#modules[@]}" -eq 1 ]]; then
        # Single module — run synchronously
        log_progress_batch "${modules[0]}"
        run_module "${modules[0]}" "$domain"
        [[ $? -ne 0 ]] && batch_failed=$((batch_failed + 1))
    else
        # Multiple modules — run in parallel
        local module_list
        module_list="$(IFS=', '; echo "${modules[*]}")"
        log_info "Parallel batch: [${module_list}]"

        for module in "${modules[@]}"; do
            (
                run_module "$module" "$domain"
            ) &
            pids+=($!)
            module_names+=("$module")
        done

        # Wait for all processes
        for i in "${!pids[@]}"; do
            wait "${pids[$i]}" 2>/dev/null
            local exit_code=$?
            if [[ "$exit_code" -ne 0 ]]; then
                log_warn "Module '${module_names[$i]}' failed in parallel batch"
                batch_failed=$((batch_failed + 1))
            fi
        done
    fi

    return "$batch_failed"
}

# ── Batch URL Processing ────────────────────────────────────────────────────
# Process URLs in parallel batches for high-speed scanning
batch_process_urls() {
    local input_file="$1"
    local callback="$2"
    local batch_size="${3:-50}"
    local max_workers="${4:-$THREADS}"

    if [[ ! -f "$input_file" ]]; then
        log_warn "Input file not found: $input_file"
        return 1
    fi

    local total
    total="$(wc -l < "$input_file")"
    local processed=0
    local worker_count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        processed=$((processed + 1))

        # Call the callback in background
        $callback "$line" &
        worker_count=$((worker_count + 1))

        # Throttle workers
        if [[ "$worker_count" -ge "$max_workers" ]]; then
            wait
            worker_count=0
        fi

        # Progress update every 100 items
        if [[ $((processed % 100)) -eq 0 ]]; then
            log_progress "$processed" "$total" "Processing"
        fi
    done < "$input_file"

    # Wait for remaining workers
    wait

    log_progress "$total" "$total" "Processing"
    return 0
}

# ── Retry Engine with Exponential Backoff ────────────────────────────────────
smart_retry() {
    local max_attempts="${1:-$RETRIES}"
    local base_delay="${2:-1}"
    shift 2
    local cmd=("$@")

    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if "${cmd[@]}" 2>/dev/null; then
            return 0
        fi

        if [[ "$attempt" -lt "$max_attempts" ]]; then
            local delay=$((base_delay * (2 ** (attempt - 1))))
            # Add jitter
            delay=$((delay + RANDOM % delay))
            sleep "$delay"
        fi
    done

    return 1
}

# ── Progress Helper ─────────────────────────────────────────────────────────
log_progress_batch() {
    local module="$1"
    echo -e "${CYAN}  ▸ Running: ${BOLD}${module}${RESET}"
}
