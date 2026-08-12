# Enigma — Autonomous XSS & SSRF Engine

Enigma is an autonomous security testing engine for web applications. It implements a **5-rotor XSS methodology** and a **4-phase SSRF methodology** as composable, knowledge-accumulating scanners.

## XSS Engine

Uses a 5-rotor cascade to systematically bypass WAF protections:

| Rotor | Purpose |
|-------|---------|
| **Context** | Detect injection point (40+ contexts: HTML, attribute, script, SVG, JSON, DOM sinks) |
| **Blockers** | Binary-search decomposition to identify exactly what the WAF blocks |
| **Encoding** | Apply targeted character encoding (HTML entities, JS unicode, double-URL, layered) |
| **Structure** | Restructure payload syntax (parentheses bypass, DOM clobbering, JSFuck, comment jumping) |
| **Execution** | Select firing mechanism (auto-fire events, browser-specific vectors, JavaScript URLs) |

### Usage

```bash
# Basic reflected XSS scan
enigma run "https://target.com/search" "q"

# With authentication
enigma run "https://target.com/search" "q" --cookie="session=abc123"

# DOM XSS via URL hash
enigma run "https://target.com/#" "hash" --source=hash

# Stored XSS with follow-up observation
enigma run "https://target.com/comment" "comment" \
  --observe="https://target.com/post/123"
```

## SSRF Engine

Implements a 4-phase methodology: **Discovery → Target → Bypass → Confirm**.

### Usage

```bash
# Find SSRF-prone parameters in proxy traffic
enigma-ssrf discover "target.com"

# With custom HTTPQL filter
enigma-ssrf discover "target.com" --httpql="req.path.cont:'/api/'"

# Full autonomous scan with OOB callback
enigma-ssrf run "https://target.com/api/fetch" "url" \
  --canary="https://poc-harness.com/c/TOKEN"

# Blind SSRF with continuous callback watching
enigma-ssrf blind "https://target.com/webhook" "callback_url" \
  --canary="https://poc-harness.com/c/TOKEN" --watch

# Targeted bypass against specific internal URL
enigma-ssrf run "https://target.com/api/fetch" "url" \
  --target="http://169.254.169.254/latest/meta-data/"

# Test header injection vectors
enigma-ssrf run "https://target.com/api/webhook" "callback_url" \
  --test-headers --canary="https://poc-harness.com/c/TOKEN"

# Verbose output with custom timeout
enigma-ssrf run "https://target.com/import" "source_url" \
  --verbose --timeout=15000 --max=200

# With Slack notifications
enigma-ssrf run "https://target.com/api/fetch" "url" \
  --canary="https://poc-harness.com/c/TOKEN" --slack-webhook="https://hooks.slack.com/..."
```

### Confirmation Methods

The engine uses multiple confirmation methods for SSRF verification:

| Method | Description |
|--------|-------------|
| **OOB Callbacks** | HTTP, DNS-only, path-identified, redirect chain |
| **Timing Analysis** | Mean + stddev, timeout detection, outlier flagging |
| **Content Matching** | Credential patterns, service fingerprints, file content detection |
| **Size Analysis** | Internal vs external group comparison |

Content matching detects:
- AWS/GCP/Azure credentials (AccessKeyId, SecretAccessKey, session tokens)
- Database connection strings, API keys, private keys
- Service fingerprints (Redis, Elasticsearch, Docker, Kubernetes, etcd, Consul)
- Sensitive files (/etc/passwd, /etc/shadow, SSH keys, certificates)
- Error leaks (stack traces, SQL errors, permission denied)

### Impact Assessment

CVSS-based impact scoring with attack path visualization:

| Category | Base CVSS | Severity |
|----------|-----------|----------|
| Cloud Metadata | 9.0 | Critical |
| Redis Attack | 8.8 | High |
| Protocol Smuggling | 8.1 | High |
| Internal Service | 7.5 | High |
| Localhost Admin | 7.0 | High |
| Parser Confusion | 6.5 | Medium |

### Scan State Machine

The engine uses a phase transition state machine:

```
Discovery → Targeting → Bypass → Confirmation → Impact → Report
                                      ↓
                               Blocked → Bypass (retry)
                               No signal → Discovery (new params)
```

## Credits

The methodology and techniques implemented here draw from the published work of several researchers:

- **Gareth Heyes** ([@garethheyes](https://portswigger.net/research/gareth-heyes)) — The 5-rotor XSS methodology, cascade orders, and systematic context-aware approach to XSS are based on his book [*JavaScript for Hackers*](https://www.amazon.co.uk/JavaScript-Hackers-Learn-Think-Like/dp/1119860555). Specific techniques include parentheses-free function calling (Ch. 2), DOM clobbering (Ch. 4), non-alphanumeric JavaScript / JSFuck (Ch. 7), and event-based execution vectors (Ch. 8).

- **Brute Logic** ([brutelogic.net](https://brutelogic.net)) — The 4-phase SSRF testing framework (Discovery, Target, Bypass, Confirm) and filter exploitation techniques for XSS (regex decoys, attribute doubling, tag boundary confusion, formfeed spacers).

- **Orange Tsai** — URL parser confusion and differential parsing attacks from [*A New Era of SSRF — Exploiting URL Parsers in Trending Programming Languages*](https://www.blackhat.com/us-17/briefings.html#a-new-era-of-ssrf-exploiting-url-parser-in-trending-programming-languages) (Black Hat USA 2017). Specific techniques: authority confusion (p. 33–34), CRLF injection (p. 53–54), TLS SNI injection (p. 38–39), IDNA case-folding (p. 61–62), fullwidth/circled digit normalization (p. 40–44), DNS rebinding TOCTOU (p. 45, 67–68).

- **Justin Gardner** — Blind SSRF methodology and out-of-band canary token patterns for confirming exploitation without response visibility.

- **Corben Leo** — Feature-based SSRF discovery, identifying vulnerable functionality by application behavior rather than parameter names alone.

## Architecture

```
core/engines/
├── mutation/                    # XSS 5-rotor engine
│   ├── composer.ts              # Orchestrator: knowledge state, candidate generation
│   ├── context-techniques.ts    # R1: 40+ context detection patterns
│   ├── blockers.ts              # R2: binary search, cascade alternatives
│   ├── encoders.ts              # R3: 10 encoding types, layered encoding
│   ├── structures.ts            # R4: paren bypass, DOM clobbering, JSFuck
│   ├── executors.ts             # R5: auto-fire events, browser-specific, JS URLs
│   ├── baselines.ts             # Starting payloads per context
│   └── composite-triggers.ts    # Multi-family trigger rules
├── dom/
│   └── sink-hooks.ts            # 30+ DOM sink monkey-patches
├── trigger-finder.ts            # Binary search probe engine
└── ssrf/                        # SSRF 4-phase engine
    ├── bypasses/
    │   ├── ip-obfuscation.ts    # 11 IP representation conversions
    │   ├── parser-confusion.ts  # 8 technique generators (Orange Tsai)
    │   ├── protocols.ts         # file, gopher, dict, ftp, data (50+ paths)
    │   ├── header-injection.ts  # SSRF via HTTP headers
    │   └── dns-rebinding.ts     # TOCTOU race conditions
    ├── payloads/
    │   ├── cloud-metadata.ts    # 14 cloud providers, AWS IMDSv2
    │   └── internal-services.ts # 18 internal services, localhost admin
    ├── canary.ts                # OOB callbacks, timing/size/content analysis, notifications
    ├── decision-trees.ts        # Stack detection, payload planning, CVSS scoring, scan state machine
    └── index.ts                 # Barrel re-exports

core/runner/
├── index.ts                     # Puppeteer-based scanner
└── session-store.ts             # JSON session persistence

core/visualization/
├── logger.ts                    # NDJSON event logging
└── dashboard.ts                 # Real-time SSE web dashboard

cli/commands/
├── run.ts                       # XSS autonomous scan
├── init.ts / next.ts / observe.ts / result.ts  # Agent mode
├── discover/                    # Caido XSS surface discovery
└── ssrf/                        # SSRF CLI (run, discover, blind)
```

## Visualization

The 5-rotor methodology is demonstrated in the competitor's interactive walkthrough article
[*Inside Enigma: How 5 Rotors Crack WAF-Protected XSS*](https://labs.trace37.com/blog/enigma-5-rotor-visualization/).
Pre-extracted frames from a representative scan are available under
`%TEMP%/opencode/frames/` (60 JPGs at ~2.92s sampling from a 175s demo) along with
`manifest.json` documenting video source and sampling cadence. Frame timestamps align
with the rotor-progression sequence described in the visualization article:
early frames show R1 (context probe), middle frames show R2/R3 (binary-search +
encoding cascade), later frames show R4/R5 (structure mutations + execution firing).
The `core/visualization/logger.ts` (NDJSON event stream) and
`core/visualization/dashboard.ts` (real-time SSE web dashboard) provide the
same per-rotor event timeline inside our codebase.

## License

This is an authorized security testing framework for evaluating web application security. Use only against systems you have explicit permission to test.
