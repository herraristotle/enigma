# Enigma Engine Audit Report

**Date:** 2026-07-27  
**Auditor:** Senior Application Security Researcher  
**Scope:** SSRF and XSS engines against competitor reference material  

---

## Executive Summary

The junior implementation provides a solid foundation but lacks critical autonomous behaviors present in the competitor's Enigma engines. The SSRF engine is missing the feedback loop that makes the system adaptive, and the XSS engine lacks the binary search decomposition and knowledge accumulation that enable systematic WAF bypass. Both engines operate as static payload generators rather than autonomous testing systems.

**Critical Gap:** The competitor's engines are autonomous loops that learn from each test. The current implementation generates payloads without feedback, making it a sophisticated wordlist generator rather than an intelligent testing system.

---

## SSRF Engine Gap Analysis

### Architecture Comparison

| Feature | Competitor (4-Phase) | Current Implementation | Status |
|---------|---------------------|----------------------|--------|
| Phase 1: Discovery | Feature-based detection (webhook, PDF, image processor) | None | **MISSING** |
| Phase 2: Target Selection | 49 cloud payloads, 30+ services, localhost admin paths | Basic cloud endpoints, 30+ services | **PARTIAL** |
| Phase 3: Bypass | Stack-specific ordering, 11 host forms, 20+ DNS names | 9 IP obfuscation, 8 parser confusion | **PARTIAL** |
| Phase 4: Confirm | OOB callbacks, timing analysis, response size analysis | Basic timing only | **MISSING** |
| Stack Detection | PHP, Python, Node.js, Java, Ruby, .NET, Go fingerprinting | None | **MISSING** |
| Feature Discovery | HTTPQL integration with Caido | None | **MISSING** |
| Header Injection | X-Forwarded-For, X-Forwarded-Host, Referer, X-Original-URL | None | **MISSING** |
| Impact Assessment | CVSS scoring (9.8 for cloud credentials) | None | **MISSING** |

### Missing Behaviors from Mermaid Diagrams

**Discovery Phase (from blog-enigma-ssrf-engine.html):**
```
- Path-based detection: /webhook, /proxy, /fetch, /redirect, /pdf, /import
- Parameter matching: url, callback, dest, source, proxy, forward
- Value heuristics: Contains http://, has domain, looks like URL
- Feature classification: Webhook (Priority 1), Proxy/Fetcher (Priority 1), PDF Generator (Priority 2), Image Processor (Priority 2)
```
**Current Implementation:** No discovery phase exists. Engine assumes target parameter is already known.

**Stack-Specific Bypass Ordering (from blog-enigma-ssrf-engine.html):**
```
- PHP: Fragment confusion, Authority confusion, Null byte injection
- Python: Backslash confusion, Unicode normalization, Fragment confusion
- Node.js: Unicode fullwidth, Protocol-relative, CRLF injection
- Java: IPv6 brackets, Fragment confusion, Authority confusion
- Ruby: open-uri redirect, Unicode normalization, Fragment confusion
- .NET: Unicode normalization, IPv6 brackets, Authority confusion
- Go: Fragment confusion, Unicode normalization, Authority confusion
```
**Current Implementation:** No stack detection or bypass ordering.

**Confirmation Phase (from blog-enigma-ssrf-engine.html):**
```
- OOB callbacks with 4 variants: Direct HTTP, DNS-only, Path-identified, Redirect chain
- Service-specific callbacks: Redis SLAVEOF, Elasticsearch snapshot
- Timing analysis: Statistical mean/stddev, internal IP timeout detection
- Response size analysis: 30%+ difference = high confidence, 15%+ = medium
- Multi-channel notifications: Slack, desktop, terminal, audio
```
**Current Implementation:** Only basic timing threshold (2x baseline).

### Bug List - SSRF Engine

| # | Severity | Bug | Impact |
|---|----------|-----|--------|
| S1 | **HIGH** | `generate_obfuscated_ip` returns None for IPv6 techniques without proper fallback | Payload generation silently fails for 127.0.0.1 and 169.254.169.254 IPv6 variants |
| S2 | **HIGH** | `detect_blind_ssrf` uses simple 2x threshold without statistical analysis | High false positive rate; no standard deviation calculation |
| S3 | **HIGH** | `analyze_response` only checks cloud indicators in body, not headers | Misses credential leaks in response headers |
| S4 | **MEDIUM** | `create_oob_callback` is a stub - no actual OOB server integration | Cannot confirm blind SSRF exploitation |
| S5 | **MEDIUM** | `check_callback` returns static data - no real callback checking | No feedback loop for payload effectiveness |
| S6 | **MEDIUM** | No payload deduplication | Same payload generated multiple times across phases |
| S7 | **MEDIUM** | No payload ordering by success probability | Suboptimal testing sequence |
| S8 | **LOW** | `generate_payloads` doesn't handle IPv6 targets | Only works with IPv4 addresses |
| S9 | **LOW** | `PARSER_CONFUSION` contains invalid payloads (e.g., overflow port 65536) | Some payloads are syntactically invalid |

---

## XSS Engine Gap Analysis

### Architecture Comparison

| Feature | Competitor (5-Rotor) | Current Implementation | Status |
|---------|---------------------|----------------------|--------|
| R1: Context Detection | 40+ patterns, probe-based detection | 7 context breaks | **PARTIAL** |
| R2: Blocker Detection | Binary search decomposition | None | **MISSING** |
| R3: Encoding | 10+ encoding layers with decode inference | 10 encodings | **ADEQUATE** |
| R4: Structure | Parentheses bypass cascade, DOM clobbering | Basic templates | **PARTIAL** |
| R5: Execution | 8+ auto-fire events, browser-specific vectors | 20 event handlers | **PARTIAL** |
| Knowledge Base | Accumulates from each test, prevents retry | None | **MISSING** |
| Partial Success Detection | Foothold tracking | None | **MISSING** |
| Browser Testing | Puppeteer with real DOM | None | **MISSING** |
| DOM Sink Hooks | 30+ intercepted APIs | None | **MISSING** |
| CSP Bypass | Multiple techniques | None | **MISSING** |

### Missing Behaviors from Mermaid Diagrams

**Binary Search Decomposition (from blog-enigma-xss-engine.html):**
```
- Decompose blocked payload into atomic components
- Test each component in isolation
- Require 2+ failures with 0 successes before marking as blocked
- Prevent false positives from network errors
- Infer broader patterns from component testing
```
**Current Implementation:** No binary search. Engine guesses what's blocked.

**Knowledge Accumulation (from blog-enigma-xss-engine.html):**
```
- Record what's blocked and what passes
- Infer patterns (if <img and <svg blocked, infer < is trigger)
- Never retry known-blocked patterns
- Build on footholds (partial successes)
- Navigate narrowing possibility space
```
**Current Implementation:** No knowledge base. Engine operates statelessly.

**Parentheses Bypass Cascade (from blog-enigma-xss-engine.html):**
```
- Backticks: alert`1`
- throw: throw onerror=alert,1
- valueOf coercion
- Symbol.hasInstance
- setInterval template
- Reflect.apply
- HTML entities: &lpar; &rpar;
- JSFuck (nuclear option)
```
**Current Implementation:** Only basic context adaptations, no parentheses bypass cascade.

**Pivot to Enumeration (from blog-enigma-xss-engine.html):**
```
- Trigger when 4+ common tags blocked
- Shift from mutation to systematic enumeration
- Tier 1: WAF bypass favorites
- Tier 2: Standard HTML5
- Tier 3: Deprecated/obscure
- Tier 4: Custom elements (infinite set, WAF can't blocklist)
```
**Current Implementation:** No enumeration mode or custom element support.

### Bug List - XSS Engine

| # | Severity | Bug | Impact |
|---|----------|-----|--------|
| X1 | **HIGH** | `_apply_mutation` doesn't properly handle all context types | CSS context returns attacker-controlled URL, not safe payload |
| X2 | **HIGH** | `autonomous_generate` generates excessive payloads without filtering | Thousands of redundant payloads, no intelligent selection |
| X3 | **HIGH** | `cascade_mutate` doesn't use knowledge base | Retries known-blocked patterns |
| X4 | **MEDIUM** | `record_success` stores data in memory only - no persistence | Learning lost between sessions |
| X5 | **MEDIUM** | No rate limiting or request throttling | May trigger WAF rate limits |
| X6 | **MEDIUM** | `WAF_BYPASSES` contains typos (e.g., `oneror` instead of `onerror`) | Bypass payloads are syntactically invalid |
| X7 | **MEDIUM** | `_encode_overlong_utf8` doesn't produce actual overlong sequences | UTF-8 encoding is incorrect |
| X8 | **LOW** | `PAYLOAD_TEMPLATES` missing some tag-specific templates | Falls back to basic template for unknown tags |
| X9 | **LOW** | No validation of generated payloads | May produce malformed HTML |

---

## Logic Visible in Mermaid Diagrams Not Implemented in Code

### SSRF Decision Map (from diagrams-complete-decision-map.html)

1. **Feature Detection Flow:** The diagram shows feature-based discovery (webhook, proxy, PDF, image, import, redirect) feeding into parameter matching. The implementation has no discovery phase.

2. **Stack Fingerprinting:** The diagram shows stack detection (PHP, Python, Node, Java, Ruby, .NET, Go) determining bypass priority. The implementation has no stack detection.

3. **Confirmation Feedback Loop:** The diagram shows OOB callback, timing, and content analysis feeding back into the bypass phase. The implementation has no feedback loop.

4. **Impact Assessment:** The diagram shows automatic CVSS scoring based on what was leaked (cloud credentials = 9.8, internal services = 8.6, metadata = 7.5). The implementation has no impact assessment.

### XSS Decision Map (from diagrams-complete-decision-map.html)

1. **Binary Search Flow:** The diagram shows blocked payloads being decomposed and tested component-by-component. The implementation has no decomposition.

2. **Blocker Inference:** The diagram shows inferring broader patterns from component testing (if <img and <svg blocked, infer < is trigger). The implementation has no inference.

3. **Partial Success Tracking:** The diagram shows "footholds" being tracked and built upon. The implementation has no foothold tracking.

4. **Pivot Decision:** The diagram shows a decision point where the engine switches from mutation to enumeration when 4+ tags are blocked. The implementation has no pivot logic.

5. **Custom Element Enumeration:** The diagram shows Tier 4 custom elements as a secret weapon against blocklist WAFs. The implementation has no custom element support.

---

## Proposed Fixes (Prioritized by Value)

### Priority 1: Critical Missing Behaviors

**1.1 Add Binary Search Decomposition to XSS Engine**
- Decompose blocked payloads into atomic components
- Test each component in isolation
- Build knowledge base of what's blocked
- Prevent retries of known-blocked patterns

**1.2 Add Feedback Loop to SSRF Engine**
- Implement real OOB callback verification
- Add statistical timing analysis (mean, stddev)
- Add response size differential analysis
- Record what works and what doesn't

**1.3 Add Stack Detection to SSRF Engine**
- Fingerprint server technology from headers
- Implement stack-specific bypass ordering
- Prioritize techniques most likely to work

### Priority 2: Missing Features

**2.1 Add Discovery Phase to SSRF Engine**
- Feature-based detection (webhook, PDF, image processor)
- HTTPQL integration for traffic analysis
- Parameter name matching

**2.2 Add Knowledge Accumulation to XSS Engine**
- Persistent storage of test results
- Pattern inference from blocked components
- Foothold tracking for partial successes

**2.3 Add Header Injection Testing to SSRF Engine**
- X-Forwarded-For, X-Forwarded-Host
- Referer, X-Original-URL, X-Rewrite-URL
- Baseline comparison for each header

### Priority 3: Bug Fixes

**3.1 Fix SSRF IP Obfuscation Bugs**
- Handle IPv6 techniques properly
- Add fallback for failed obfuscations
- Validate generated payloads

**3.2 Fix XSS Mutation Bugs**
- Fix CSS context handling
- Fix overlong UTF-8 encoding
- Fix WAF bypass typos

**3.3 Add Payload Validation**
- Validate generated payloads are syntactically correct
- Remove invalid payloads from output
- Deduplicate payloads

---

## Implementation Recommendations

### Phase 1: Core Autonomous Behaviors (1-2 weeks)

1. Implement binary search decomposition for XSS engine
2. Add knowledge base with persistent storage
3. Implement real OOB callback verification for SSRF
4. Add statistical timing analysis

### Phase 2: Missing Features (2-3 weeks)

1. Add stack detection and bypass ordering
2. Implement discovery phase for SSRF
3. Add header injection testing
4. Implement payload deduplication and ordering

### Phase 3: Polish and Edge Cases (1 week)

1. Fix all identified bugs
2. Add payload validation
3. Add error handling
4. Add comprehensive test coverage

---

## Conclusion

The current implementation provides a solid foundation of payload generation techniques but lacks the autonomous behaviors that make the competitor's engines effective. The most critical gaps are:

1. **No feedback loop** - Both engines operate statelessly
2. **No binary search** - XSS engine guesses what's blocked
3. **No knowledge accumulation** - Learning is lost between sessions
4. **No stack detection** - SSRF engine uses same techniques for all targets

Implementing the Priority 1 fixes would transform these from sophisticated wordlist generators into truly autonomous testing systems.
