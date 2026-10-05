# Changelog

## [Unreleased]

### Added
- Machine batch payload command (`cli/commands/payloads.ts`, bin `enigma-payloads`) — deterministic JSON candidates per context for the Mastermind-Ai Python bridge (`mastermind_core/enigma_bridge.py`)
- SSRF network scanning with port and service identification
- XSS CSP bypass cascade expansion (6 → 13 techniques)
- XSS learning loop feedback integration
- XSS pivot-to-enumeration with event prioritization
- SSRF header injection runner integration
- Comprehensive security audit test suite
- XSS AngularJS version-aware escape module (`core/engines/mutation/angular.ts`) — 10 version-differential sandbox escapes with `detectAngularVersion()` and `selectAngularEscapes()`
- XSS CSP policy parser (`core/engines/mutation/csp.ts`) — `parseCspHeader()`, `summarizeCsp()`, `selectCspBypassStrategies()` with 3 directive-aware bypass strategies (trusted_types_bypass, strict_dynamic_bypass, extracted_nonce_reuse) and `scrapeDomNonceScript()` for live DOM nonce extraction
- XSS mXSS parser-differential detector (`core/engines/mutation/mxss.ts`) — 7 canonical mXSS vectors, `buildMxssDetectionScript()`, `analyzeMxss()`
- Multi-step stored XSS workflow engine (`core/runner/workflow.ts`) — `StoredXssStage` interface, `validateWorkflow()`, `transformPayload()`, `buildProfileAdminEmailChain()`
- MutationComposer integration of Angular/CSP/mXSS — `setCspRawHeader()`, `setAngularVersion()`, Angular escape candidates in `nextCandidates()`, mXSS vector candidates for HTML contexts, 3 new CSP bypass cases in `_payloadForCspBypass()`
- Runner integration of mXSS + workflow — `buildMxssDetectionScript` injection, `setCspRawHeader()`, Angular version detection, `executeWorkflow()` method
- Test files: `tests/angular.test.ts`, `tests/csp.test.ts`, `tests/mxss.test.ts`, `tests/workflow.test.ts`
- Tsai parser-confusion bypasses: multi-@-with-port, extra-colon port, Glibc NSS whitespace, RFC1035 decimal DNS, fullwidth CRLF, IDNA ZWJ, IPv6 ambiguity
- Tsai decimal `0` faraday bypass in ip-obfuscation.ts
- Heyes Ch.8 auto-fire events: onunhandledrejection, onpopstate, onhashchange, onmessage, onfocusin, ontransitioncancel, onwebkittransitionend, onbeforescriptexecute, animate onend
- Heyes Ch.4 DOM clobber gadgets: 3-level form, attributes, nodeName, getElementById dup-body, querySelector dup-body, iframe srcdoc nested chain

### Fixed
- SSRF expandSubnetHosts IP overflow at 255 boundary
- SSRF ContentMatcher.getConfirmationLevel requiring multiple medium matches
- XSS blocker inference contradictory conditions
- CSP parser — simplified to semicolon-based splitting (replaced complex regex that failed on single-directive headers)
- CSP nonce detection — stripped surrounding quotes before `nonce-` prefix matching (fixes `selectCspBypassStrategies` returning empty for valid CSP with nonces)
- Import paths in `tests/mutation-csp-bypass.test.ts` and `tests/ssrf-network-scan.test.ts` (missing `.ts` extension)

### Changed
- SSRF blind watch mode enhanced with token-based correlation pattern
- Test suite: 199 → 251 tests (all passing)
