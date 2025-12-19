# Changelog

All notable changes to this project will be documented in this file.

## [1.1.12] - 2024-12-19

### Changed
- Route ALL API requests through FlareSolverr, not just initial cookie fetch
- Bypasses TLS fingerprinting by using FlareSolverr's real Chrome browser for every request
- Each API call now goes through FlareSolverr with proper cookie persistence

### Fixed
- 403 Forbidden on second API request caused by httpx TLS fingerprint detection

## [1.1.11] - 2024-12-19

### Fixed
- Removed Accept-Encoding header that caused gzip decode errors
- httpx handles compression automatically; explicit header caused raw bytes to be parsed as JSON
- Fixes "'utf-8' codec can't decode byte 0x9b" error

## [1.1.10] - 2024-12-19

### Fixed
- Added browser-like headers (Origin, Referer, Sec-Fetch-*, etc.) to HTTP requests
- Claude's API validates these headers to detect non-browser requests
- Fixes 403 Forbidden that occurred even with valid cookies

## [1.1.9] - 2024-12-19

### Fixed
- Pass sessionKey cookie to FlareSolverr during Cloudflare bypass
- Ensures cf_clearance is generated for logged-in session, not anonymous
- Fixes 403 Forbidden on second API request after first succeeds

## [1.1.8] - 2024-12-19

### Fixed
- Corrected API endpoint: use `claude.ai/api/` instead of non-existent `api.claude.ai`
- Fixes DNS resolution error "[Errno -2] Name or service not known"

## [1.1.7] - 2024-12-19

### Changed
- Replaced Playwright browser automation with direct HTTP requests
- Uses FlareSolverr cookies directly with httpx for API calls
- Removed Playwright dependency (image now ~300MB smaller)
- Removed shm_size requirement from docker-compose

### Fixed
- "Failed to fetch" error caused by cross-origin browser restrictions
- Simplified architecture: FlareSolverr cookies + httpx instead of Playwright

## [1.1.6] - 2024-12-19

### Fixed
- Cookie domain normalization for API subdomain compatibility
- Ensures all cookies from FlareSolverr use `.claude.ai` domain (with leading dot)
- Fixes "Failed to fetch" error when calling api.claude.ai from claude.ai page context

## [1.1.5] - 2024-12-19

### Fixed
- FlareSolverr URL auto-normalization: automatically appends /v1 if missing
- Fixes 405 Method Not Allowed when FLARESOLVERR_URL is set without /v1 path

## [1.1.4] - 2024-12-19

### Added
- FlareSolverr integration for automatic Cloudflare challenge bypass
- FLARESOLVERR_URL environment variable (default: http://flaresolverr:8191/v1)
- Detection for Cloudflare challenge_redirect with helpful error message

### Changed
- Browser initialization now gets cookies from FlareSolverr before launching Playwright
- Uses FlareSolverr's user agent for consistent browser fingerprint
- Simplified _get_org_id() navigation flow

## [1.1.3] - 2024-12-19

### Added
- Comprehensive verbose logging throughout all operations
- Tagged log messages: [BROWSER], [CLAUDE API], [TRILIUM], [SYNC], [CONFIG], [MODE]
- Request/response logging for all API calls (>>> for requests, <<< for responses)
- Progress tracking for conversation fetching and syncing
- Configuration dump at startup showing all settings
- Phase markers for sync cycle (Phase 1: Fetch, Phase 2: Sync)
- Detailed hash comparison logging for change detection

## [1.1.2] - 2024-12-19

### Fixed
- API 403 Forbidden error by using correct API subdomain (api.claude.ai instead of claude.ai)

## [1.1.1] - 2024-12-19

### Fixed
- Navigation timeout by switching from `networkidle` to `domcontentloaded` wait condition
- Increased navigation timeout from 30s to 60s for slower connections

### Added
- Verbose debug logging throughout Playwright operations
- Logging for browser init, cookie injection, navigation, and API requests
- 2-second stabilization wait after page load for JS initialization

## [1.1.0] - 2024-12-19

### Changed
- Replaced direct HTTP API calls with Playwright browser automation
- This bypasses Claude.ai's API protections that were causing 403 errors
- Converted application to async/await pattern for Playwright compatibility

### Added
- Playwright dependency for headless browser automation
- Session detection for expired login redirects
- shm_size configuration in docker-compose for Chrome stability

### Technical
- ClaudeAPI class now uses Playwright to make API calls from browser context
- API requests made via page.evaluate() inherit all cookies and security context
- Docker image now includes Chromium browser (~300MB larger)

## [1.0.0] - 2024-12-19

### Added
- Initial release of Claude to Trilium Notes sync
- Automatic sync of Claude.ai conversations to Trilium Notes
- Session key authentication with Claude.ai API
- ETAPI integration with Trilium Notes
- Content hashing for incremental sync (only sync changed conversations)
- Parent note organization with labels
- Pushover notifications for session expiry and errors
- Docker support with persistent state volume

### Features
- Retry logic with exponential backoff for transient API failures
- Atomic state file saves to prevent data corruption
- Markdown to HTML conversion:
  - Code blocks with syntax highlighting
  - Inline code
  - Bold and italic text
  - Headers (h2, h3, h4)
  - Links
  - Unordered and ordered lists
- Color-coded messages (blue for human, green for Claude)
- Configurable sync interval (one-shot or continuous mode)
