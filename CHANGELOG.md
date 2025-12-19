# Changelog

All notable changes to this project will be documented in this file.

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
