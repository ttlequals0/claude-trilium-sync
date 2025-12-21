# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2025-12-21

### Fixed
- Added `isInheritable=False` to all `create_attribute()` calls for explicit trilium-py API compatibility
- Added Trilium-side deduplication check to prevent duplicate notes when state file is lost
  - New `find_note_by_conversation_id()` method queries Trilium for existing notes by `claudeConversationId` label
  - If state file has no record but Trilium has the note, sync will update instead of creating duplicates

## [1.0.0] - 2025-12-19

### Added
- Initial release of Claude to Trilium Notes sync
- Automatic sync of Claude.ai conversations to Trilium Notes
- FlareSolverr integration for Cloudflare bypass (routes all requests through real Chrome browser)
- Session key authentication with Claude.ai API
- ETAPI integration with Trilium Notes
- Content hashing for incremental sync (only sync changed conversations)
- Parent note organization with labels
- Pushover notifications for session expiry and errors
- Docker support with persistent state volume
- Comprehensive verbose logging with tagged messages ([FLARESOLVERR], [CLAUDE API], [TRILIUM], [SYNC], [CONFIG])

### Features
- Retry logic with exponential backoff for transient API failures
- Atomic state file saves to prevent data corruption
- FlareSolverr URL auto-normalization (appends /v1 if missing)
- Improved organization selection (prefers non-Individual orgs)
- Markdown to HTML conversion:
  - Code blocks with syntax highlighting
  - Inline code
  - Bold and italic text
  - Headers (h2, h3, h4)
  - Links
  - Unordered and ordered lists
- Clean message formatting with horizontal line separators
- Configurable sync interval (one-shot or continuous mode)
