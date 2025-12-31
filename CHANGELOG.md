# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2025-12-30

### Fixed
- Fixed duplicate notes bug when continuing conversations
  - Changed `patch_note_content()` to `update_note_content()` (correct trilium-py method name)
  - Previously, continued conversations would create new notes instead of updating existing ones

### Added
- Attachment file download support
  - Attachments are now downloaded as actual files instead of just metadata
  - Creates file-type notes in Trilium with proper MIME types
  - Falls back to text notes with metadata if download fails
  - New `get_attachment_content()` method in ClaudeAPI for fetching file content via FlareSolverr

## [1.1.0] - 2025-12-23

### Added
- Attachment support: Claude message attachments are now saved as child notes under the conversation
  - Each attachment creates a child note with extracted content (if available)
  - Attachments are labeled with `claudeAttachment` and `claudeAttachmentFileName` for easy identification
  - Duplicate attachments are skipped on sync updates

### Fixed
- Improved list formatting in markdown to HTML conversion
  - Blank lines between list items no longer break the list grouping
  - Ordered lists (1. 2. 3.) now properly render with `<ol>` tags instead of `<ul>`
  - Mixed list types are handled correctly
  - List items no longer get spurious `<br/>` tags added

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
