# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-02-17

### Changed
- Rewrote artifact extraction to use `files_v2` field instead of parsing `<antArtifact>` XML tags
  - Claude API does not include artifact XML tags in message text, even with `rendering_mode=raw`
  - Artifacts (sandbox output files) are now discovered via the `files_v2` field on each message
  - Artifact files are downloaded via the wiggle endpoint (`/wiggle/download-file`)
  - Text-based artifacts (.py, .md, .html, etc.) are saved as code-type notes in Trilium
  - Binary artifacts are saved as file-type notes with proper MIME types
  - Artifacts are identified by `file_uuid` for deduplication (replaces XML `identifier`)
  - New label `claudeArtifactPath` stores the original sandbox path for reference

### Added
- `get_artifact_file()` method on `ClaudeAPI` for downloading files via wiggle endpoint
  - Tries FlareSolverr first, falls back to direct httpx request with session cookie
- `get_mime_from_filename()` helper to determine MIME type from file extension
- `is_text_file()` helper to distinguish text vs binary artifact files

### Removed
- `parse_artifacts()` function (no longer needed; artifacts are not in message text)
- `strip_artifact_tags()` function and its call in `_format_message_content()`
- `rendering_mode=raw` query parameter from `get_conversation()` endpoint
- Diagnostic logging added in v1.4.2 (no longer needed after root cause identified)

## [1.4.2] - 2026-02-17

### Fixed
- Add diagnostic logging to inspect message structure from Claude API
  - Logs all message keys to identify where artifact data is stored
  - Logs non-standard fields (content blocks, metadata) with type info
  - Logs all conversation response keys (previously truncated at 10)
  - Will reveal whether artifacts are in `content` blocks, a separate field, or elsewhere

## [1.4.1] - 2026-02-17

### Fixed
- Add `rendering_mode=raw` query parameter to `get_conversation()` API call
  - Claude API strips `<antArtifact>` XML tags from message text by default
  - Without `rendering_mode=raw`, artifact extraction found zero artifacts across all conversations
  - The raw rendering mode returns the original model output with artifact tags inline
- Add debug logging to confirm artifact tag presence in message text after fix

## [1.4.0] - 2026-02-17

### Added
- Artifact extraction and sync from Claude conversations
  - Parses `<antArtifact>` XML tags embedded in Claude's message text
  - Each artifact is saved as a code-type child note under the conversation
  - Artifacts preserve original content with proper MIME types and file extensions
  - Supports all artifact types: React (`.jsx`), HTML, Markdown, SVG, Mermaid, code in 40+ languages
  - Artifacts are labeled with `claudeArtifact`, `claudeArtifactId`, `claudeArtifactType`, and `claudeArtifactLanguage`
  - Existing artifacts are updated in-place on re-sync (matched by identifier)
  - Artifact XML tags are replaced with `[Artifact: title]` placeholders in the conversation HTML
  - New helper functions: `parse_artifacts()`, `strip_artifact_tags()`, `get_artifact_extension()`, `get_artifact_mime()`

## [1.3.0] - 2026-01-30

### Added
- Download actual file content for attachments from Claude API
  - Attachments with downloadable content are now stored as file-type notes in Trilium
  - Files preserve original binary content, not just metadata
  - Falls back to text notes with metadata when content cannot be downloaded
  - New `get_attachment_content()` method in ClaudeAPI for fetching file data

### Changed
- `sync_conversation()` and `_sync_attachments()` are now async methods
- Claude API client is kept open during sync to enable attachment downloads
- Logging now shows count of attachments downloaded with content

## [1.2.4] - 2026-01-30

### Fixed
- Fix duplicate notes created instead of updating existing ones
  - Changed `patch_note_content()` to `update_note_content()` for trilium-py compatibility
  - Updates to existing conversations now correctly modify the existing Trilium note

## [1.2.3] - 2026-01-19

### Fixed
- Remove empty code blocks left after filtering unsupported block text
  - Handles markdown code fences that become empty after text removal
  - Collapses multiple empty lines to prevent rendering artifacts

## [1.2.2] - 2026-01-19

### Fixed
- Empty grey boxes no longer appear after filtering unsupported blocks
  - Collapse consecutive empty lines left behind after filtering

## [1.2.1] - 2026-01-19

### Added
- Filter out "This block is not supported on your current device yet." placeholder text from messages
  - Removes grey placeholder boxes that appear for tool use blocks (web searches, artifacts, etc.)
  - Filtering applied before HTML conversion for clean output in Trilium notes
  - Hash computation also filters this text to avoid unnecessary re-syncs

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
