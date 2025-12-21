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
- Initial release
- Sync Claude.ai conversations to Trilium Notes
- Content hash-based change detection for efficient incremental syncs
- Persistent state tracking via JSON file
- Pushover notifications for session expiry and errors
- Docker support with bind mount for state persistence
- Configurable sync interval (continuous or one-shot mode)
- Markdown to HTML conversion with code highlighting
