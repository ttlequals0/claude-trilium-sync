#!/usr/bin/env python3
"""
Claude Chat to Trilium Notes Sync

Automatically syncs Claude.ai conversations to Trilium Notes.
- Uses Playwright browser automation to access Claude API
- Tracks sync state to only process new/updated chats
- Merges updates into existing Trilium notes

Environment Variables:
    TRILIUM_URL: Trilium server URL (default: http://localhost:8080)
    TRILIUM_TOKEN: ETAPI token from Trilium
    CLAUDE_SESSION_KEY: sessionKey cookie value from claude.ai
    STATE_FILE: Path to sync state file (default: /data/state.json)
    SYNC_INTERVAL: Seconds between syncs, 0 for one-shot (default: 0)
    LOG_LEVEL: Logging level (default: INFO)

    PARENT_NOTE_ID: Trilium note ID to use as parent (optional)
    PARENT_NOTE_TITLE: Title for auto-created parent note (default: Claude Chats)

    PUSHOVER_USER_KEY: Pushover user key for notifications (optional)
    PUSHOVER_API_TOKEN: Pushover application token (optional)
    PUSHOVER_DEVICE: Specific device to notify (optional)

    FLARESOLVERR_URL: FlareSolverr endpoint for Cloudflare bypass (default: http://flaresolverr:8191/v1)
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from trilium_py.client import ETAPI

from version import get_version

# Configuration from environment
CONFIG = {
    "trilium_url": os.environ.get("TRILIUM_URL", "http://localhost:8080"),
    "trilium_token": os.environ.get("TRILIUM_TOKEN", ""),
    "claude_session_key": os.environ.get("CLAUDE_SESSION_KEY", ""),
    "state_file": os.environ.get("STATE_FILE", "/data/state.json"),
    "sync_interval": int(os.environ.get("SYNC_INTERVAL", "0")),
    "log_level": os.environ.get("LOG_LEVEL", "INFO"),

    # Parent note configuration
    "parent_note_id": os.environ.get("PARENT_NOTE_ID", ""),
    "parent_note_title": os.environ.get("PARENT_NOTE_TITLE", "Claude Chats"),
    "parent_note_label": "claudeChatsRoot",

    # Pushover notifications
    "pushover_user_key": os.environ.get("PUSHOVER_USER_KEY", ""),
    "pushover_api_token": os.environ.get("PUSHOVER_API_TOKEN", ""),
    "pushover_device": os.environ.get("PUSHOVER_DEVICE", ""),

    # FlareSolverr for Cloudflare bypass
    "flaresolverr_url": os.environ.get("FLARESOLVERR_URL", "http://flaresolverr:8191/v1"),
}

# Unsupported block placeholder text to filter out
UNSUPPORTED_BLOCK_TEXT = "This block is not supported on your current device yet."

# Setup logging
logging.basicConfig(
    level=getattr(logging, CONFIG["log_level"]),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
log = logging.getLogger(__name__)


def filter_unsupported_blocks(text: str) -> str:
    """Remove 'unsupported block' placeholder lines from text.

    Filters out lines containing the placeholder text that appears
    when Claude's tool use blocks can't be rendered. Also removes
    empty code blocks and collapses consecutive empty lines.
    """
    if not text or UNSUPPORTED_BLOCK_TEXT not in text:
        return text

    lines = text.split("\n")
    filtered_lines = [
        line for line in lines
        if UNSUPPORTED_BLOCK_TEXT not in line
    ]

    # Collapse multiple consecutive empty lines into one
    result = []
    prev_empty = False
    for line in filtered_lines:
        is_empty = line.strip() == ""
        if is_empty and prev_empty:
            continue  # Skip consecutive empty lines
        result.append(line)
        prev_empty = is_empty

    text = "\n".join(result)

    # Remove empty code blocks (``` followed by ``` with only whitespace between)
    text = re.sub(r"```\w*\s*```", "", text)

    # Clean up any resulting multiple empty lines again
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def parse_artifacts(text: str) -> list[dict]:
    """Parse antArtifact/artifact XML tags from message text.

    Claude.ai embeds artifacts inline in the message text as XML tags like:
        <antArtifact identifier="..." type="..." title="..." language="...">
            content here
        </antArtifact>

    Returns a list of dicts with keys: identifier, type, title, language, content.
    """
    if not text:
        return []

    artifacts = []

    # Match both <antArtifact> and <artifact> tag variants
    pattern = re.compile(
        r'<(?:ant[Aa]rtifact|antartifact|artifact)\s+'
        r'(?P<attrs>[^>]*?)>'
        r'(?P<content>.*?)'
        r'</(?:ant[Aa]rtifact|antartifact|artifact)>',
        re.DOTALL | re.IGNORECASE,
    )

    for match in pattern.finditer(text):
        attrs_str = match.group("attrs")
        content = match.group("content").strip()

        # Parse attributes
        def get_attr(name: str) -> str:
            attr_match = re.search(rf'{name}\s*=\s*"([^"]*)"', attrs_str)
            return attr_match.group(1) if attr_match else ""

        artifact = {
            "identifier": get_attr("identifier"),
            "type": get_attr("type"),
            "title": get_attr("title"),
            "language": get_attr("language"),
            "content": content,
        }
        artifacts.append(artifact)

    return artifacts


def strip_artifact_tags(text: str) -> str:
    """Replace artifact XML tags with a placeholder reference in the message text."""
    if not text:
        return text

    def replacer(match):
        attrs_str = match.group(1)
        title_match = re.search(r'title\s*=\s*"([^"]*)"', attrs_str)
        title = title_match.group(1) if title_match else "Artifact"
        return f"\n\n[Artifact: {title}]\n\n"

    text = re.sub(
        r'<(?:ant[Aa]rtifact|antartifact|artifact)\s+([^>]*?)>.*?</(?:ant[Aa]rtifact|antartifact|artifact)>',
        replacer,
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return text


# Map artifact type to file extension
ARTIFACT_TYPE_EXTENSIONS = {
    "application/vnd.ant.react": ".jsx",
    "application/vnd.ant.code": "",  # uses language attr
    "text/markdown": ".md",
    "text/html": ".html",
    "image/svg+xml": ".svg",
    "application/vnd.ant.mermaid": ".mermaid",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "application/json": ".json",
    "application/xml": ".xml",
    "application/x-latex": ".tex",
    "text/vnd.graphviz": ".dot",
}

# Map language attribute to file extension
LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "jsx": ".jsx",
    "tsx": ".tsx",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "csharp": ".cs",
    "c#": ".cs",
    "go": ".go",
    "rust": ".rs",
    "ruby": ".rb",
    "php": ".php",
    "swift": ".swift",
    "kotlin": ".kt",
    "scala": ".scala",
    "shell": ".sh",
    "bash": ".sh",
    "sql": ".sql",
    "yaml": ".yaml",
    "yml": ".yaml",
    "toml": ".toml",
    "html": ".html",
    "css": ".css",
    "scss": ".scss",
    "lua": ".lua",
    "r": ".r",
    "perl": ".pl",
    "haskell": ".hs",
    "elixir": ".ex",
    "clojure": ".clj",
    "dart": ".dart",
    "zig": ".zig",
    "dockerfile": ".Dockerfile",
    "makefile": ".Makefile",
    "graphql": ".graphql",
    "proto": ".proto",
    "terraform": ".tf",
    "nix": ".nix",
}


def get_artifact_extension(artifact: dict) -> str:
    """Determine file extension for an artifact based on type and language."""
    art_type = artifact.get("type", "")
    language = artifact.get("language", "").lower()

    # For code type, prefer language-based extension
    if art_type == "application/vnd.ant.code" and language:
        return LANGUAGE_EXTENSIONS.get(language, f".{language}")

    # Otherwise use type-based extension
    ext = ARTIFACT_TYPE_EXTENSIONS.get(art_type, "")
    if ext:
        return ext

    # Fallback: try language if available
    if language:
        return LANGUAGE_EXTENSIONS.get(language, f".{language}")

    return ".txt"


def get_artifact_mime(artifact: dict) -> str:
    """Determine MIME type for an artifact for Trilium file notes."""
    art_type = artifact.get("type", "")
    language = artifact.get("language", "").lower()

    # Direct MIME types
    if art_type in ("text/html", "text/markdown", "text/plain", "text/csv",
                     "application/json", "application/xml", "image/svg+xml"):
        return art_type

    # Code types
    if art_type in ("application/vnd.ant.code", "application/vnd.ant.react"):
        if art_type == "application/vnd.ant.react":
            return "application/javascript"
        if language in ("python",):
            return "text/x-python"
        if language in ("javascript", "jsx"):
            return "application/javascript"
        if language in ("typescript", "tsx"):
            return "application/typescript"
        return "text/plain"

    return "text/plain"


class PushoverNotifier:
    """Send notifications via Pushover."""

    API_URL = "https://api.pushover.net/1/messages.json"

    def __init__(self, user_key: str, api_token: str, device: str = ""):
        self.user_key = user_key
        self.api_token = api_token
        self.device = device
        self.enabled = bool(user_key and api_token)

        if not self.enabled:
            log.debug("Pushover notifications disabled (no credentials)")

    def send(
        self,
        message: str,
        title: str = "Claude-Trilium Sync",
        priority: int = 0,
        url: str = "",
        url_title: str = "",
    ) -> bool:
        """Send a Pushover notification."""
        if not self.enabled:
            return False

        payload = {
            "token": self.api_token,
            "user": self.user_key,
            "message": message,
            "title": title,
            "priority": priority,
        }

        if self.device:
            payload["device"] = self.device
        if url:
            payload["url"] = url
            if url_title:
                payload["url_title"] = url_title

        try:
            resp = httpx.post(self.API_URL, data=payload, timeout=10.0)
            resp.raise_for_status()
            log.debug(f"Pushover notification sent: {title}")
            return True
        except Exception as e:
            log.warning(f"Failed to send Pushover notification: {e}")
            return False

    def notify_session_expired(self):
        """Send a session expired notification."""
        return self.send(
            message="Claude session key has expired. Update CLAUDE_SESSION_KEY to resume syncing.",
            title="Claude Session Expired",
            priority=1,
            url="https://claude.ai",
            url_title="Open Claude to get new session key",
        )

    def notify_error(self, error: str):
        """Send a generic error notification."""
        return self.send(
            message=f"Sync error: {error}",
            title="Claude-Trilium Sync Error",
            priority=0,
        )


# Global notifier instance
notifier = PushoverNotifier(
    CONFIG["pushover_user_key"],
    CONFIG["pushover_api_token"],
    CONFIG["pushover_device"],
)


class SyncState:
    """Tracks which conversations have been synced and their content hashes."""

    def __init__(self, state_file: str):
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            with open(self.state_file) as f:
                return json.load(f)
        return {"conversations": {}, "last_sync": None}

    def save(self):
        """Save state atomically by writing to temp file then renaming."""
        temp_file = self.state_file.with_suffix(".tmp")
        with open(temp_file, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        temp_file.replace(self.state_file)

    def get_conversation_hash(self, conv_id: str) -> Optional[str]:
        return self.data["conversations"].get(conv_id, {}).get("content_hash")

    def get_trilium_note_id(self, conv_id: str) -> Optional[str]:
        return self.data["conversations"].get(conv_id, {}).get("trilium_note_id")

    def update_conversation(self, conv_id: str, content_hash: str, trilium_note_id: str):
        self.data["conversations"][conv_id] = {
            "content_hash": content_hash,
            "trilium_note_id": trilium_note_id,
            "last_synced": datetime.now(timezone.utc).isoformat(),
        }
        self.data["last_sync"] = datetime.now(timezone.utc).isoformat()
        self.save()


class ClaudeAPI:
    """HTTP client for Claude.ai API using FlareSolverr for all requests.

    All API requests go through FlareSolverr's real browser to bypass
    TLS fingerprinting and other bot detection mechanisms.
    """

    BASE_URL = "https://claude.ai"

    def __init__(self, session_key: str):
        self.session_key = session_key
        self._org_id: Optional[str] = None
        self._flaresolverr_url: Optional[str] = None
        self._cookies: Optional[list] = None

    def _get_flaresolverr_url(self) -> str:
        """Get normalized FlareSolverr URL."""
        if self._flaresolverr_url:
            return self._flaresolverr_url

        # Normalize FlareSolverr URL - ensure it ends with /v1
        url = CONFIG['flaresolverr_url'].rstrip('/')
        if not url.endswith('/v1'):
            url = f"{url}/v1"
        self._flaresolverr_url = url
        return url

    async def _flaresolverr_request(self, url: str) -> dict:
        """Make a request through FlareSolverr's real browser.

        This bypasses TLS fingerprinting by using FlareSolverr's Chrome browser
        for all requests, not just the initial Cloudflare challenge.
        """
        flaresolverr_url = self._get_flaresolverr_url()

        # Build cookies list - always include sessionKey
        cookies = [{"name": "sessionKey", "value": self.session_key}]

        # Add any cookies from previous requests
        if self._cookies:
            for cookie in self._cookies:
                if cookie.get("name") != "sessionKey":  # Don't duplicate
                    cookies.append(cookie)

        log.info(f"[FLARESOLVERR] >>> GET {url}")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                flaresolverr_url,
                json={
                    "cmd": "request.get",
                    "url": url,
                    "maxTimeout": 60000,
                    "cookies": cookies
                },
                timeout=90.0
            )
            data = response.json()

        status = data.get("status")

        if status != "ok":
            error_msg = data.get("message", "Unknown error")
            log.error(f"[FLARESOLVERR] <<< Error: {error_msg}")
            raise ValueError(f"FlareSolverr error: {error_msg}")

        solution = data["solution"]

        # Store cookies for subsequent requests
        self._cookies = solution.get("cookies", [])

        # Get response details
        response_status = solution.get("status", 0)
        response_body = solution.get("response", "")

        log.info(f"[FLARESOLVERR] <<< Status: {response_status}")

        return {
            "status": response_status,
            "body": response_body,
            "cookies": self._cookies
        }

    async def _api_request(self, endpoint: str) -> dict:
        """Make an API request through FlareSolverr."""
        full_url = f"{self.BASE_URL}/api{endpoint}"

        response = await self._flaresolverr_request(full_url)
        status_code = response.get("status", 0)
        body = response.get("body", "")

        log.info(f"[CLAUDE API] <<< HTTP Status: {status_code}")

        if status_code == 403:
            log.error("[CLAUDE API] <<< 403 Forbidden - Cloudflare or auth issue")
            raise ValueError(f"HTTP 403: Access denied - check session key or Cloudflare bypass")

        if status_code == 401:
            log.error("[CLAUDE API] <<< 401 Unauthorized - Session expired")
            raise ValueError("Session expired - please update CLAUDE_SESSION_KEY")

        if status_code >= 400:
            raise ValueError(f"HTTP {status_code}: Request failed")

        # Parse JSON response from the HTML body
        # FlareSolverr returns the page content, which for API endpoints is JSON
        try:
            result = json.loads(body)
        except json.JSONDecodeError:
            # Try to extract JSON from HTML if wrapped
            json_match = re.search(r'<pre[^>]*>(.*?)</pre>', body, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group(1))
            else:
                log.error(f"[CLAUDE API] <<< Failed to parse response: {body[:200]}...")
                raise ValueError("Failed to parse API response as JSON")

        # Check for error response
        if isinstance(result, dict) and "error" in result:
            error_type = result.get("type", "unknown")
            error_msg = result.get("error", {})
            if isinstance(error_msg, dict):
                error_msg = error_msg.get("message", str(error_msg))
            log.error(f"[CLAUDE API] <<< API Error ({error_type}): {error_msg}")
            raise ValueError(f"Claude API error: {error_msg}")

        # Log response info
        if isinstance(result, list):
            log.info(f"[CLAUDE API] <<< Response: {len(result)} items returned")
            if result and len(result) > 0:
                first_item = result[0]
                if isinstance(first_item, dict):
                    keys = list(first_item.keys())[:5]
                    log.info(f"[CLAUDE API] <<< Item keys: {keys}")
                else:
                    log.info(f"[CLAUDE API] <<< First item type: {type(first_item).__name__}")
                    log.info(f"[CLAUDE API] <<< First item preview: {str(first_item)[:100]}")
        elif isinstance(result, dict):
            keys = list(result.keys())[:10]
            log.info(f"[CLAUDE API] <<< Response: dict with keys: {keys}")

        return result

    async def _get_org_id(self) -> str:
        """Get the organization ID for the authenticated user."""
        if self._org_id:
            log.info(f"[CLAUDE API] Using cached organization ID: {self._org_id}")
            return self._org_id

        log.info("[CLAUDE API] Fetching organization ID...")
        orgs = await self._api_request("/organizations")

        if not orgs:
            log.error("[CLAUDE API] No organizations returned!")
            raise ValueError("No organizations found for this account")

        # Log all available organizations
        log.info(f"[CLAUDE API] Found {len(orgs)} organizations:")
        for i, org in enumerate(orgs):
            org_name = org.get("name", "Unknown")
            org_id = org.get("uuid", "Unknown")
            caps = org.get("capabilities", [])
            log.info(f"[CLAUDE API]   [{i}] {org_name} (ID: {org_id})")
            log.info(f"[CLAUDE API]       Capabilities: {caps[:5]}...")

        # Try to find an org with chat capabilities, otherwise use first
        # Prefer orgs that are NOT "Individual Org" as those may have restrictions
        selected_org = orgs[0]
        for org in orgs:
            org_name = org.get("name", "")
            # Skip individual orgs if we have other options
            if "Individual" not in org_name and len(orgs) > 1:
                selected_org = org
                break

        self._org_id = selected_org["uuid"]
        org_name = selected_org.get("name", "Unknown")
        log.info(f"[CLAUDE API] Selected organization: {org_name} (ID: {self._org_id})")
        return self._org_id

    async def get_conversations_list(self) -> list[dict]:
        """Get list of all conversations with metadata."""
        log.info("[CLAUDE API] Fetching conversations list...")
        org_id = await self._get_org_id()
        result = await self._api_request(f"/organizations/{org_id}/chat_conversations")

        # Handle if result is a dict with a 'conversations' key (pagination wrapper)
        if isinstance(result, dict):
            if "conversations" in result:
                result = result["conversations"]
                log.info(f"[CLAUDE API] Extracted conversations from wrapper")
            elif "items" in result:
                result = result["items"]
                log.info(f"[CLAUDE API] Extracted items from wrapper")

        if not isinstance(result, list):
            log.error(f"[CLAUDE API] Expected list but got {type(result).__name__}")
            return []

        log.info(f"[CLAUDE API] Retrieved {len(result)} conversations from Claude")
        return result

    async def get_conversation(self, conv_id: str) -> Optional[dict]:
        """Get full conversation content by ID."""
        org_id = await self._get_org_id()
        try:
            result = await self._api_request(
                f"/organizations/{org_id}/chat_conversations/{conv_id}"
            )
            msg_count = len(result.get("chat_messages", []))
            log.info(f"[CLAUDE API] Conversation {conv_id[:8]}... has {msg_count} messages")
            return result
        except Exception as e:
            log.warning(f"[CLAUDE API] Failed to fetch conversation {conv_id}: {e}")
            return None

    async def get_attachment_content(self, conv_id: str, attachment_id: str) -> Optional[bytes]:
        """Download attachment binary content.

        Args:
            conv_id: The conversation UUID
            attachment_id: The attachment UUID

        Returns:
            Binary content of the file, or None if download failed
        """
        import base64

        org_id = await self._get_org_id()
        try:
            result = await self._api_request(
                f"/organizations/{org_id}/chat_conversations/{conv_id}/files/{attachment_id}"
            )

            # Handle base64 encoded content
            if isinstance(result, dict):
                if "content" in result:
                    content = result["content"]
                    # Check if it's base64 encoded
                    if isinstance(content, str):
                        try:
                            return base64.b64decode(content)
                        except Exception:
                            return content.encode("utf-8")
                    return content

                # Handle download URL response
                if "download_url" in result:
                    download_url = result["download_url"]
                    log.info(f"[CLAUDE API] Following download URL for attachment {attachment_id[:8]}...")
                    response = await self._flaresolverr_request(download_url)
                    if response.get("status") == 200:
                        body = response.get("body", "")
                        # Try to decode as base64 if it looks like it
                        if body and not body.startswith(("<", "{")):
                            try:
                                return base64.b64decode(body)
                            except Exception:
                                return body.encode("utf-8") if isinstance(body, str) else body
                        return body.encode("utf-8") if isinstance(body, str) else body

            log.warning(f"[CLAUDE API] Unexpected attachment response format for {attachment_id[:8]}")
            return None

        except Exception as e:
            log.warning(f"[CLAUDE API] Failed to download attachment {attachment_id[:8]}: {e}")
            return None

    async def get_all_conversations_full(self) -> list[dict]:
        """Get all conversations with full message content."""
        log.info("[CLAUDE API] Starting to fetch all conversations with full content...")
        conversations_meta = await self.get_conversations_list()
        log.info(f"[CLAUDE API] Found {len(conversations_meta)} conversations to fetch")

        full_conversations = []
        for i, conv_meta in enumerate(conversations_meta):
            # Handle if conv_meta is not a dict
            if not isinstance(conv_meta, dict):
                log.warning(f"[CLAUDE API] Skipping non-dict item at index {i}: {type(conv_meta).__name__}")
                continue

            conv_id = conv_meta.get("uuid")
            if not conv_id:
                log.warning(f"[CLAUDE API] Skipping conversation without uuid at index {i}")
                continue

            name = conv_meta.get("name", "Untitled")[:50]
            log.info(f"[CLAUDE API] Fetching [{i+1}/{len(conversations_meta)}]: {name}")

            conv = await self.get_conversation(conv_id)
            if conv:
                full_conversations.append(conv)

            # Small delay to be nice to the API
            await asyncio.sleep(0.3)

        log.info(f"[CLAUDE API] Successfully fetched {len(full_conversations)} full conversations")
        return full_conversations

    async def close(self):
        """Cleanup resources."""
        self._org_id = None
        self._cookies = None


class TriliumSync:
    """Syncs conversations to Trilium Notes."""

    def __init__(
        self,
        trilium_url: str,
        token: str,
        parent_note_id: str = "",
        parent_note_title: str = "Claude Chats",
        parent_label: str = "claudeChatsRoot",
    ):
        log.info(f"[TRILIUM] Initializing connection to {trilium_url}")
        log.info(f"[TRILIUM] Token length: {len(token)} chars")
        self.trilium_url = trilium_url
        self.ea = ETAPI(trilium_url, token)
        self.parent_note_id = parent_note_id
        self.parent_note_title = parent_note_title
        self.parent_label = parent_label
        self._resolved_parent_id: Optional[str] = None
        log.info(f"[TRILIUM] Parent note ID: {parent_note_id or '(auto-create)'}")
        log.info(f"[TRILIUM] Parent note title: {parent_note_title}")

    def find_note_by_conversation_id(self, conv_id: str) -> Optional[str]:
        """Find existing Trilium note by claudeConversationId label."""
        try:
            results = self.ea.search_note(search=f"#claudeConversationId={conv_id}")
            if results and results.get("results"):
                note_id = results["results"][0]["noteId"]
                log.debug(f"Found existing note for conversation {conv_id}: {note_id}")
                return note_id
        except Exception as e:
            log.debug(f"Search for conversation {conv_id} failed: {e}")
        return None

    def _get_or_create_parent_note(self) -> str:
        """Get or create the parent note for Claude chats."""
        if self._resolved_parent_id:
            log.info(f"[TRILIUM] Using cached parent note ID: {self._resolved_parent_id}")
            return self._resolved_parent_id

        if self.parent_note_id:
            log.info(f"[TRILIUM] >>> GET note {self.parent_note_id}")
            try:
                note = self.ea.get_note(self.parent_note_id)
                if note:
                    self._resolved_parent_id = self.parent_note_id
                    log.info(f"[TRILIUM] <<< Found specified parent note: {note.get('title', self.parent_note_id)}")
                    return self._resolved_parent_id
            except Exception as e:
                log.warning(f"[TRILIUM] <<< Specified parent note {self.parent_note_id} not found: {e}")
                log.warning("[TRILIUM] Falling back to auto-create behavior")

        log.info(f"[TRILIUM] >>> SEARCH for #{self.parent_label}")
        try:
            results = self.ea.search_note(search=f"#{self.parent_label}")
            if results and results.get("results"):
                self._resolved_parent_id = results["results"][0]["noteId"]
                log.info(f"[TRILIUM] <<< Found existing parent note: {self._resolved_parent_id}")
                return self._resolved_parent_id
            log.info("[TRILIUM] <<< No existing parent note found")
        except Exception as e:
            log.info(f"[TRILIUM] <<< Search failed, will create new parent: {e}")

        log.info(f"[TRILIUM] >>> CREATE note '{self.parent_note_title}' under root")
        try:
            result = self.ea.create_note(
                parentNoteId="root",
                title=self.parent_note_title,
                type="text",
                content="<p>Automatically synced conversations from Claude.ai</p>",
            )
            if not result or "note" not in result or "noteId" not in result["note"]:
                raise ValueError(f"Invalid response from create_note: {result}")
            self._resolved_parent_id = result["note"]["noteId"]
            log.info(f"[TRILIUM] <<< Created note with ID: {self._resolved_parent_id}")
        except Exception as e:
            log.error(f"[TRILIUM] <<< Failed to create parent note '{self.parent_note_title}': {e}")
            raise RuntimeError(f"Cannot create parent note: {e}") from e

        log.info(f"[TRILIUM] >>> CREATE attribute #{self.parent_label} on {self._resolved_parent_id}")
        try:
            self.ea.create_attribute(
                noteId=self._resolved_parent_id,
                type="label",
                name=self.parent_label,
                value="",
                isInheritable=False,
            )
            log.info("[TRILIUM] <<< Attribute created successfully")
        except Exception as e:
            log.warning(f"[TRILIUM] <<< Failed to add label to parent note: {e}")

        log.info(f"[TRILIUM] Parent note ready: '{self.parent_note_title}' ({self._resolved_parent_id})")
        return self._resolved_parent_id

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _format_lists(self, text: str) -> str:
        """Process markdown lists into HTML with proper ul/ol handling.

        Handles:
        - Unordered lists (- or *)
        - Ordered lists (1. 2. etc)
        - Blank lines between list items (tolerates them)
        - Mixed list types (flushes and switches)
        """
        lines = text.split("\n")
        result = []
        current_list_type = None  # 'ul' or 'ol'
        list_items = []

        def flush_list():
            """Output accumulated list items wrapped in appropriate tag."""
            nonlocal list_items, current_list_type
            if list_items and current_list_type:
                tag = current_list_type
                result.append(f"<{tag}>")
                result.extend(list_items)
                result.append(f"</{tag}>")
                list_items = []
                current_list_type = None

        for line in lines:
            stripped = line.strip()

            # Check for unordered list item (- or *)
            ul_match = re.match(r"^[\-\*]\s+(.+)$", stripped)
            # Check for ordered list item (1. 2. etc)
            ol_match = re.match(r"^\d+\.\s+(.+)$", stripped)

            if ul_match:
                # If we were in an ordered list, flush it first
                if current_list_type == "ol":
                    flush_list()
                current_list_type = "ul"
                list_items.append(f"<li>{ul_match.group(1)}</li>")
            elif ol_match:
                # If we were in an unordered list, flush it first
                if current_list_type == "ul":
                    flush_list()
                current_list_type = "ol"
                list_items.append(f"<li>{ol_match.group(1)}</li>")
            elif stripped == "" and current_list_type:
                # Empty line while in a list - continue the list
                # (This handles blank lines between list items)
                continue
            else:
                # Non-list line - flush any pending list and add the line
                flush_list()
                result.append(line)

        # Flush any remaining list at end
        flush_list()

        return "\n".join(result)

    def _format_message_content(self, text: str) -> str:
        """Format message content with markdown to HTML conversion."""
        text = filter_unsupported_blocks(text)
        text = strip_artifact_tags(text)
        text = self._escape_html(text)

        # Code blocks with language
        text = re.sub(
            r"```(\w*)\n?(.*?)```",
            r'<pre><code class="language-\1">\2</code></pre>',
            text,
            flags=re.DOTALL,
        )

        # Inline code
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

        # Bold
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

        # Italic
        text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)

        # Links
        text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)

        # Headers
        text = re.sub(r"^### (.+)$", r"<h4>\1</h4>", text, flags=re.MULTILINE)
        text = re.sub(r"^## (.+)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
        text = re.sub(r"^# (.+)$", r"<h2>\1</h2>", text, flags=re.MULTILINE)

        # Lists - use dedicated method for proper handling
        text = self._format_lists(text)

        # Line breaks - skip code blocks and list elements
        lines = text.split("\n")
        result = []
        in_code = False
        for line in lines:
            if "<pre>" in line:
                in_code = True
            if "</pre>" in line:
                in_code = False
                result.append(line)
                continue
            # Skip adding <br/> to list elements
            if any(tag in line for tag in ["<ul>", "</ul>", "<ol>", "</ol>", "<li>"]):
                result.append(line)
                continue
            if not in_code and line.strip():
                result.append(line + "<br/>")
            else:
                result.append(line + "\n" if in_code else line)

        return "".join(result)

    def _format_conversation(self, conv: dict) -> str:
        """Convert conversation to HTML for Trilium."""
        title = conv.get("name", "Untitled Conversation")
        created = conv.get("created_at", "")
        updated = conv.get("updated_at", "")
        messages = conv.get("chat_messages", [])

        html_parts = [
            f"<h1>{self._escape_html(title)}</h1>",
            f"<p><strong>Created:</strong> {created}<br/>",
            f"<strong>Updated:</strong> {updated}<br/>",
            f"<strong>Messages:</strong> {len(messages)}</p>",
            "<hr/>",
        ]

        for msg in messages:
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
            timestamp = msg.get("created_at", "")

            is_human = sender == "human"
            sender_label = "Human" if is_human else "Claude"

            formatted_text = self._format_message_content(text)

            html_parts.append(f"""
<div style="margin: 1.5em 0; padding: 0.5em 0;">
    <p style="margin: 0 0 0.5em 0;"><strong>{sender_label}</strong> <span style="color: #6b7280; font-size: 0.875em;">({timestamp})</span></p>
    <div style="margin: 0;">{formatted_text}</div>
</div>
<hr style="border: none; border-top: 1px solid #e5e7eb; margin: 0;" />
""")

        return "\n".join(html_parts)

    def _create_attachment_note(
        self,
        parent_note_id: str,
        attachment: dict,
        msg_index: int,
        att_index: int,
        file_content: Optional[bytes] = None,
    ) -> Optional[str]:
        """Create a child note for an attachment under the conversation note.

        Args:
            parent_note_id: The conversation note ID to attach to
            attachment: The attachment dict from Claude API
            msg_index: Index of the message containing this attachment
            att_index: Index of this attachment within the message
            file_content: Optional binary content of the file

        Returns:
            The created note ID, or None if creation failed
        """
        file_name = attachment.get("file_name", f"Attachment {att_index + 1}")
        file_type = attachment.get("file_type", "unknown")
        file_size = attachment.get("file_size", 0)
        extracted_content = attachment.get("extracted_content", "")

        # Determine note type based on whether we have file content
        if file_content:
            # Create a file-type note with the actual binary content
            log.info(f"[TRILIUM] >>> CREATE file note '{file_name}' under {parent_note_id} ({len(file_content)} bytes)")
            try:
                result = self.ea.create_note(
                    parentNoteId=parent_note_id,
                    title=file_name,
                    type="file",
                    content=file_content,
                    mime=file_type if file_type != "unknown" else "application/octet-stream",
                )
                note_id = result["note"]["noteId"]

                # Add labels to identify this as an attachment
                self.ea.create_attribute(
                    noteId=note_id,
                    type="label",
                    name="claudeAttachment",
                    value="",
                    isInheritable=False,
                )
                self.ea.create_attribute(
                    noteId=note_id,
                    type="label",
                    name="claudeAttachmentFileName",
                    value=file_name,
                    isInheritable=False,
                )
                self.ea.create_attribute(
                    noteId=note_id,
                    type="label",
                    name="originalFileName",
                    value=file_name,
                    isInheritable=False,
                )

                log.info(f"[TRILIUM] <<< Created file note: {note_id}")
                return note_id
            except Exception as e:
                log.warning(f"[TRILIUM] <<< Failed to create file note, falling back to text: {e}")
                # Fall through to text note creation

        # Create a text note with metadata (fallback or when no content)
        content_parts = [
            f"<h2>{self._escape_html(file_name)}</h2>",
            f"<p><strong>Type:</strong> {self._escape_html(file_type)}<br/>",
            f"<strong>Size:</strong> {file_size} bytes<br/>",
            f"<strong>From message:</strong> #{msg_index + 1}</p>",
            "<hr/>",
        ]

        if extracted_content:
            content_parts.append("<h3>Extracted Content</h3>")
            content_parts.append(f"<pre>{self._escape_html(extracted_content)}</pre>")
        else:
            content_parts.append("<p><em>No extracted content available</em></p>")

        content = "\n".join(content_parts)

        log.info(f"[TRILIUM] >>> CREATE attachment note '{file_name}' under {parent_note_id}")
        try:
            result = self.ea.create_note(
                parentNoteId=parent_note_id,
                title=f"[Attachment] {file_name}",
                type="text",
                content=content,
            )
            note_id = result["note"]["noteId"]

            # Add labels to identify this as an attachment
            self.ea.create_attribute(
                noteId=note_id,
                type="label",
                name="claudeAttachment",
                value="",
                isInheritable=False,
            )
            self.ea.create_attribute(
                noteId=note_id,
                type="label",
                name="claudeAttachmentFileName",
                value=file_name,
                isInheritable=False,
            )

            log.info(f"[TRILIUM] <<< Created attachment note: {note_id}")
            return note_id
        except Exception as e:
            log.warning(f"[TRILIUM] <<< Failed to create attachment note: {e}")
            return None

    def _get_existing_attachment_notes(self, parent_note_id: str) -> dict:
        """Get existing attachment child notes for a conversation.

        Returns:
            Dict mapping file_name to note_id
        """
        try:
            results = self.ea.search_note(
                search=f"#claudeAttachment note.parents.noteId={parent_note_id}"
            )
            if results and results.get("results"):
                existing = {}
                for note in results["results"]:
                    # Use title which is "[Attachment] filename"
                    title = note.get("title", "")
                    if title.startswith("[Attachment] "):
                        file_name = title[13:]  # Remove prefix
                        existing[file_name] = note["noteId"]
                return existing
        except Exception as e:
            log.debug(f"Failed to search for existing attachments: {e}")
        return {}

    def _create_artifact_note(
        self,
        parent_note_id: str,
        artifact: dict,
        msg_index: int,
        art_index: int,
    ) -> Optional[str]:
        """Create a child note for an artifact under the conversation note.

        Args:
            parent_note_id: The conversation note ID to attach to
            artifact: Parsed artifact dict with identifier, type, title, language, content
            msg_index: Index of the message containing this artifact
            art_index: Index of this artifact within the message

        Returns:
            The created note ID, or None if creation failed
        """
        identifier = artifact.get("identifier", f"artifact-{msg_index}-{art_index}")
        art_type = artifact.get("type", "")
        title = artifact.get("title", identifier)
        language = artifact.get("language", "")
        content = artifact.get("content", "")

        if not content:
            log.debug(f"[TRILIUM] Skipping empty artifact: {identifier}")
            return None

        ext = get_artifact_extension(artifact)
        mime = get_artifact_mime(artifact)
        file_name = f"{identifier}{ext}"

        # Create as a file-type note with the artifact content
        log.info(f"[TRILIUM] >>> CREATE artifact note '{title}' ({file_name}) under {parent_note_id}")
        try:
            result = self.ea.create_note(
                parentNoteId=parent_note_id,
                title=f"[Artifact] {title}",
                type="code",
                mime=mime,
                content=content,
            )
            note_id = result["note"]["noteId"]

            # Add labels to identify this as an artifact
            self.ea.create_attribute(
                noteId=note_id,
                type="label",
                name="claudeArtifact",
                value="",
                isInheritable=False,
            )
            self.ea.create_attribute(
                noteId=note_id,
                type="label",
                name="claudeArtifactId",
                value=identifier,
                isInheritable=False,
            )
            if art_type:
                self.ea.create_attribute(
                    noteId=note_id,
                    type="label",
                    name="claudeArtifactType",
                    value=art_type,
                    isInheritable=False,
                )
            if language:
                self.ea.create_attribute(
                    noteId=note_id,
                    type="label",
                    name="claudeArtifactLanguage",
                    value=language,
                    isInheritable=False,
                )
            self.ea.create_attribute(
                noteId=note_id,
                type="label",
                name="originalFileName",
                value=file_name,
                isInheritable=False,
            )

            log.info(f"[TRILIUM] <<< Created artifact note: {note_id} ({file_name})")
            return note_id
        except Exception as e:
            log.warning(f"[TRILIUM] <<< Failed to create artifact note: {e}")
            return None

    def _get_existing_artifact_notes(self, parent_note_id: str) -> dict:
        """Get existing artifact child notes for a conversation.

        Returns:
            Dict mapping artifact identifier to note_id
        """
        try:
            results = self.ea.search_note(
                search=f"#claudeArtifact note.parents.noteId={parent_note_id}"
            )
            if results and results.get("results"):
                existing = {}
                for note in results["results"]:
                    note_id = note["noteId"]
                    # Try to get the artifact identifier from attributes
                    try:
                        attrs = self.ea.get_note(note_id)
                        if attrs:
                            for attr in attrs.get("attributes", []):
                                if attr.get("name") == "claudeArtifactId":
                                    existing[attr["value"]] = note_id
                                    break
                            else:
                                # Fallback: use title
                                title = note.get("title", "")
                                if title.startswith("[Artifact] "):
                                    existing[title[11:]] = note_id
                    except Exception:
                        title = note.get("title", "")
                        if title.startswith("[Artifact] "):
                            existing[title[11:]] = note_id
                return existing
        except Exception as e:
            log.debug(f"Failed to search for existing artifacts: {e}")
        return {}

    def _sync_artifacts(
        self,
        conv: dict,
        parent_note_id: str,
    ):
        """Extract and sync all artifacts from conversation messages as child notes.

        Parses antArtifact XML tags from message text and creates code-type
        child notes in Trilium with the artifact content.

        Args:
            conv: The conversation dict
            parent_note_id: The Trilium note ID to create artifact notes under
        """
        messages = conv.get("chat_messages", [])

        # Get existing artifact notes to avoid duplicates
        existing_artifacts = self._get_existing_artifact_notes(parent_note_id)

        artifact_count = 0
        skipped_count = 0
        updated_count = 0

        for msg_index, msg in enumerate(messages):
            text = msg.get("text", "")
            if not text:
                continue

            artifacts = parse_artifacts(text)
            if not artifacts:
                continue

            for art_index, artifact in enumerate(artifacts):
                identifier = artifact.get("identifier", "")
                if not identifier:
                    identifier = f"artifact-{msg_index}-{art_index}"

                # Check if artifact already exists
                if identifier in existing_artifacts:
                    # Update existing artifact content
                    existing_note_id = existing_artifacts[identifier]
                    try:
                        self.ea.update_note_content(
                            noteId=existing_note_id, content=artifact["content"]
                        )
                        log.debug(f"[TRILIUM] Updated existing artifact: {identifier}")
                        updated_count += 1
                    except Exception as e:
                        log.warning(f"[TRILIUM] Failed to update artifact {identifier}: {e}")
                    continue

                self._create_artifact_note(
                    parent_note_id, artifact, msg_index, art_index
                )
                artifact_count += 1

        if artifact_count > 0 or skipped_count > 0 or updated_count > 0:
            log.info(
                f"[TRILIUM] Artifacts: {artifact_count} created, "
                f"{updated_count} updated, {skipped_count} skipped"
            )

    async def _sync_attachments(
        self,
        conv: dict,
        parent_note_id: str,
        claude_api: Optional["ClaudeAPI"] = None,
    ):
        """Sync all attachments from conversation messages as child notes.

        Args:
            conv: The conversation dict
            parent_note_id: The Trilium note ID to attach to
            claude_api: Optional ClaudeAPI instance for downloading file content
        """
        messages = conv.get("chat_messages", [])
        conv_id = conv.get("uuid", "")

        # Get existing attachment notes to avoid duplicates
        existing_attachments = self._get_existing_attachment_notes(parent_note_id)

        attachment_count = 0
        skipped_count = 0
        with_content_count = 0

        for msg_index, msg in enumerate(messages):
            attachments = msg.get("attachments", [])
            if not attachments:
                continue

            for att_index, attachment in enumerate(attachments):
                file_name = attachment.get("file_name", f"Attachment {att_index + 1}")

                # Skip if attachment appears to be empty/invalid
                if not attachment.get("file_name") and not attachment.get("id"):
                    continue

                # Skip if already exists
                if file_name in existing_attachments:
                    log.debug(f"[TRILIUM] Skipping existing attachment: {file_name}")
                    skipped_count += 1
                    continue

                # Try to download actual file content if API client is available
                file_content = None
                attachment_id = attachment.get("id")
                if claude_api and conv_id and attachment_id:
                    log.info(f"[SYNC] Downloading attachment: {file_name}")
                    file_content = await claude_api.get_attachment_content(conv_id, attachment_id)
                    if file_content:
                        with_content_count += 1

                self._create_attachment_note(
                    parent_note_id, attachment, msg_index, att_index, file_content
                )
                attachment_count += 1

        if attachment_count > 0 or skipped_count > 0:
            content_info = f", {with_content_count} with content" if with_content_count > 0 else ""
            log.info(f"[TRILIUM] Attachments: {attachment_count} created{content_info}, {skipped_count} skipped (existing)")

    async def sync_conversation(
        self,
        conv: dict,
        existing_note_id: Optional[str] = None,
        claude_api: Optional["ClaudeAPI"] = None,
    ) -> str:
        """Sync a single conversation to Trilium. Returns the note ID.

        Args:
            conv: The conversation dict from Claude API
            existing_note_id: Optional existing Trilium note ID to update
            claude_api: Optional ClaudeAPI instance for downloading attachments
        """
        title = conv.get("name", "Untitled Conversation")
        content = self._format_conversation(conv)
        conv_id = conv.get("uuid", "")
        updated_at = conv.get("updated_at", "")
        msg_count = len(conv.get("chat_messages", []))

        log.info(f"[TRILIUM] Syncing conversation: {title[:50]}")
        log.info(f"[TRILIUM]   - Conversation ID: {conv_id}")
        log.info(f"[TRILIUM]   - Messages: {msg_count}")
        log.info(f"[TRILIUM]   - Content length: {len(content)} chars")

        if existing_note_id:
            log.info(f"[TRILIUM] >>> PATCH note {existing_note_id} (update existing)")
            try:
                self.ea.patch_note(noteId=existing_note_id, title=title)
                self.ea.update_note_content(noteId=existing_note_id, content=content)
                log.info(f"[TRILIUM] <<< Updated successfully: {title[:50]}")
                # Sync attachments and artifacts for existing note
                await self._sync_attachments(conv, existing_note_id, claude_api)
                self._sync_artifacts(conv, existing_note_id)
                return existing_note_id
            except Exception as e:
                log.warning(f"[TRILIUM] <<< Failed to update note {existing_note_id}: {e}")
                log.warning("[TRILIUM] Will create new note instead")

        parent_id = self._get_or_create_parent_note()
        log.info(f"[TRILIUM] >>> CREATE note '{title[:50]}' under {parent_id}")
        result = self.ea.create_note(
            parentNoteId=parent_id,
            title=title,
            type="text",
            content=content,
        )
        note_id = result["note"]["noteId"]
        log.info(f"[TRILIUM] <<< Created note: {note_id}")

        log.info(f"[TRILIUM] >>> CREATE attributes on {note_id}")
        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeConversationId",
            value=conv_id,
            isInheritable=False,
        )
        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeUpdatedAt",
            value=updated_at,
            isInheritable=False,
        )
        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeChat",
            value="",
            isInheritable=False,
        )
        log.info("[TRILIUM] <<< Attributes created: claudeConversationId, claudeUpdatedAt, claudeChat")

        # Sync attachments and artifacts for new note
        await self._sync_attachments(conv, note_id, claude_api)
        self._sync_artifacts(conv, note_id)

        log.info(f"[TRILIUM] Successfully synced: {title[:50]}")
        return note_id


def compute_content_hash(conv: dict) -> str:
    """Compute hash of conversation content for change detection."""
    content = json.dumps(
        {
            "messages": [
                {
                    "sender": m.get("sender"),
                    "text": filter_unsupported_blocks(m.get("text", "")),
                    "attachments": [
                        a.get("file_name", "") for a in m.get("attachments", [])
                    ],
                }
                for m in conv.get("chat_messages", [])
            ],
            "name": conv.get("name", ""),
            "updated_at": conv.get("updated_at", ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(content.encode()).hexdigest()[:16]


async def run_sync():
    """Run a single sync cycle."""
    log.info("=" * 60)
    log.info("[SYNC] Starting sync cycle")
    log.info("=" * 60)

    log.info(f"[SYNC] State file: {CONFIG['state_file']}")
    state = SyncState(CONFIG["state_file"])
    log.info(f"[SYNC] Last sync: {state.data.get('last_sync', 'Never')}")
    log.info(f"[SYNC] Known conversations in state: {len(state.data.get('conversations', {}))}")

    log.info("[SYNC] Initializing Claude API client...")
    log.info(f"[SYNC] Session key length: {len(CONFIG['claude_session_key'])} chars")
    claude = ClaudeAPI(CONFIG["claude_session_key"])

    trilium = TriliumSync(
        CONFIG["trilium_url"],
        CONFIG["trilium_token"],
        parent_note_id=CONFIG["parent_note_id"],
        parent_note_title=CONFIG["parent_note_title"],
        parent_label=CONFIG["parent_note_label"],
    )

    log.info("-" * 60)
    log.info("[SYNC] Phase 1: Fetching conversations from Claude.ai")
    log.info("-" * 60)

    try:
        conversations = await claude.get_all_conversations_full()
    except Exception as e:
        error_msg = str(e)
        log.error(f"[SYNC] FAILED to fetch conversations: {error_msg}")
        if "401" in error_msg or "session expired" in error_msg.lower() or "login" in error_msg.lower():
            log.error("[SYNC] Authentication failed. Check your CLAUDE_SESSION_KEY.")
            notifier.notify_session_expired()
        else:
            log.error(f"[SYNC] API error: {e}")
            notifier.notify_error(error_msg)
        await claude.close()
        return

    if not conversations:
        log.warning("[SYNC] No conversations found - nothing to sync")
        await claude.close()
        return

    log.info("-" * 60)
    log.info("[SYNC] Phase 2: Syncing to Trilium Notes")
    log.info("-" * 60)
    log.info(f"[SYNC] Processing {len(conversations)} conversations...")

    synced = 0
    skipped = 0
    errors = 0

    for i, conv in enumerate(conversations):
        conv_id = conv.get("uuid", "")
        conv_name = conv.get("name", "Untitled")[:40]
        if not conv_id:
            continue

        content_hash = compute_content_hash(conv)
        existing_hash = state.get_conversation_hash(conv_id)

        log.info(f"[SYNC] [{i+1}/{len(conversations)}] {conv_name}")
        log.info(f"[SYNC]   Hash: {content_hash} (existing: {existing_hash or 'none'})")

        if existing_hash == content_hash:
            log.info(f"[SYNC]   -> SKIPPED (unchanged)")
            skipped += 1
            continue

        try:
            existing_note_id = state.get_trilium_note_id(conv_id)
            if not existing_note_id:
                # State file may have been lost - check Trilium directly
                existing_note_id = trilium.find_note_by_conversation_id(conv_id)
                if existing_note_id:
                    log.info(f"Recovered note ID from Trilium for: {conv.get('name', conv_id)[:30]}")
            note_id = await trilium.sync_conversation(conv, existing_note_id, claude)
            state.update_conversation(conv_id, content_hash, note_id)
            log.info(f"[SYNC]   -> SUCCESS (note: {note_id})")
            synced += 1
        except Exception as e:
            log.error(f"[SYNC]   -> FAILED: {e}")
            errors += 1

    # Close Claude API client after all syncs complete
    log.info("[SYNC] Closing Claude API client...")
    await claude.close()
    log.info("[SYNC] Claude API client closed")

    log.info("=" * 60)
    log.info(f"[SYNC] Sync complete!")
    log.info(f"[SYNC]   Synced: {synced}")
    log.info(f"[SYNC]   Skipped (unchanged): {skipped}")
    log.info(f"[SYNC]   Errors: {errors}")
    log.info("=" * 60)


async def async_main():
    """Async main entry point."""
    log.info("=" * 60)
    log.info(f"Claude-Trilium Sync v{get_version()}")
    log.info("=" * 60)

    log.info("[CONFIG] Configuration:")
    log.info(f"[CONFIG]   TRILIUM_URL: {CONFIG['trilium_url']}")
    log.info(f"[CONFIG]   TRILIUM_TOKEN: {'*' * 8}... ({len(CONFIG['trilium_token'])} chars)")
    log.info(f"[CONFIG]   CLAUDE_SESSION_KEY: {'*' * 8}... ({len(CONFIG['claude_session_key'])} chars)")
    log.info(f"[CONFIG]   STATE_FILE: {CONFIG['state_file']}")
    log.info(f"[CONFIG]   SYNC_INTERVAL: {CONFIG['sync_interval']}s")
    log.info(f"[CONFIG]   LOG_LEVEL: {CONFIG['log_level']}")
    log.info(f"[CONFIG]   PARENT_NOTE_ID: {CONFIG['parent_note_id'] or '(auto)'}")
    log.info(f"[CONFIG]   PARENT_NOTE_TITLE: {CONFIG['parent_note_title']}")
    if CONFIG['pushover_user_key']:
        log.info(f"[CONFIG]   PUSHOVER: Enabled")
    else:
        log.info(f"[CONFIG]   PUSHOVER: Disabled")
    log.info(f"[CONFIG]   FLARESOLVERR_URL: {CONFIG['flaresolverr_url']}")

    if not CONFIG["trilium_token"]:
        log.error("[CONFIG] TRILIUM_TOKEN not set!")
        log.error("[CONFIG] Get token from Trilium: Options -> ETAPI -> Create new token")
        sys.exit(1)

    if not CONFIG["claude_session_key"]:
        log.error("[CONFIG] CLAUDE_SESSION_KEY not set!")
        log.error("[CONFIG] Get from Claude.ai: DevTools -> Application -> Cookies -> sessionKey")
        sys.exit(1)

    interval = CONFIG["sync_interval"]

    if interval <= 0:
        log.info("[MODE] Running in one-shot mode")
        await run_sync()
    else:
        log.info(f"[MODE] Running in continuous mode, interval: {interval}s")
        while True:
            try:
                await run_sync()
            except Exception as e:
                log.exception(f"[SYNC] Sync failed with exception: {e}")
            log.info(f"[MODE] Sleeping {interval}s until next sync...")
            await asyncio.sleep(interval)


def main():
    """Main entry point."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
