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
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
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
}

# Setup logging
logging.basicConfig(
    level=getattr(logging, CONFIG["log_level"]),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
log = logging.getLogger(__name__)


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
    """Playwright-based client for Claude.ai API."""

    BASE_URL = "https://claude.ai"

    def __init__(self, session_key: str):
        self.session_key = session_key
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._org_id: Optional[str] = None

    async def _init_browser(self):
        """Initialize Playwright browser with session cookie."""
        if self.browser:
            log.debug("Browser already initialized, reusing existing instance")
            return

        log.debug("Initializing Playwright browser...")
        log.debug("Starting Playwright...")
        self.playwright = await async_playwright().start()
        log.debug("Playwright started, launching Chromium...")
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )
        log.debug("Chromium launched, creating browser context...")
        self.context = await self.browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        log.debug("Browser context created")

        # Set the session cookie
        log.debug(f"Injecting sessionKey cookie (length: {len(self.session_key)} chars)...")
        await self.context.add_cookies([{
            'name': 'sessionKey',
            'value': self.session_key,
            'domain': '.claude.ai',
            'path': '/',
            'httpOnly': True,
            'secure': True,
        }])
        log.debug("Session cookie injected")

        log.debug("Creating new page...")
        self.page = await self.context.new_page()
        log.debug("Browser initialized successfully")

    async def _api_request(self, endpoint: str) -> dict:
        """Make an API request from within the browser context."""
        await self._init_browser()

        log.debug(f"API request: GET /api{endpoint}")

        # Use page.evaluate to make fetch request from browser context
        # This inherits all cookies and browser security context
        result = await self.page.evaluate(f"""
            async () => {{
                const response = await fetch('{self.BASE_URL}/api{endpoint}', {{
                    method: 'GET',
                    credentials: 'include',
                    headers: {{
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                    }}
                }});
                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}
                return await response.json();
            }}
        """)

        # Log response info
        if isinstance(result, list):
            log.debug(f"API response: {len(result)} items")
        elif isinstance(result, dict):
            log.debug(f"API response: {len(result)} keys")
        else:
            log.debug(f"API response received")

        return result

    async def _get_org_id(self) -> str:
        """Get the organization ID for the authenticated user."""
        if self._org_id:
            log.debug(f"Using cached organization ID: {self._org_id}")
            return self._org_id

        log.debug("Fetching organization ID...")

        # First navigate to Claude to establish the session
        await self._init_browser()

        log.debug(f"Navigating to {self.BASE_URL}/...")
        await self.page.goto(
            f"{self.BASE_URL}/",
            wait_until="domcontentloaded",
            timeout=60000
        )
        log.debug(f"Navigation complete, current URL: {self.page.url}")

        # Wait for page to stabilize after initial load
        log.debug("Waiting for page to stabilize...")
        await asyncio.sleep(2)

        # Check if we're on a login page (session expired)
        current_url = self.page.url
        log.debug(f"Checking URL for login redirect: {current_url}")
        if "login" in current_url or "auth" in current_url:
            raise ValueError("Session expired - redirected to login page")

        log.debug("Making API request for /organizations...")
        orgs = await self._api_request("/organizations")
        log.debug(f"Got {len(orgs)} organization(s)")

        if not orgs:
            raise ValueError("No organizations found for this account")

        self._org_id = orgs[0]["uuid"]
        log.debug(f"Using organization: {self._org_id}")
        return self._org_id

    async def get_conversations_list(self) -> list[dict]:
        """Get list of all conversations with metadata."""
        org_id = await self._get_org_id()
        result = await self._api_request(f"/organizations/{org_id}/chat_conversations")
        return result

    async def get_conversation(self, conv_id: str) -> Optional[dict]:
        """Get full conversation content by ID."""
        org_id = await self._get_org_id()
        try:
            result = await self._api_request(
                f"/organizations/{org_id}/chat_conversations/{conv_id}"
            )
            return result
        except Exception as e:
            log.warning(f"Failed to fetch conversation {conv_id}: {e}")
            return None

    async def get_all_conversations_full(self) -> list[dict]:
        """Get all conversations with full message content."""
        conversations_meta = await self.get_conversations_list()
        log.info(f"Found {len(conversations_meta)} conversations")

        full_conversations = []
        for i, conv_meta in enumerate(conversations_meta):
            conv_id = conv_meta.get("uuid")
            if not conv_id:
                continue

            name = conv_meta.get("name", "Untitled")[:50]
            log.debug(f"Fetching {i+1}/{len(conversations_meta)}: {name}")

            conv = await self.get_conversation(conv_id)
            if conv:
                full_conversations.append(conv)

            # Small delay to be nice to the API
            await asyncio.sleep(0.3)

        return full_conversations

    async def close(self):
        """Close browser and cleanup."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.browser = None
        self.context = None
        self.page = None
        self.playwright = None


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
        self.ea = ETAPI(trilium_url, token)
        self.parent_note_id = parent_note_id
        self.parent_note_title = parent_note_title
        self.parent_label = parent_label
        self._resolved_parent_id: Optional[str] = None

    def _get_or_create_parent_note(self) -> str:
        """Get or create the parent note for Claude chats."""
        if self._resolved_parent_id:
            return self._resolved_parent_id

        if self.parent_note_id:
            try:
                note = self.ea.get_note(self.parent_note_id)
                if note:
                    self._resolved_parent_id = self.parent_note_id
                    log.info(f"Using specified parent note: {note.get('title', self.parent_note_id)}")
                    return self._resolved_parent_id
            except Exception as e:
                log.warning(f"Specified parent note {self.parent_note_id} not found: {e}")
                log.warning("Falling back to auto-create behavior")

        try:
            results = self.ea.search_note(search=f"#{self.parent_label}")
            if results and results.get("results"):
                self._resolved_parent_id = results["results"][0]["noteId"]
                log.debug(f"Found existing parent note: {self._resolved_parent_id}")
                return self._resolved_parent_id
        except Exception as e:
            log.debug(f"Search failed, will create new parent: {e}")

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
        except Exception as e:
            log.error(f"Failed to create parent note '{self.parent_note_title}': {e}")
            raise RuntimeError(f"Cannot create parent note: {e}") from e

        try:
            self.ea.create_attribute(
                noteId=self._resolved_parent_id,
                type="label",
                name=self.parent_label,
                value="",
            )
        except Exception as e:
            log.warning(f"Failed to add label to parent note: {e}")

        log.info(f"Created parent note '{self.parent_note_title}': {self._resolved_parent_id}")
        return self._resolved_parent_id

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _format_message_content(self, text: str) -> str:
        """Format message content with markdown to HTML conversion."""
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

        # Lists
        text = re.sub(r"^[\-\*] (.+)$", r"<li>\1</li>", text, flags=re.MULTILINE)
        text = re.sub(r"^\d+\. (.+)$", r"<li>\1</li>", text, flags=re.MULTILINE)
        text = re.sub(
            r"((?:<li>.*?</li>\n?)+)",
            r"<ul>\1</ul>",
            text,
            flags=re.DOTALL,
        )

        # Line breaks
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
            border_color = "#3b82f6" if is_human else "#10b981"
            bg_color = "#eff6ff" if is_human else "#f0fdf4"
            sender_label = "Human" if is_human else "Claude"

            formatted_text = self._format_message_content(text)

            html_parts.append(f"""
<div style="margin: 1em 0; padding: 1em; border-left: 4px solid {border_color}; background: {bg_color};">
    <p style="margin: 0 0 0.5em 0;"><strong>{sender_label}</strong> <span style="color: #6b7280; font-size: 0.875em;">({timestamp})</span></p>
    <div style="margin: 0;">{formatted_text}</div>
</div>
""")

        return "\n".join(html_parts)

    def sync_conversation(
        self, conv: dict, existing_note_id: Optional[str] = None
    ) -> str:
        """Sync a single conversation to Trilium. Returns the note ID."""
        title = conv.get("name", "Untitled Conversation")
        content = self._format_conversation(conv)
        conv_id = conv.get("uuid", "")
        updated_at = conv.get("updated_at", "")

        if existing_note_id:
            try:
                self.ea.patch_note(noteId=existing_note_id, title=title)
                self.ea.patch_note_content(noteId=existing_note_id, content=content)
                log.info(f"Updated: {title[:60]}")
                return existing_note_id
            except Exception as e:
                log.warning(f"Failed to update note {existing_note_id}, creating new: {e}")

        parent_id = self._get_or_create_parent_note()
        result = self.ea.create_note(
            parentNoteId=parent_id,
            title=title,
            type="text",
            content=content,
        )
        note_id = result["note"]["noteId"]

        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeConversationId",
            value=conv_id,
        )
        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeUpdatedAt",
            value=updated_at,
        )
        self.ea.create_attribute(
            noteId=note_id,
            type="label",
            name="claudeChat",
            value="",
        )

        log.info(f"Created: {title[:60]}")
        return note_id


def compute_content_hash(conv: dict) -> str:
    """Compute hash of conversation content for change detection."""
    content = json.dumps(
        {
            "messages": [
                {"sender": m.get("sender"), "text": m.get("text")}
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
    state = SyncState(CONFIG["state_file"])
    claude = ClaudeAPI(CONFIG["claude_session_key"])
    trilium = TriliumSync(
        CONFIG["trilium_url"],
        CONFIG["trilium_token"],
        parent_note_id=CONFIG["parent_note_id"],
        parent_note_title=CONFIG["parent_note_title"],
        parent_label=CONFIG["parent_note_label"],
    )

    log.info(f"Starting sync (last: {state.data.get('last_sync', 'Never')})")

    try:
        conversations = await claude.get_all_conversations_full()
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "session expired" in error_msg.lower() or "login" in error_msg.lower():
            log.error("Authentication failed. Check your CLAUDE_SESSION_KEY.")
            notifier.notify_session_expired()
        else:
            log.error(f"API error: {e}")
            notifier.notify_error(error_msg)
        return
    finally:
        await claude.close()

    if not conversations:
        log.warning("No conversations found")
        return

    synced = 0
    skipped = 0
    errors = 0

    for conv in conversations:
        conv_id = conv.get("uuid", "")
        if not conv_id:
            continue

        content_hash = compute_content_hash(conv)
        existing_hash = state.get_conversation_hash(conv_id)

        if existing_hash == content_hash:
            skipped += 1
            continue

        try:
            existing_note_id = state.get_trilium_note_id(conv_id)
            note_id = trilium.sync_conversation(conv, existing_note_id)
            state.update_conversation(conv_id, content_hash, note_id)
            synced += 1
        except Exception as e:
            log.error(f"Failed to sync {conv.get('name', conv_id)[:30]}: {e}")
            errors += 1

    log.info(f"Sync complete: {synced} synced, {skipped} unchanged, {errors} errors")


async def async_main():
    """Async main entry point."""
    log.info(f"Claude-Trilium Sync v{get_version()} starting")

    if not CONFIG["trilium_token"]:
        log.error("TRILIUM_TOKEN not set")
        log.error("Get token from Trilium: Options -> ETAPI -> Create new token")
        sys.exit(1)

    if not CONFIG["claude_session_key"]:
        log.error("CLAUDE_SESSION_KEY not set")
        log.error("Get from Claude.ai: DevTools -> Application -> Cookies -> sessionKey")
        sys.exit(1)

    interval = CONFIG["sync_interval"]

    if interval <= 0:
        await run_sync()
    else:
        log.info(f"Running in continuous mode, interval: {interval}s")
        while True:
            try:
                await run_sync()
            except Exception as e:
                log.exception(f"Sync failed: {e}")
            log.info(f"Sleeping {interval}s until next sync...")
            await asyncio.sleep(interval)


def main():
    """Main entry point."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
