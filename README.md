# Claude to Trilium Notes Sync

Automatically sync your Claude.ai conversations to Trilium Notes.

## Features

- **Automatic sync**: Runs periodically to check for new/updated conversations
- **Incremental updates**: Only syncs changed conversations using content hashing
- **Merge support**: Updates existing notes when conversations are extended
- **Formatted output**: Converts messages to nicely styled HTML with code highlighting
- **Lightweight**: Uses direct HTTP API calls (no browser/Playwright needed)
- **Docker-ready**: Designed to run as a container

## Prerequisites

1. **Trilium Notes** instance (self-hosted or TriliumNext)
2. **Claude.ai** account with active conversations
3. **Docker** and Docker Compose

## Quick Start

### 1. Get your Trilium ETAPI Token

1. Open Trilium Notes
2. Go to **Options** (gear icon, top right)
3. Navigate to **ETAPI**
4. Click **Create new token**
5. Copy the token

### 2. Get your Claude Session Key

1. Go to [claude.ai](https://claude.ai) and log in
2. Open browser DevTools (F12)
3. Go to **Application** tab → **Cookies** → `claude.ai`
4. Find `sessionKey` and copy its value

> ⚠️ **Note**: The session key expires periodically. You'll need to update it when syncs start failing with auth errors.

### 3. Configure and Run

```bash
# Clone or copy the files
cd claude-trilium-sync

# Create your .env file
cp .env.example .env

# Edit .env with your tokens
nano .env

# Start the sync service
docker-compose up -d

# Check logs
docker-compose logs -f
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRILIUM_TOKEN` | Yes | - | ETAPI token from Trilium |
| `CLAUDE_SESSION_KEY` | Yes | - | Session cookie from claude.ai |
| `TRILIUM_URL` | No | `http://trilium:8080` | Trilium server URL |
| `SYNC_INTERVAL` | No | `3600` | Seconds between syncs (0 = one-shot) |
| `LOG_LEVEL` | No | `INFO` | DEBUG, INFO, WARNING, ERROR |
| `PARENT_NOTE_ID` | No | - | Import under this specific Trilium note ID |
| `PARENT_NOTE_TITLE` | No | `Claude Chats` | Title for auto-created parent note |
| `PUSHOVER_USER_KEY` | No | - | Pushover user key for notifications |
| `PUSHOVER_API_TOKEN` | No | - | Pushover application token |
| `PUSHOVER_DEVICE` | No | - | Specific Pushover device to notify |

### Parent Note Configuration

By default, conversations are imported under a "Claude Chats" note at the root level. You can customize this:

**Option 1: Import under an existing note**

Set `PARENT_NOTE_ID` to the ID of any existing note. Find the note ID by:
- Right-clicking the note in Trilium → "Note Info"
- Or from the URL when viewing the note: `.../#/aBcDeFgHiJkL`

```bash
PARENT_NOTE_ID=aBcDeFgHiJkL
```

**Option 2: Customize the auto-created parent**

```bash
PARENT_NOTE_TITLE="AI Conversations"
```

### Pushover Notifications

Get notified when your Claude session expires so you can update the key:

1. Create a Pushover account at https://pushover.net/
2. Note your **User Key** from the dashboard
3. Create an application at https://pushover.net/apps/build
4. Copy the **API Token**

```bash
PUSHOVER_USER_KEY=uQiRzpo4DXghDmr9QzzfQu27cmVRsG
PUSHOVER_API_TOKEN=azGDORePK8gMaC0QOYAMyEEuzJnyUi
```

You'll receive a high-priority notification when authentication fails, with a direct link to Claude.

## How It Works

1. **Fetch conversations**: Uses Claude's internal API to list all conversations
2. **Check for changes**: Computes content hash and compares with last sync
3. **Sync to Trilium**: Creates new notes or updates existing ones
4. **Track state**: Saves sync state to persist between restarts

### Note Structure

Notes are created under a "Claude Chats" parent note with:
- `#claudeChatsRoot` label on parent
- `#claudeChat` label on each conversation
- `#claudeConversationId` with the Claude UUID
- `#claudeUpdatedAt` with last update timestamp

## Alternative: Cron-based Scheduling

If you prefer cron over the built-in interval:

```bash
# Set SYNC_INTERVAL=0 in .env, then add to crontab:
0 * * * * cd /path/to/claude-trilium-sync && docker-compose run --rm claude-trilium-sync
```

## Connecting to External Trilium

If Trilium isn't in the same Docker network:

```yaml
# docker-compose.yml
services:
  claude-trilium-sync:
    # ...
    environment:
      - TRILIUM_URL=http://192.168.1.100:8080
    network_mode: host  # Or use extra_hosts
```

## Troubleshooting

### "Authentication failed" errors
Your Claude session key has expired. Get a fresh one from the browser.

### "No conversations found"
- Verify the session key is correct
- Check if you have any conversations in Claude
- Try with `LOG_LEVEL=DEBUG` for more info

### Can't connect to Trilium
- Verify `TRILIUM_URL` is correct
- Check network connectivity between containers
- Ensure ETAPI is enabled in Trilium

### Notes not appearing
- Check the "Claude Chats" parent note was created
- Search for `#claudeChat` label in Trilium
- Verify the ETAPI token has write permissions

## Development

Run locally without Docker:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export TRILIUM_TOKEN="your-token"
export CLAUDE_SESSION_KEY="your-session-key"
export TRILIUM_URL="http://localhost:8080"
export SYNC_INTERVAL=0

python sync.py
```

## License

MIT
# claude-trilium-sync
