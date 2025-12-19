# Claude to Trilium Notes Sync

Automatically sync your Claude.ai conversations to Trilium Notes.

## Features

- **Automatic sync**: Runs periodically to check for new/updated conversations
- **Incremental updates**: Only syncs changed conversations using content hashing
- **Merge support**: Updates existing notes when conversations are extended
- **Formatted output**: Converts messages to nicely styled HTML with code highlighting
- **Cloudflare bypass**: Uses FlareSolverr to handle Claude.ai's Cloudflare protection
- **Docker-ready**: Designed to run as a container alongside FlareSolverr

## Prerequisites

1. **Trilium Notes** instance (self-hosted or TriliumNext)
2. **Claude.ai** account with active conversations
3. **Docker** and Docker Compose
4. **FlareSolverr** - Required for Cloudflare bypass

## Architecture

Claude.ai uses Cloudflare protection that blocks direct API requests. This tool uses [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) to route all requests through a real Chrome browser, bypassing TLS fingerprinting and Cloudflare challenges.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  claude-sync    │────▶│  FlareSolverr   │────▶│   claude.ai     │
│   (this app)    │     │  (real Chrome)  │     │   (Cloudflare)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Trilium Notes  │
│    (ETAPI)      │
└─────────────────┘
```

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

> **Note**: The session key expires periodically. You'll need to update it when syncs start failing with auth errors.

### 3. Configure and Run

```bash
# Clone or copy the files
cd claude-trilium-sync

# Create your .env file
cp .env.example .env

# Edit .env with your tokens
nano .env

# Start the services (includes FlareSolverr)
docker-compose up -d

# Check logs
docker-compose logs -f claude-trilium-sync
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRILIUM_TOKEN` | Yes | - | ETAPI token from Trilium |
| `CLAUDE_SESSION_KEY` | Yes | - | Session cookie from claude.ai |
| `TRILIUM_URL` | No | `http://trilium:8080` | Trilium server URL |
| `FLARESOLVERR_URL` | No | `http://flaresolverr:8191/v1` | FlareSolverr endpoint |
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

1. **Fetch conversations**: Routes requests through FlareSolverr to Claude's internal API
2. **Check for changes**: Computes content hash and compares with last sync
3. **Sync to Trilium**: Creates new notes or updates existing ones via ETAPI
4. **Track state**: Saves sync state to persist between restarts

### Note Structure

Notes are created under a "Claude Chats" parent note with:
- `#claudeChatsRoot` label on parent
- `#claudeChat` label on each conversation
- `#claudeConversationId` with the Claude UUID
- `#claudeUpdatedAt` with last update timestamp

## Docker Compose Setup

The included `docker-compose.yml` sets up both services:

```yaml
services:
  claude-trilium-sync:
    image: ttlequals0/claude-trilium-sync:latest
    environment:
      - TRILIUM_TOKEN=${TRILIUM_TOKEN}
      - CLAUDE_SESSION_KEY=${CLAUDE_SESSION_KEY}
      - TRILIUM_URL=${TRILIUM_URL:-http://trilium:8080}
      - FLARESOLVERR_URL=${FLARESOLVERR_URL:-http://flaresolverr:8191/v1}
    depends_on:
      - flaresolverr

  flaresolverr:
    image: ghcr.io/flaresolverr/flaresolverr:latest
    environment:
      - LOG_LEVEL=info
```

## Alternative: External FlareSolverr

If you already have FlareSolverr running elsewhere:

```bash
FLARESOLVERR_URL=http://192.168.1.100:8191/v1
```

Note: The `/v1` path is required. If omitted, it will be auto-appended.

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

### "403 Forbidden" errors
- Ensure FlareSolverr is running and accessible
- Check `FLARESOLVERR_URL` is correct
- Try restarting FlareSolverr to clear its browser session

### "No conversations found"
- Verify the session key is correct
- Check if you have any conversations in Claude
- Try with `LOG_LEVEL=DEBUG` for more info

### "Invalid authorization for organization"
- This can occur if your account has multiple organizations
- The sync will automatically select an organization with chat access

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
export FLARESOLVERR_URL="http://localhost:8191/v1"
export SYNC_INTERVAL=0

python sync.py
```

## License

MIT
