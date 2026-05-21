# MyFitnessPal MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants like Claude to interact with your MyFitnessPal data, including food diary, exercises, body measurements, nutrition goals, and water intake.

## Features

| Tool | Type | Description |
|------|------|-------------|
| `mfp_get_diary` | Read | Get food diary entries for any date |
| `mfp_search_food` | Read | Search the MyFitnessPal food database |
| `mfp_get_food_details` | Read | Get detailed nutrition info for a food item |
| `mfp_add_food_to_diary` | Write | Add a food item to your diary for a specific meal and date |
| `mfp_get_measurements` | Read | Get weight/body measurement history |
| `mfp_set_measurement` | Write | Log a new weight or body measurement |
| `mfp_get_exercises` | Read | Get logged exercises (cardio & strength) |
| `mfp_get_goals` | Read | Get daily nutrition goals |
| `mfp_set_goals` | Write | Update daily nutrition goals |
| `mfp_get_water` | Read | Get water intake for a date |
| `mfp_set_water` | Write | Log water intake for a date |
| `mfp_get_report` | Read | Get nutrition reports over a date range |
| `refresh_browser_cookies` | Utility | Extract and save session cookies from browser |

## Prerequisites

- **Python 3.10+** (check with `python3 --version`)
- **pip 21.3+** (for pyproject.toml support; upgrade with `pip install --upgrade pip`)
- **MyFitnessPal account**
- **One of the following for authentication:**
  - Your MFP username/email and password (recommended), OR
  - Any Chromium-based browser (Arc, Chrome, Edge, Brave, Vivaldi, Opera, ...)
    or Firefox with an active MyFitnessPal login session

### Authentication Options

This MCP supports multiple authentication methods:

| Method | Setup | Persistence |
|--------|-------|-------------|
| **Chromium browser auto-discovery (macOS, recommended)** | Log into myfitnesspal.com in any Chromium-based browser (Arc, Chrome, Edge, Brave, Vivaldi, Opera, ...). The MCP auto-detects installed browsers via the macOS keychain and uses whichever one is logged in. | Until browser session expires (cached for 30 days in `~/.mfp_mcp/cookies.json`) |
| **Encrypted credentials (legacy)** | Add encrypted `MFP_USERNAME` and `MFP_PASSWORD` to Claude Desktop config; set `MFP_SECRET_KEY` outside the config (for example via shell env or OS keychain) | Form login no longer works against MFP's NextAuth backend — only useful if cached cookies are still valid |
| **Plain credentials (legacy)** | Add `MFP_USERNAME` and `MFP_PASSWORD` to Claude Desktop config | Same as above — form login flow is deprecated |
| **Browser cookies (browser_cookie3 fallback)** | Log into myfitnesspal.com in Chrome or Firefox via the default profile paths | Until browser session expires |

> **Note**: MyFitnessPal migrated their authentication to NextAuth, so the
> legacy form-POST `authenticate_with_credentials` path almost always fails
> for fresh logins. The Chromium auto-discovery path is the reliable way to
> get a session on macOS — just log in via any modern browser and the MCP
> picks it up automatically on the next call.

## Installation

### Option 1: Install from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/myfitnesspal-mcp-python.git
cd myfitnesspal-mcp-python

# Create virtual environment (use python3.10+ on macOS/Linux)
python3 -m venv venv
# On macOS, you may need to specify version: python3.12 -m venv venv

# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# On Windows: .\venv\Scripts\activate

# Upgrade pip (required for pyproject.toml support)
pip install --upgrade pip

# Install the package in editable mode
pip install -e .
```

### Option 2: Install with pip (when published)

```bash
pip install mfp-mcp
```

> **Note**: Option 2 requires the package to be published to PyPI. For now, use Option 1.

### Verify Installation

After installation, verify the server can start:

```bash
# With venv activated
python -m mfp_mcp.server
```

You should see the server waiting for input (it communicates via stdio). Press `Ctrl+C` to stop.

To test authentication (optional):

```bash
MFP_USERNAME="your_email" MFP_PASSWORD="your_password" python -c "
from mfp_mcp.server import get_mfp_client
client = get_mfp_client()
print('Authentication successful!')
"
```

## Configuration for Claude Desktop

### Step 1: Locate Your Config File

| OS | Config File Location |
|----|---------------------|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |

### Step 2: Add the MCP Server Configuration

If the file doesn't exist, create it. Add or merge the following configuration:

#### Option A: With Encrypted Credentials (Enhanced Security)

Encrypt your credentials before storing them in the config file. See [Encrypted Credentials](#encrypted-credentials-enhanced-security) for setup instructions.

> ⚠️ **Security note**: Encryption only provides meaningful protection if `MFP_SECRET_KEY` is stored **separately** from the config file (e.g., set in your shell profile or OS keychain). Storing the key alongside the encrypted values in the same config file means anyone who obtains the config can still decrypt your credentials.

**macOS Example** (with key set separately in your shell environment):
```json
{
  "mcpServers": {
    "myfitnesspal": {
      "command": "/Users/yourname/myfitnesspal-mcp-python/venv/bin/python",
      "args": ["-m", "mfp_mcp.server"],
      "env": {
        "MFP_USERNAME": "gAAAAAB...<encrypted_email>",
        "MFP_PASSWORD": "gAAAAAB...<encrypted_password>"
      }
    }
  }
}
```

#### Option B: With Plain Credentials (No Browser Required)

**macOS Example:**
```json
{
  "mcpServers": {
    "myfitnesspal": {
      "command": "/Users/yourname/myfitnesspal-mcp-python/venv/bin/python",
      "args": ["-m", "mfp_mcp.server"],
      "env": {
        "MFP_USERNAME": "your_email@example.com",
        "MFP_PASSWORD": "your_password"
      }
    }
  }
}
```

**Windows Example:**
```json
{
  "mcpServers": {
    "myfitnesspal": {
      "command": "C:\\Users\\YourName\\myfitnesspal-mcp-python\\venv\\Scripts\\python.exe",
      "args": ["-m", "mfp_mcp.server"],
      "env": {
        "MFP_USERNAME": "your_email@example.com",
        "MFP_PASSWORD": "your_password"
      }
    }
  }
}
```

#### Option C: Without Credentials (Browser Cookie Fallback)

**macOS Example:**
```json
{
  "mcpServers": {
    "myfitnesspal": {
      "command": "/Users/yourname/myfitnesspal-mcp-python/venv/bin/python",
      "args": ["-m", "mfp_mcp.server"]
    }
  }
}
```

> ⚠️ **Important**: Use **full absolute paths** to the Python executable in your virtual environment. Replace `yourname`/`YourName` with your actual username.

### Step 3: Restart Claude Desktop

After saving the config file, **completely quit and restart Claude Desktop** for the changes to take effect.

### Step 4: Verify Connection

In Claude Desktop, you should see a hammer icon (🔨) indicating MCP tools are available. Try asking:

> "Show my MyFitnessPal diary for today"

## Authentication Methods

The MCP server supports three authentication methods, tried in this order:

### 1. Environment Variables (Recommended)
Set `MFP_USERNAME` and `MFP_PASSWORD` in your Claude Desktop config's `env` section. This is the most reliable method and doesn't require a browser. You can store them as plain text or encrypted (see below).

```json
"env": {
  "MFP_USERNAME": "your_email@example.com",
  "MFP_PASSWORD": "your_password"
}
```

### Encrypted Credentials (Enhanced Security)

Instead of storing plain-text credentials, you can encrypt them using [Fernet symmetric encryption](https://cryptography.io/en/latest/fernet/) from the `cryptography` library. The server decrypts them at runtime using `MFP_SECRET_KEY`.

> ⚠️ **Important**: For encryption to be meaningful, `MFP_SECRET_KEY` must be kept **outside** the Claude Desktop config file. The server resolves it in this order:
> 1. `MFP_SECRET_KEY` environment variable (shell profile, not the Claude config)
> 2. OS keychain — service `mfp-mcp`, account `MFP_SECRET_KEY` **(recommended)**

**Step 1 — Generate and store the key in one command:**

```bash
npm install
npm run store-key
```

`store-key` generates a Fernet-compatible key, stores it in the OS keychain (`mfp-mcp` / `MFP_SECRET_KEY`), and prints the key so you can use it in Step 2. See [Key Management CLI](#key-management-cli) for all available flags.

**Step 2 — Encrypt your credentials:**

```python
from cryptography.fernet import Fernet

key = b"abc123XYZ...=="  # your key from Step 1
f = Fernet(key)

encrypted_user = f.encrypt(b"your_email@example.com").decode()
encrypted_pass = f.encrypt(b"your_password").decode()

print("MFP_USERNAME:", encrypted_user)
print("MFP_PASSWORD:", encrypted_pass)
```

**Step 3 — Add only the encrypted values to your Claude Desktop config:**

```json
"env": {
  "MFP_USERNAME": "gAAAAAB...<encrypted>",
  "MFP_PASSWORD": "gAAAAAB...<encrypted>"
}
```

The key stays in the keychain — it never touches the config file.

**Alternative: shell profile (simpler, still outside the Claude config):**

```bash
# Add to ~/.zshrc or ~/.bashrc — do NOT put this in claude_desktop_config.json
export MFP_SECRET_KEY="abc123XYZ...=="
```

If `MFP_SECRET_KEY` is not found in the environment or keychain, the server treats `MFP_USERNAME` and `MFP_PASSWORD` as plain text (backward compatible).

### 2. Stored Session Cookies
After successful authentication, session cookies are saved to `~/.mfp_mcp/cookies.json`. These persist for 30 days, so you won't need to re-authenticate frequently.

### 3. Chromium Browser Auto-Discovery (macOS)

If no credentials are provided and stored cookies are absent or expired, the
server scans the macOS keychain for `<Browser> Safe Storage` entries to find
every installed Chromium-based browser, then tries each one's cookies
database until it finds a valid MyFitnessPal session token.

This works out of the box with Arc, Chrome, Edge, Brave, Vivaldi, Opera,
Chromium, and any other Chromium-derived browser. You only need to be
logged into [myfitnesspal.com](https://www.myfitnesspal.com) in one of
them.

The first successful extraction is persisted to `~/.mfp_mcp/cookies.json`,
so subsequent calls skip the discovery step until the session expires.

You can also force a specific browser via the `refresh_browser_cookies`
MCP tool:

```
refresh_browser_cookies(browser="arc")     # or "chrome", "edge", "brave", ...
refresh_browser_cookies(browser="auto")    # scan everything (default)
refresh_browser_cookies(browser="firefox") # via browser_cookie3
```

### 4. browser_cookie3 Fallback (Legacy)
A final fallback uses [`browser_cookie3`](https://pypi.org/project/browser-cookie3/)
to read Chrome or Firefox cookies from the default profile paths. Useful on
Linux/Windows or if the macOS auto-discovery path can't access your
keychain.

## Security Note on Credentials

Your MyFitnessPal credentials in the Claude Desktop config are stored locally on your machine. The config file is only readable by your user account. Options to harden this further:

1. **Encrypt credentials + store the key in the OS keychain** — the strongest option. The ciphertext lives in the config; the key never does. See [Encrypted Credentials](#encrypted-credentials-enhanced-security).
2. **Encrypt credentials + export the key in your shell profile** — still separates key from ciphertext, though the key is on disk.
3. Use browser cookies instead (no credentials stored in config at all)
4. Use a dedicated MyFitnessPal account for API access
5. Session cookies are stored in `~/.mfp_mcp/cookies.json` with restricted permissions

## Usage Examples

Once configured, you can interact with your MyFitnessPal data through Claude:

### Food Diary
```
"Show me what I ate today"
"Get my food diary for 2026-01-05"
"What meals did I log yesterday?"
```

### Track Weight Progress
```
"Show my weight history for the past 30 days"
"Log my weight as 232.5 pounds"
"What's my weight trend this month?"
```

### Search Foods
```
"Search MyFitnessPal for chicken breast"
"Find nutrition info for Greek yogurt"
"Look up calories in a banana"
```

### Check Goals vs Actual
```
"Compare my nutrition goals to what I actually ate today"
"Am I on track with my protein intake?"
"How many calories do I have left today?"
```

### Exercise Log
```
"What exercises did I log today?"
"Show my workout from yesterday"
```

### Nutrition Reports
```
"Show my calorie intake over the past week"
"What's my average protein intake this week?"
"Generate a nutrition report for January"
```

## Key Management CLI

`scripts/store-key.ts` is a one-time setup tool that generates and stores `MFP_SECRET_KEY` in your OS keychain (macOS Keychain, Windows Credential Vault, Linux Secret Service). Node.js 18+ is required.

### Prerequisites

```bash
npm install
```

### Commands

| Command | What it does |
|---------|-------------|
| `npm run store-key` | Generate a new Fernet key and store it in the keychain |
| `npm run store-key -- --key <val>` | Store an existing key instead of generating one |
| `npm run store-key -- --overwrite` | Replace a key that is already stored |
| `npm run store-key -- --show` | Print the currently stored key |
| `npm run store-key -- --delete` | Remove the stored key from the keychain |

### Example output

```
✅ MFP_SECRET_KEY stored in OS keychain
   service : mfp-mcp
   account : MFP_SECRET_KEY
   source  : generated

Your key (use this to encrypt MFP_USERNAME / MFP_PASSWORD):

  abc123XYZ...==

Next — encrypt your credentials with Python:

  from cryptography.fernet import Fernet
  f = Fernet(b"abc123XYZ...==")
  print("MFP_USERNAME:", f.encrypt(b"your_email@example.com").decode())
  print("MFP_PASSWORD:", f.encrypt(b"your_password").decode())
```

## Project Structure

```
myfitnesspal-mcp-python/
├── Dockerfile              # Container deployment
├── package.json            # Node tooling (store-key CLI)
├── tsconfig.json           # TypeScript config for scripts/
├── pyproject.toml          # Python package configuration
├── README.md               # This file
├── scripts/
│   └── store-key.ts        # One-time key management CLI
└── src/
    └── mfp_mcp/
        ├── __init__.py     # Package initialization
        └── server.py       # MCP server implementation
```

## Development

### Setup Development Environment

```bash
# Clone and enter directory
git clone https://github.com/YOUR_USERNAME/myfitnesspal-mcp-python.git
cd myfitnesspal-mcp-python

# Create virtual environment (Python 3.10+ required)
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and install with dev dependencies
pip install --upgrade pip
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Code Formatting

```bash
black src/
isort src/
ruff check src/
```

### Type Checking

```bash
mypy src/
```

## Docker Deployment

> ⚠️ **Note**: Docker deployment requires mounting your browser's cookie database for authentication.

```bash
# Build the image
docker build -t mfp-mcp .

# Run with Chrome cookies mounted (Linux example)
docker run -it --rm \
  -v ~/.config/google-chrome:/root/.config/google-chrome:ro \
  mfp-mcp
```

## Troubleshooting

### "python: command not found" or wrong Python version

**Problem**: Python is not in PATH or you need to specify version.

**Solutions**:
1. On macOS/Linux, use `python3` instead of `python`
2. Check your version: `python3 --version` (must be 3.10+)
3. If needed, install Python 3.12 via Homebrew: `brew install python@3.12`
4. Then create venv with: `python3.12 -m venv venv`

### "pip install -e ." fails with "setup.py not found"

**Problem**: Your pip version is too old to support pyproject.toml builds.

**Solution**: Upgrade pip first:
```bash
pip install --upgrade pip
pip install -e .
```

### "Failed to authenticate with MyFitnessPal"

**Problem**: The server can't authenticate with your credentials or read browser cookies.

**Solutions**:
1. **Easiest (macOS)**: Log into [myfitnesspal.com](https://www.myfitnesspal.com)
   in any Chromium-based browser (Arc, Chrome, Edge, Brave, ...). The MCP
   will auto-discover the session on the next call.
2. **Force a refresh**: Call the `refresh_browser_cookies` tool — `auto`
   scans every browser, or pass a specific name (`arc`, `chrome`, `edge`,
   `brave`, `vivaldi`, `opera`, `firefox`).
3. **If using credentials**: Double-check your MFP_USERNAME and MFP_PASSWORD
   in the config. Note that the legacy form-login flow no longer works
   against MFP's NextAuth backend — credentials are only useful while
   `~/.mfp_mcp/cookies.json` still holds a valid session.
4. Try logging out and back in to MyFitnessPal in your browser.
5. Clear `~/.mfp_mcp/cookies.json` and let the auto-discovery rebuild it.
6. On **macOS**, the auto-discovery path needs to read your login keychain.
   If the MCP runs inside Claude Desktop, you may see a one-time keychain
   prompt — click "Always Allow".

### "No module named 'mfp_mcp'"

**Problem**: Package not installed or wrong Python environment.

**Solutions**:
1. Ensure you're using the correct Python from your virtual environment
2. Reinstall the package: `pip install -e .`
3. Verify the path in your Claude Desktop config points to the venv Python:
   ```
   /path/to/project/venv/bin/python  # macOS/Linux
   C:\path\to\project\venv\Scripts\python.exe  # Windows
   ```

### Tools not appearing in Claude Desktop

**Problem**: MCP server not connecting.

**Solutions**:
1. Check the config file syntax (must be valid JSON - use a JSON validator)
2. Use **absolute paths** in the configuration (no `~` or relative paths)
3. Restart Claude Desktop completely (Cmd+Q on macOS, then relaunch)
4. Check Claude Desktop logs:
   - macOS: `~/Library/Logs/Claude/`
   - Windows: `%APPDATA%\Claude\logs\`

### Empty responses or no data

**Problem**: Authentication works but no data returned.

**Solutions**:
1. Verify you have data logged in MyFitnessPal for the requested date
2. Check the date format (YYYY-MM-DD)
3. Try a recent date where you know you have entries

### Double parentheses in terminal prompt like "((venv) )"

**Problem**: VS Code/Cursor Python extension bug with venv prompt.

**Solutions**:
1. Update the Python extension in VS Code/Cursor
2. Or manually fix the venv activate script - change line ~70 in `venv/bin/activate`:
   ```bash
   # Change from:
   PS1="("'(venv) '") ${PS1:-}"
   # To:
   PS1="(venv) ${PS1:-}"
   ```

## API Reference

### mfp_get_diary
Get food diary for a specific date.
- `date` (optional): YYYY-MM-DD format, defaults to today
- `response_format`: "markdown" or "json"

### mfp_search_food
Search the MyFitnessPal food database.
- `query` (required): Search term
- `limit` (optional): Max results (default 10, max 50)
- `response_format`: "markdown" or "json"

### mfp_get_food_details
Get detailed nutrition for a food item.
- `mfp_id` (required): MyFitnessPal food ID from search results
- `response_format`: "markdown" or "json"

### mfp_add_food_to_diary
Add a food item to your diary for a specific meal and date.
- `mfp_id` (required): MyFitnessPal food ID from search results (use `mfp_search_food` first)
- `meal` (optional): Meal name - "Breakfast", "Lunch", "Dinner", or "Snacks" (default: "Breakfast")
- `date` (optional): YYYY-MM-DD format (default: today)
- `quantity` (optional): Number of servings (default: 1.0)
- `unit` (optional): Unit/serving size description (e.g., "1 cup", "100g")

**Example workflow:**
1. Use `mfp_search_food` to find a food item and get its `mfp_id`
2. Use `mfp_add_food_to_diary` with the `mfp_id` to add it to your diary

### mfp_get_measurements
Get body measurement history.
- `measurement` (optional): "Weight", "Body Fat", "Waist", etc.
- `start_date` (optional): YYYY-MM-DD (default 30 days ago)
- `end_date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

### mfp_set_measurement
Log a body measurement for today.
- `measurement` (optional): Type (default "Weight")
- `value` (required): Numeric value

### mfp_get_exercises
Get exercise log for a date.
- `date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

### mfp_get_goals
Get daily nutrition goals.
- `date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

### mfp_set_goals
Update nutrition goals.
- `calories` (optional): Daily calorie goal
- `protein` (optional): Daily protein in grams
- `carbohydrates` (optional): Daily carbs in grams
- `fat` (optional): Daily fat in grams

### mfp_get_water
Get water intake for a date.
- `date` (optional): YYYY-MM-DD (default today)

### mfp_set_water
Log water intake for a date.
- `cups` (required): Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit (1 cup = ~237ml)
- `date` (optional): YYYY-MM-DD format (default: today)

### mfp_get_report
Get nutrition report over a date range.
- `report_name` (optional): "Net Calories", "Protein", "Fat", "Carbs"
- `start_date` (optional): YYYY-MM-DD (default 7 days ago)
- `end_date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

## Security & Privacy

- **Encrypted Credentials**: Credentials can be stored as Fernet-encrypted ciphertext in your config. `MFP_SECRET_KEY` is resolved at runtime from the environment variable first, then the OS keychain (`mfp-mcp` / `MFP_SECRET_KEY`). See [Encrypted Credentials](#encrypted-credentials-enhanced-security) for setup.
- **OS Keychain**: Storing `MFP_SECRET_KEY` in the native keychain (macOS Keychain, Windows Credential Vault, Linux Secret Service) means the decryption key never touches the config file or any backup.
- **Plain Credentials**: If `MFP_SECRET_KEY` is absent from both environment and keychain, `MFP_USERNAME` and `MFP_PASSWORD` are used as-is (backward compatible).
- **Session Cookies**: After successful authentication, session cookies are cached in `~/.mfp_mcp/cookies.json` (restricted permissions) for 30 days.
- **Browser Cookies**: As a fallback, the server can read your browser cookies to authenticate with MyFitnessPal.
- **Local Only**: The server runs locally on your machine via stdio transport. No data is sent to any third-party servers.
- **No External Transmission**: Your MyFitnessPal data is only transmitted between your computer and MyFitnessPal's servers (myfitnesspal.com).

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [python-myfitnesspal](https://github.com/coddingtonbear/python-myfitnesspal) - The underlying library for MyFitnessPal access
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) - Model Context Protocol framework
- [Anthropic](https://anthropic.com) - Claude and the MCP specification
