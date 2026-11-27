# MyFitnessPal MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants like Claude to interact with your MyFitnessPal data, including food diary, exercises, body measurements, nutrition goals, and water intake.

## Features

| Tool | Type | Description |
|------|------|-------------|
| `mfp_get_diary` | Read | Get food diary entries for any date |
| `mfp_get_food_entries` | Read | List a day's individual food entries with the time each was eaten |
| `mfp_search_food` | Read | Search the MyFitnessPal food database |
| `mfp_get_food_details` | Read | Get detailed nutrition info for a food item |
| `mfp_add_food_to_diary` | Write | Add a food item to your diary for a specific meal and date |
| `mfp_list_meals` | Read | List the account's configured meal names (incl. renamed/custom) for use with `mfp_add_food_to_diary` |
| `mfp_quick_add` | Write | Quick Add raw calories (+ optional macros) with no food lookup |
| `mfp_remove_food_from_diary` | Write | Remove a logged entry from your diary |
| `mfp_create_custom_food` | Write | Create a private custom food with a full nutrition panel |
| `mfp_list_own_foods` | Read | List your own custom foods (private ones do not appear in search) |
| `mfp_delete_custom_food` | Write | Delete one of your custom foods |
| `mfp_get_measurements` | Read | Get weight/body measurement history |
| `mfp_set_measurement` | Write | Log a new weight or body measurement |
| `mfp_get_exercises` | Read | Get logged exercises (cardio & strength) |
| `mfp_get_goals` | Read | Get nutrition goals (per-day with `all_days`) |
| `mfp_set_goals` | Write | Update nutrition goals (whole week or a single day) |
| `mfp_get_water` | Read | Get water intake for a date |
| `mfp_set_water` | Write | Log water intake for a date |
| `mfp_get_steps` | Read | Get daily step counts synced from Apple Health / devices |
| `mfp_log_fast` | Write | Log a completed intermittent fasting window (start + end) |
| `mfp_update_fast` | Write | Update the start/end times of an existing fasting entry |
| `mfp_delete_fast` | Write | Delete a fasting entry by id |
| `mfp_get_report` | Read | Get nutrition reports over a date range |
| `refresh_browser_cookies` | Utility | Extract and save session cookies from browser |

## How diary writes work

MyFitnessPal has no public API. Reads here are scraped from the website via
[`python-myfitnesspal`](https://github.com/coddingtonbear/python-myfitnesspal), and **diary
writes go through MFP's internal v2 JSON API** — the same one their web client uses,
authenticated with your existing session token.

**Custom-food writes** (`mfp_create_custom_food`, `mfp_list_own_foods`,
`mfp_delete_custom_food`) use a different endpoint family: MFP's v2 API exposes no
custom-food create, so these call the same cookie-authenticated web endpoints their
website uses (`/api/auth/csrf`, `/api/services/users/foods/mine`, `/api/services/foods`).
No browser needs to be running — the stored session cookies are sufficient.

That interface is undocumented and was determined by observing the web client. It works today,
but MyFitnessPal can change it without notice. They have already done so once: this server
originally posted to `/food/diary/{user}/add`, which now returns 404, leaving food logging
broken. If logging starts failing, that is the most likely cause.

## How fasting works (write-only)

**Fasting tools** (`mfp_log_fast`, `mfp_update_fast`, `mfp_delete_fast`) POST / PATCH /
DELETE against `/v2/diary/fasting_entry` on the same v2 JSON API. Payloads match the
shape captured from the iOS app:

```json
{"items": [{
  "type": "fasting_entry",
  "id": "UPPERCASE-UUID",
  "fast_started": "2026-08-06T13:00:00Z",
  "fast_ended":   "2026-08-07T05:00:00Z"
}]}
```

Ids are client-generated UUIDv4s in uppercase (the iOS convention). The MCP auto-generates
one when you omit `id` from `mfp_log_fast`; save the returned id if you plan to update or
delete the entry.

**There is no read endpoint.** MFP exposes no GET for fasting entries — `GET /v2/diary/fasting_entry`
returns `405 Method Not Allowed`. The mobile app populates its Fasting History screen via a
delta-sync channel (`mobile-sync-api.myfitnesspal.com/v2.1/sync`) that requires a pre-issued
sync token, is scoped to the mobile OAuth client, and rejects the web-session bearer this
server authenticates with. You'll continue to read fasting history in the MFP app itself
until Under Armour publishes something.

The write tools are still useful for automating log-entry (e.g. inferring fasts from your
Garmin sleep window + first-meal timestamp) or correcting entries programmatically.

## Prerequisites

- **Python 3.10–3.12** (check with `python3 --version`)

  Not 3.13+: `lxml`, pulled in by `myfitnesspal`, has no wheels for it and fails to build
  against the 3.14 C API. On macOS, `brew install python@3.12`.

- **pip 21.3+** (for pyproject.toml support; upgrade with `pip install --upgrade pip`)
- **MyFitnessPal account**
- **One of the following for authentication:**
  - **Linux:** Google Chrome and Xvfb, for the `mfp-mcp-login` command. See [The mfp-mcp-login Command](#the-mfp-mcp-login-command).
  - **Recommended (macOS):** any Chromium-based browser (Arc, Dia, Chrome, Edge,
    Brave, Vivaldi, Opera, ...) with an active MyFitnessPal login session —
    the MCP auto-discovers the session on next call
  - Firefox with an active MyFitnessPal login session (via the
    `browser_cookie3` fallback)
  - Legacy: your MFP username/email and password (see caveats below —
    MFP's NextAuth backend rejects the form-POST flow, so credential auth
    only works while cached cookies remain valid)

### Authentication Options

This MCP supports multiple authentication methods:

| Method | Setup | Persistence |
|--------|-------|-------------|
| **`mfp-mcp-login` command, recommended on Linux** | Run `mfp-mcp-login` once. It logs in through a headed Google Chrome. It saves the session to `~/.mfp_mcp/cookies.json`. | Until the session expires. The server ignores a file over 30 days old. |
| **Chromium browser auto-discovery (macOS, recommended)** | Log into myfitnesspal.com in any Chromium-based browser (Arc, Dia, Chrome, Edge, Brave, Vivaldi, Opera, ...). The MCP auto-detects installed browsers via the macOS keychain and uses whichever one is logged in. | Until browser session expires (cached for 30 days in `~/.mfp_mcp/cookies.json`) |
| **Encrypted credentials (legacy)** | Add encrypted `MFP_USERNAME` and `MFP_PASSWORD` to Claude Desktop config; set `MFP_SECRET_KEY` outside the config (for example via shell env or OS keychain) | Form login no longer works against MFP's NextAuth backend — only useful if cached cookies are still valid |
| **Plain credentials (legacy)** | Add `MFP_USERNAME` and `MFP_PASSWORD` to Claude Desktop config | Same as above — form login flow is deprecated |
| **Browser cookies (browser_cookie3 fallback)** | Log into myfitnesspal.com in Chrome or Firefox via the default profile paths | Until browser session expires |

> **Note**: MyFitnessPal moved its login to NextAuth. So the legacy `authenticate_with_credentials` form login almost always fails. On macOS, Chromium auto-discovery picks up a browser session. Log in with any Chromium browser first. On Linux, auto-discovery does not run. Log in with `mfp-mcp-login` there instead.

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

# Install the package and its login extra in editable mode
pip install -e ".[login]"
```

The `login` extra adds `websockets>=11` and `requests`. The `mfp-mcp-login` command needs them.

### Option 2: Install from GitHub

```bash
pip install "mfp-mcp[login] @ git+https://github.com/AdamWalt/myfitnesspal-mcp-python.git"
```

> **Note**: This form works once the login command merges upstream. Until then, use Option 1. The package is not on PyPI. The `mfp-mcp` name there belongs to another project.

### Verify Installation

After installation, verify the server can start:

```bash
# With venv activated
python -m mfp_mcp.server
```

You should see the server waiting for input (it communicates via stdio). Press `Ctrl+C` to stop.

To check a saved session without logging in:

```bash
mfp-mcp-login --check
```

It exits 0 when the saved session still works. With no session yet, it prints `check: no cookie file` and exits 4. Then log in as [The mfp-mcp-login Command](#the-mfp-mcp-login-command) shows.

## The mfp-mcp-login Command

`mfp-mcp-login` logs in to MyFitnessPal and saves the session. It drives a headed Chrome over the DevTools protocol. Cloudflare Turnstile never clears in headless Chrome. The session goes to `~/.mfp_mcp/cookies.json`, the file the server reads. The server re-reads that file on every call. So it needs no restart after a login.

The command comes with the `login` extra, as [Installation](#installation) shows. Run it from the activated virtual environment. `python -m mfp_mcp.login` runs the same command.

### Usage

```bash
mfp-mcp-login                  # check the saved session, log in only when it fails
mfp-mcp-login --check          # check the saved session, never log in
mfp-mcp-login --dry-run        # log in and verify, write no cookie file
mfp-mcp-login --install-xvfb   # on Linux, install Xvfb with apt when it is missing
```

- With no flag, it checks the saved session first. It logs in only when that check fails.
- `--check` never logs in. It takes no lock and never touches the attempt log.
- `--dry-run` skips the saved-session check and always logs in. Its submission counts against the attempt window.
- `--check` and `--dry-run` cannot be combined.
- `--install-xvfb` combines with a plain run or `--dry-run`.

A login keeps only the `myfitnesspal.com` cookies. It verifies them against `/user/auth_token` twice. One request sends Chrome's user agent. The other sends the one `python-myfitnesspal` uses. Only then does it write the cookie file. The write is atomic, with mode `0600`.

### Linux

The command needs Google Chrome and Xvfb. Chrome draws on a private Xvfb display. No window appears.

Install Google Chrome from <https://www.google.com/chrome/>. The command searches `PATH` in this order. It tries `google-chrome`, `google-chrome-stable`, `chromium`, then `chromium-browser`. It skips a snap Chromium, which it does not support.

With Xvfb missing from `PATH`, a run exits 2. It prints how to install Xvfb. Install Xvfb with your package manager:

| Distribution | Command |
|--------------|---------|
| Debian, Ubuntu and other `apt-get` systems | `sudo apt-get install xvfb` |
| Fedora | `sudo dnf install xorg-x11-server-Xvfb` |
| Arch | `sudo pacman -S xorg-server-xvfb` |

On an `apt-get` system, `--install-xvfb` can run it for you. It runs only when Xvfb is missing from `PATH`. It needs a terminal, so apt can ask first. With no terminal or no `apt-get`, it exits 2. It then prints how to install Xvfb instead.

### macOS

macOS support is experimental. It was never run live. The command prints one line saying so on every run.

Install Chrome with `brew install --cask google-chrome`. The command looks for it in `/Applications/Google Chrome.app`. macOS needs no Xvfb. The Chrome window opens off-screen instead.

### Windows

The command does not run on Windows directly. It exits 2 there. Run it under WSL2, where the Linux steps apply.

### Credentials

Give your credentials to `mfp-mcp-login` only. Keep them out of the server config. The server would post them whenever its session fails.

The command reads `MFP_USERNAME` and `MFP_PASSWORD` from the environment. It prompts on the terminal for an unset one:

```
MyFitnessPal email:
MyFitnessPal password:
```

The password prompt hides what you type. A typed value is used as typed, never decrypted. With no terminal, an unset value exits 2. Output never shows a credential, the key or a cookie. Chrome, Xvfb and helper commands get no `MFP_*` variable.

### Encrypted Credentials

The environment values may be encrypted with [Fernet symmetric encryption](https://cryptography.io/en/latest/fernet/). The command decrypts them as the server does. It looks for the key in this order:

1. The `MFP_SECRET_KEY` environment variable.
2. The OS keychain, service `mfp-mcp`, account `MFP_SECRET_KEY`. This is the recommended place.

The key lookup runs only when a value looks encrypted. A plain value is used as is. An encrypted value with no key exits 2. So does a value that fails to decrypt.

**Step 1: Generate the key and store it.**

```bash
npm install
npm run store-key
```

`store-key` generates a Fernet key. It stores the key in the OS keychain. It also prints the key for Step 2. See [Key Management CLI](#key-management-cli) for every flag.

**Step 2: Encrypt your credentials.**

```python
from cryptography.fernet import Fernet

key = b"abc123XYZ...=="  # your key from Step 1
f = Fernet(key)

encrypted_user = f.encrypt(b"your_email@example.com").decode()
encrypted_pass = f.encrypt(b"your_password").decode()

print("MFP_USERNAME:", encrypted_user)
print("MFP_PASSWORD:", encrypted_pass)
```

**Step 3: Export the encrypted values, then run the command.**

```bash
export MFP_USERNAME=gAAAAAB...
export MFP_PASSWORD=gAAAAAB...
mfp-mcp-login
```

Fernet tokens need no quotes. Never export the plain password this way. Use the prompt for plain values.

The key stays in the keychain. You can export it from your shell profile instead:

```bash
# Add to ~/.zshrc or ~/.bashrc
export MFP_SECRET_KEY="abc123XYZ...=="
```

### Attempt Window

The command allows 3 login submissions in any 24 hours. Each submission appends one UTC timestamp to `~/.mfp_mcp/login-attempts.log`. Dry runs count too. The window is checked before any prompt or browser starts.

- A full window stops a login with exit 6. It prints the log path and when the window reopens.
- A submission stops counting 24 hours after it was made.
- A non-timestamp line counts against the limit. Such a line is never dropped. When such lines fill the window, exit 6 counts them. Delete them to log in again.
- Each run except `--check` drops timestamps older than 30 days.
- To reset the window, delete `~/.mfp_mcp/login-attempts.log`.

Every run except `--check` holds `~/.mfp_mcp/login.lock` while it works. A second run at the same time exits 2.

### Session Age

`--check` fails a session saved 29 days ago or more. The server ignores a cookie file over 30 days old. So `--check` flags an old session a day early. A plain `mfp-mcp-login` then logs in again.

`--check` also needs a real session cookie. Both verify requests must pass too.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Session saved, verified in a dry run, or still valid |
| 2 | Bad usage, or Windows outside WSL2 |
| 2 | A credential is missing, or it fails to decrypt |
| 2 | No Chrome, or no Xvfb |
| 2 | The Xvfb install or start failed |
| 2 | The `login` extra is missing |
| 2 | Another run holds the lock |
| 3 | Captcha, stuck Turnstile, account lock or rate-limit page |
| 4 | No cookie file, or the file is unreadable |
| 4 | Verification failed, or the session reached 29 days |
| 5 | No login form, or a field refused its text |
| 5 | Another page after submit, or a timeout |
| 5 | An unexpected error |
| 6 | Three submissions in 24 hours, or unreadable log lines |
| 128 plus N | Stopped by signal N: SIGINT, SIGTERM or SIGHUP |

On exit 3 or 5, a page excerpt may print. It is redacted and at most 300 characters. Only a login or challenge page gets one. A stopped run kills Chrome and Xvfb before it exits.

## Configuration for Claude Desktop

### Step 1: Locate Your Config File

| OS | Config File Location |
|----|---------------------|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |

### Step 2: Add the MCP Server Configuration

If the file doesn't exist, create it. Add or merge the following configuration:

#### Option A: No Credentials, Recommended

This setup puts no credentials in the config. The server reads the session from `~/.mfp_mcp/cookies.json`. On Linux, create it first with [`mfp-mcp-login`](#the-mfp-mcp-login-command). On macOS, a logged-in Chromium browser can supply it instead.

Give credentials to `mfp-mcp-login` only. The server posts `env` credentials on every failed call. The server's form login rarely works against NextAuth.

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

On Linux, use the same `command` and `args`.

#### Option B: Encrypted Credentials, Legacy

Not recommended, for the reasons under Option A. Encrypt your credentials before storing them in the config. See [Encrypted Credentials](#encrypted-credentials) for the setup.

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

#### Option C: Plain Credentials, Legacy

Not recommended. This puts your password in plaintext in the config.

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

> ⚠️ **Important**: Use **full absolute paths** to the Python executable in your virtual environment. Replace `yourname`/`YourName` with your actual username.

### Step 3: Restart Claude Desktop

After saving the config file, **completely quit and restart Claude Desktop** for the changes to take effect.

### Step 4: Verify Connection

In Claude Desktop, you should see a hammer icon (🔨) indicating MCP tools are available. Try asking:

> "Show my MyFitnessPal diary for today"

## Authentication Methods

The server tries four methods, in this order. `mfp-mcp-login` is not one of them. It writes the cookie file that method 2 reads.

### 1. Environment Variables (Legacy)
Set `MFP_USERNAME` and `MFP_PASSWORD` in your Claude Desktop config's `env`
section. You can store them as plain text or encrypted (see below).

> ⚠️ **Note**: MyFitnessPal migrated to a NextAuth backend, so the form-POST
> flow this method uses no longer produces a session cookie. Credential auth
> only succeeds while `~/.mfp_mcp/cookies.json` still holds a valid session
> from a previous browser login — after that, this method silently falls
> through to the browser cookie paths below. Prefer the Chromium
> auto-discovery method on macOS.

```json
"env": {
  "MFP_USERNAME": "your_email@example.com",
  "MFP_PASSWORD": "your_password"
}
```

Not recommended. The server posts these on every failed call. Give credentials to `mfp-mcp-login` instead.

The encrypted credentials setup now lives under the login command. See [Encrypted Credentials](#encrypted-credentials).

### 2. Stored Session Cookies
After successful authentication, session cookies are saved to `~/.mfp_mcp/cookies.json`. These persist for 30 days, so you won't need to re-authenticate frequently.

`mfp-mcp-login` writes this file too. The server re-reads it on every call.

### 3. Chromium Browser Auto-Discovery (macOS)

If no credentials are provided and stored cookies are absent or expired, the
server scans the macOS keychain for `<Browser> Safe Storage` entries to find
every installed Chromium-based browser, then tries each one's cookies
database until it finds a valid MyFitnessPal session token.

This works out of the box with Arc, Dia, Chrome, Edge, Brave, Vivaldi, Opera,
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

A final fallback uses [`browser_cookie3`](https://pypi.org/project/browser-cookie3/). It reads Chrome or Firefox cookies from default profile paths. It may help when macOS auto-discovery cannot reach your keychain. Do not rely on it on Linux. Use `mfp-mcp-login` there.

## Security Note on Credentials

Your MyFitnessPal credentials in the Claude Desktop config are stored locally on your machine. The config file is only readable by your user account. Options to harden this further:

### 1. **Encrypt credentials + store the key in the OS keychain**

The strongest option. The ciphertext lives in the config; the key never does. See [Encrypted Credentials](#encrypted-credentials).

### 2. **Encrypt credentials + export the key in your shell profile**

Still separates key from ciphertext, though the key is on disk.

### 3. Storing `MFP_PASSWORD` in your MCP client

Avoid storing `MFP_PASSWORD` in your MCP client config. It sits there in **plaintext on disk**. Anything running as your user can read it. It also buys little. The server's form login rarely works against NextAuth. Yet the server posts the password on every failed call. Give it to `mfp-mcp-login` instead.

### 4. Use browser cookies instead (no credentials stored in config at all)

Prefer browser-cookie auth if you would rather not store the password: log into
myfitnesspal.com and the server reads the session from your browser. The cost is that MFP
sessions expire, so you will occasionally need to log in again.

Files the server and `mfp-mcp-login` write to `~/.mfp_mcp/`. The folder has mode `0700`.

| File | Contents | Mode |
|------|----------|------|
| `cookies.json` | Session cookies — full account access, treat as a password | `0600` |
| `login-attempts.log` | One UTC timestamp per `mfp-mcp-login` submission | `0600` |
| `login.lock` | Empty lock file, held during an `mfp-mcp-login` run | `0600` |

Note that this server can **modify your diary** — adding food entries and updating goals,
measurements, and water.

## Usage Examples

Once configured, you can interact with your MyFitnessPal data through Claude:

### Food Diary
```
"Show me what I ate today"
"Get my food diary for 2026-01-05"
"What meals did I log yesterday?"
"What time did I have my first and last food today?"
```

### Logging and Correcting Food
```
"Log a grilled chicken breast, 6 oz, for lunch"
"Add 2 cups of oatmeal to breakfast"
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
        ├── login.py        # mfp-mcp-login command
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
pip install -e ".[dev,login]"
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
pip install -e ".[login]"
```

### "Failed to authenticate with MyFitnessPal"

**Problem**: The server can't authenticate with your credentials or read browser cookies.

**Solutions**:
1. **Easiest (macOS)**: Log into [myfitnesspal.com](https://www.myfitnesspal.com)
   in any Chromium-based browser (Arc, Dia, Chrome, Edge, Brave, ...). The MCP
   will auto-discover the session on the next call.
2. **Force a refresh**: Call the `refresh_browser_cookies` tool — `auto`
   scans every browser, or pass a specific name (`arc`, `dia`, `chrome`, `edge`,
   `brave`, `vivaldi`, `opera`, `firefox`).
3. **If using credentials**: Double-check your MFP_USERNAME and MFP_PASSWORD
   in the config. Note that the legacy form-login flow no longer works
   against MFP's NextAuth backend — credentials are only useful while
   `~/.mfp_mcp/cookies.json` still holds a valid session.
4. Try logging out and back in to MyFitnessPal in your browser.
5. Clear `~/.mfp_mcp/cookies.json` and let the auto-discovery rebuild it.
6. On **macOS**, the auto-discovery path reads each browser's `Safe Storage`
   password from your login keychain. On the very first run, macOS shows a
   dialog: *"<binary> wants to use information stored in your keychain"* —
   click **Always Allow**. If Claude Desktop is spawning the MCP headlessly
   in the background, this dialog can be easy to miss; if auto-discovery
   returns "no browser had a session", bring Claude Desktop to the
   foreground and retry so the prompt is visible. Once approved, the key
   is cached and the prompt won't repeat.
7. On **Linux**, browser auto-discovery does not run. Log in with `mfp-mcp-login` instead. See [The mfp-mcp-login Command](#the-mfp-mcp-login-command). The server uses the new session on its next call.

### `mfp-mcp-login` fails on Linux

**Problem**: The login command exits with a nonzero code.

**Solutions**:

1. Run `mfp-mcp-login --check` first. Exit 0 means the saved session still works.
2. `display: no Xvfb on PATH`: install Xvfb with the command it prints. On an `apt-get` system, `mfp-mcp-login --install-xvfb` can install it for you.
3. `chrome: none found on PATH`: install Google Chrome from <https://www.google.com/chrome/>.
4. `chrome: skipped ... a snap Chromium`: install Google Chrome. The snap is not supported.
5. `setup: the browser login needs websockets>=11`: reinstall with `pip install -e ".[login]"`.
6. `credentials: ... no terminal to prompt on`: run it in a terminal, or export both variables.
7. `credentials: ... looks encrypted but there is no key`: set `MFP_SECRET_KEY`, or store the key with `npm run store-key`.
8. `attempts: ... refused`: the attempt window is full. Wait for the time it prints. Or delete the lines it names. To reset it, delete `~/.mfp_mcp/login-attempts.log`.
9. `lock: another mfp-mcp-login run holds ...`: wait for the other run to end.
10. Exit 3: MyFitnessPal showed a challenge, lock or limit page. Try again later, and mind the attempt window.
11. Exit 4 after a login: the new session failed verification. No cookie file was written. Try again later, and mind the attempt window.

### "No module named 'mfp_mcp'"

**Problem**: Package not installed or wrong Python environment.

**Solutions**:
1. Ensure you're using the correct Python from your virtual environment
2. Reinstall the package: `pip install -e ".[login]"`
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

### mfp_get_food_entries
List a day's individual food entries, one record per logged food, with the times MyFitnessPal stores for each.
- `date` (optional): YYYY-MM-DD format, defaults to today
- `response_format`: "markdown" or "json"

Each entry has `id`, `meal`, `name`, `brand`, `quantity`, `unit`, `energy`, `energy_unit`, macros (plus `fiber`, `sodium`, `sugar`), and four time fields. The `id` is the entry's v2 diary id: pass it as `entry_id` to `mfp_remove_food_from_diary` to delete exactly that entry.

| Field | Example | Meaning |
|-------|---------|---------|
| `consumed_at` | `15:45:00` | Time of day chosen in the app. No time zone. |
| `logged_at` | `2026-01-15T14:45:28+00:00` | When the entry was logged, in UTC |
| `logged_at_offset` | `+01:00` | UTC offset of the device that logged it |
| `created_at` | `2026-01-15T14:45:29Z` | When MyFitnessPal created the entry, in UTC |

`consumed_at`, `logged_at` and `logged_at_offset` can all be `null`: MyFitnessPal does not store a time for every entry. `created_at` is always set but is not a reliable substitute for the eating time.

### mfp_search_food
Search the MyFitnessPal food database.
- `query` (required): Search term
- `limit` (optional): Max results (default 10, max 50)
- `response_format`: "markdown" or "json"

Each result has `mfp_id`, `name`, `brand`, `calories`, `energy`, `energy_unit` and `verified`. `calories` is always kcal. `energy` and `energy_unit` (`calories` or `kilojoules`) carry the value the way the account displays it, so on a kilojoule account `energy` is the kJ figure and `calories` is that figure converted.

**Changed from earlier versions:** results no longer include `serving` (it cost one extra request per result; `mfp_get_food_details` returns the serving sizes), and they add `energy`, `energy_unit` and `verified`. A search made with an expired session now returns an error instead of `count: 0`.

### mfp_get_food_details
Get detailed nutrition for a food item.
- `mfp_id` (required): MyFitnessPal food ID from search results
- `response_format`: "markdown" or "json"

### mfp_add_food_to_diary
Add a food item to your diary for a specific meal and date.
- `mfp_id` (required): MyFitnessPal food ID from search results (use `mfp_search_food` first)
- `meal` (optional): Meal to log under (default: "Breakfast"). Matched case-insensitively against the account's own meals — the defaults (Breakfast, Lunch, Dinner, Snacks), renamed or localized ones, and custom meals — and posted with the account's exact spelling. A name that matches none of them is rejected with the list of valid meals, because MyFitnessPal would otherwise file the entry under the first meal without an error. Use `mfp_list_meals` to see the account's meals.
- `date` (optional): YYYY-MM-DD format (default: today)
- `quantity` (optional): Number of servings (default: 1.0)
- `unit` (optional): Unit/serving size description (e.g., "1 cup", "100g")

The first call reads the diary page once to learn the account's meal names (cached for a few minutes).

**Example workflow:**
1. Use `mfp_search_food` to find a food item and get its `mfp_id`
2. Use `mfp_add_food_to_diary` with the `mfp_id` to add it to your diary

### mfp_list_meals
List the account's configured meal names, in diary order and spelled the way the account defines them (for example `Breakfast`, a localized `Almoço`, or a custom `During Ride`). These are the values `mfp_add_food_to_diary` accepts for `meal`.
- `response_format`: "markdown" or "json"

### mfp_quick_add
Quick Add raw calories (and optional carbs/protein/fat) with no food lookup — the equivalent of MyFitnessPal's "Quick Add". Use it to log an energy/macro total directly when you don't have or don't need a specific food (a rough restaurant meal, a ride-fuel total). The entry is backed by a throwaway food that's deleted after logging, so it doesn't clutter your food list (the entry keeps its own nutrition — the same way MFP's own Quick Add works).
- `calories` (required): Calories to log, in kcal (behavior on kJ-unit accounts is unverified)
- `carbohydrates` / `protein` / `fat` (optional): grams (fractions are fine, e.g. `7.5`)
- `meal` (optional): Meal to log under (see `mfp_list_meals`; default "Breakfast")
- `date` (optional): YYYY-MM-DD format (default: today)
- `name` (optional): Label for the entry (default: "Quick Add")

Returns the new entry's `entry_id`, which `mfp_remove_food_from_diary` accepts. `entry_id` can come back null (`add_food_to_diary` may return no id); use `mfp_get_food_entries` to find the entry. That id is valid until the entry is edited elsewhere: an edit can give the entry a new id (seen with the MyFitnessPal iOS app), and `mfp_remove_food_from_diary` then fails with `Error removing food: Remove failed for entry <id>: HTTP 404` for the old one. `mfp_get_food_entries` lists the entry's current id.

### mfp_create_custom_food
Create a private custom food in your account. Returns the new food's `id`, which
`mfp_add_food_to_diary` accepts.
- `description` (required): Food name as it appears in MFP
- `calories` (required): Calories per serving
- `brand_name` (optional): Brand; packaged = label brand, restaurant = venue, homemade = "Generic" (default: "Generic")
- `serving_amount` (optional): Serving size number (default: 100)
- `serving_unit` (optional): Serving unit, e.g. "g", "ml", "piece" (default: "g")
- Nutrients (all optional): `carbs`, `fiber`, `sugar`, `protein`, `fat`, `saturated_fat`,
  `polyunsaturated_fat`, `monounsaturated_fat`, `trans_fat`, `cholesterol` (mg), `sodium` (mg),
  `potassium` (mg), `vitamin_a`, `vitamin_c`, `calcium`, `iron` (last four are %DV)
- `country_code` (optional): Label convention (default: "NL") — **see the carbs note below**
- `public` (optional): Share publicly (default: false)
- `response_format`: "markdown" or "json"

**`carbs` is NET carbs, and `country_code` is what makes it so.** The field selects which
label convention your number follows, so it changes the meaning of `carbs`:

| `country_code` | `carbs` is read as | MFP stores |
|------|------|-------------|
| `"NL"` and other EU codes (labels exclude fibre) | **NET** | `net_carbs = carbs`, `carbohydrates = carbs + fiber` |
| omitted / US (labels include fibre) | TOTAL | `carbohydrates = carbs`, `net_carbs = carbs − fiber` |

Sending `carbs=42, fiber=8` stores `50/42` under `"NL"` but `42/34` without it. Pass the number
straight off the label and leave `country_code` matching that label's origin — do not pre-subtract
fibre.

**MyFitnessPal has no custom-food update endpoint.** To correct a food, create the corrected
version and then `mfp_delete_custom_food` the old one.

### mfp_list_own_foods
List your own custom foods, newest first. Private custom foods do not reliably appear in
`mfp_search_food`, so this is how to find the `id` of something you created earlier.
- `search` (optional): Substring filter on the food name
- `limit` (optional): Max foods to return (default: 25)
- `response_format`: "markdown" or "json"

### mfp_delete_custom_food
Delete one of your custom foods. Destructive and not recoverable; MyFitnessPal may refuse if the
food is referenced by a logged diary entry.
- `food_id` (required): Food id from `mfp_create_custom_food` or `mfp_list_own_foods`

### mfp_remove_food_from_diary
Remove one or more logged entries from your diary. Pass either `entry_id` (exact) or `name_contains` (by name).
- `entry_id` (optional): The entry's v2 diary id; deletes exactly that entry. `mfp_add_food_to_diary` and `mfp_quick_add` return it when you log a food, and `mfp_get_food_entries` lists it as `id` for every entry of a day (`mfp_get_diary` does not include ids). When set, `name_contains`, `meal` and `max_matches` are ignored, and `date` is not used to find the entry.
- `name_contains` (optional): Text to look for in the day's entries, case-insensitive. It is matched against each entry's line on the diary page, which includes the serving (e.g. `banana` or `0.5 cup rice`).
- `meal` (optional): With `name_contains`, only match entries in this meal. Case-insensitive, and part of the meal's name is enough, so `lunch` also matches a custom meal named `Second Lunch`.
- `max_matches` (optional): With `name_contains`, the most entries to delete in one call, taken in diary order (default: 1, max: 50)
- `date` (optional): With `name_contains`, the day to search, in YYYY-MM-DD format (default: today)

By id, an id MyFitnessPal does not have fails with `Error removing food: Remove failed for entry <id>: HTTP 404`. An entry's id can change when the entry is edited elsewhere (seen with the MyFitnessPal iOS app); `mfp_get_food_entries` lists the current one.

By name, the response lists what was removed and reports `matched_count` and `remaining_matches_skipped`, so you can see when more entries matched than `max_matches` allowed. Those entries are listed with the diary page's numeric id, which is not the id `entry_id` takes. Two limits to know:
- If nothing matches, nothing is deleted and `success` is `false`. A diary page that could not be read (a login page, for instance) gives the same result, so a no-match does not prove the entry is gone.
- If a removal fails part-way through, the call returns only the error. Entries removed before it stay removed, so check the day with `mfp_get_food_entries`.

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
Get nutrition goals. By default returns the goal that applies on `date` (MyFitnessPal resolves the weekday for you).
- `date` (optional): YYYY-MM-DD (default today)
- `all_days` (optional): when true, return the full weekly breakdown — all 7 weekdays plus the default goal — for accounts that set different goals per day (Premium). Each row reports `energy` with its `energy_unit` (`calories` or `kilojoules`, as the account stores it), plus carbs, protein, fat, sodium, sugar and fiber.
- `response_format`: "markdown" or "json"

### mfp_set_goals
Update nutrition goals. Read-modify-write: only the nutrients you pass change; the micronutrient targets, the exercise split, any per-meal goals, and (when setting one day) the other six days are all sent back as they were read.

**Calories on their own rescale the macros.** If `calories` is the only value you pass, carbs, protein and fat are scaled by the same factor (rounded to whole grams), so the macro split is kept and the macros follow the new calories (to within whole-gram rounding) — the same thing MyFitnessPal's goal editor does. Pass any macro explicitly to set exact grams instead; nothing is rescaled then.
- `calories` (optional): Daily calorie goal
- `protein` (optional): Daily protein in grams
- `carbohydrates` (optional): Daily carbs in grams
- `fat` (optional): Daily fat in grams
- `day` (optional): weekday to update (e.g. `monday`), for Premium accounts with different goals per day. Omit to set every day of the week (and the default) to the same values. Different goals per weekday are a MyFitnessPal Premium feature: after a per-day write the tool compares what MyFitnessPal saved with what was sent and returns an error if the weekday did not keep the value, rather than reporting success.

### mfp_get_water
Get water intake for a date.
- `date` (optional): YYYY-MM-DD (default today)

### mfp_set_water
Log water intake for a date.
- `cups` (required): Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit (1 cup = ~237ml)
- `date` (optional): YYYY-MM-DD format (default: today)

### mfp_get_steps
Get daily step counts synced into MyFitnessPal (Apple Health, Google Fit, connected devices). Days with no synced data return `steps: null`.
- `start_date` (optional): YYYY-MM-DD (default 6 days before end_date)
- `end_date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

Maximum 31 days per call (MFP's API returns one day per request).

### mfp_get_report
Get nutrition report over a date range.
- `report_name` (optional): "Net Calories", "Protein", "Fat", "Carbs"
- `start_date` (optional): YYYY-MM-DD (default 7 days ago)
- `end_date` (optional): YYYY-MM-DD (default today)
- `response_format`: "markdown" or "json"

## Security & Privacy

- **Login Command**: `mfp-mcp-login` types credentials only into MyFitnessPal's login page. Its output never prints a credential or a cookie value. Chrome and Xvfb run with no `MFP_*` variable.
- **Encrypted Credentials**: The server and `mfp-mcp-login` accept Fernet-encrypted credentials. `MFP_SECRET_KEY` comes from the environment first, then the OS keychain. See [Encrypted Credentials](#encrypted-credentials) for setup.
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
