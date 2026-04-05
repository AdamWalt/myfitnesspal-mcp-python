# MyFitnessPal MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants like Claude to interact with your MyFitnessPal data, including food diary, exercises, body measurements, nutrition goals, and water intake.

## Features

| Tool | Type | Description |
|------|------|-------------|
| `mfp_get_diary` | Read | Get food diary entries for any date |
| `mfp_search_food` | Read | Search the MyFitnessPal food database |
| `mfp_get_food_details` | Read | Get detailed nutrition info for a food item |
| `mfp_get_recent_foods` | Read | Get recently used foods from the authenticated account |
| `mfp_get_frequent_foods` | Read | Get most-used foods from the authenticated account |
| `mfp_get_my_foods` | Read | Get foods created or saved by the authenticated account |
| `mfp_add_food_to_diary` | Write | Add a food item to your diary for a specific meal and date |
| `mfp_update_food_entry` | Write | Update an existing diary entry by `entry_id` |
| `mfp_delete_food_entry` | Write | Delete an existing diary entry by `entry_id` |
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
  - Chrome or Firefox with an active MyFitnessPal login session

### Authentication Options

This MCP supports multiple authentication methods:

| Method | Setup | Persistence |
|--------|-------|-------------|
| **Credentials in config** | Add `MFP_USERNAME` and `MFP_PASSWORD` to Claude Desktop config | Automatic (session cached 30 days) |
| **Browser cookies** | Log into myfitnesspal.com in Chrome/Firefox | Until browser session expires |

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

#### Option A: With Credentials (Recommended - No Browser Required)

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

#### Option B: Without Credentials (Browser Cookie Fallback)

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
Set `MFP_USERNAME` and `MFP_PASSWORD` in your Claude Desktop config's `env` section. This is the most reliable method and doesn't require a browser.

```json
"env": {
  "MFP_USERNAME": "your_email@example.com",
  "MFP_PASSWORD": "your_password"
}
```

### 2. Stored Session Cookies
After successful authentication, session cookies are saved to `~/.mfp_mcp/cookies.json`. These persist for 30 days, so you won't need to re-authenticate frequently.

### 3. Browser Cookies (Fallback)
If no credentials are provided and no stored cookies exist, the server falls back to reading cookies from Chrome or Firefox. You must be logged into myfitnesspal.com in your browser.

## Security Note on Credentials

Your MyFitnessPal credentials in the Claude Desktop config are stored locally on your machine. The config file is only readable by your user account. However, if you're concerned about storing credentials:

1. Use Option B (browser cookies) instead
2. Or use a dedicated MyFitnessPal account for API access
3. Session cookies are stored in `~/.mfp_mcp/cookies.json` with restricted permissions

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

## Project Structure

```
myfitnesspal-mcp-python/
├── Dockerfile              # Container deployment
├── pyproject.toml          # Package configuration
├── README.md               # This file
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
1. **If using credentials**: Double-check your MFP_USERNAME and MFP_PASSWORD in the config
2. **If using browser cookies**: Make sure you're logged into myfitnesspal.com in Chrome or Firefox
3. Try logging out and back in to MyFitnessPal
4. Clear browser cookies and log in fresh
5. On **macOS**, grant **Full Disk Access** to Claude Desktop:
   - System Settings → Privacy & Security → Full Disk Access
   - Add Claude.app

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

### `My Foods` or `My Meals` routes redirect to logout

**Problem**: Newer account pages like `/food/mine`, `/meal/mine`, or `/food/new`
can redirect to `/account/logout` even when diary reads and API token fetches still work.

**Solution**:
1. Use the MCP tools `mfp_get_recent_foods`, `mfp_get_frequent_foods`, and `mfp_get_my_foods`
2. Those tools intentionally use the legacy add-to-diary page and its AJAX endpoints:
   - `/food/load_recent`
   - `/food/load_most_used`
   - `/food/load_my_foods`
3. If you are extending the server, fetch a fresh CSRF token from `/user/<username>/diary/add?...`
   and send the AJAX headers that page expects

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

When `response_format` is `json`, each meal entry includes an `entry_id` that can be passed to `mfp_update_food_entry` and `mfp_delete_food_entry`.

### mfp_search_food
Search the MyFitnessPal food database.
- `query` (required): Search term
- `limit` (optional): Max results (default 10, max 50)
- `response_format`: "markdown" or "json"

### mfp_get_food_details
Get detailed nutrition for a food item.
- `mfp_id` (required): MyFitnessPal food ID from search results
- `response_format`: "markdown" or "json"

### mfp_get_recent_foods
Get recently used foods for the authenticated account.
- `limit` (optional): Max results (default 10, max 100)
- `response_format`: "markdown" or "json"

### mfp_get_frequent_foods
Get most-used foods for the authenticated account.
- `limit` (optional): Max results (default 10, max 100)
- `response_format`: "markdown" or "json"

### mfp_get_my_foods
Get foods created or saved by the authenticated account.
- `limit` (optional): Max results (default 100, max 100)
- `response_format`: "markdown" or "json"

These three tools use the legacy add-to-diary AJAX endpoints because the newer
`/food/mine` and related pages can redirect away from authenticated sessions.

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

The add response includes the created `entry_id` when the server can confirm the new diary row.

### mfp_update_food_entry
Update an existing diary entry.
- `entry_id` (required): Diary entry ID from `mfp_get_diary` JSON output
- `date` (optional): YYYY-MM-DD format (default: today)
- `meal` (optional): New meal name
- `quantity` (optional): New number of servings
- `unit` (optional): New serving-size label
- `weight_id` (optional): Raw MyFitnessPal serving-size option ID

MyFitnessPal can rewrite an entry during edit and return a replacement row. The tool response includes `current_entry_id` and `entry_id_changed` so callers can keep tracking the right diary row after an update.

### mfp_delete_food_entry
Delete an existing diary entry.
- `entry_id` (required): Diary entry ID from `mfp_get_diary` JSON output
- `date` (optional): YYYY-MM-DD format (default: today)

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

- **Credentials**: If using username/password authentication, credentials are stored in your Claude Desktop config file which is only readable by your user account. Session cookies are cached in `~/.mfp_mcp/cookies.json` for 30 days.
- **Browser Cookies**: As a fallback, the server can read your browser cookies to authenticate with MyFitnessPal.
- **Local Only**: The server runs locally on your machine via stdio transport. No data is sent to any third-party servers.
- **No External Transmission**: Your MyFitnessPal data is only transmitted between your computer and MyFitnessPal's servers (myfitnesspal.com).

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [python-myfitnesspal](https://github.com/coddingtonbear/python-myfitnesspal) - The underlying library for MyFitnessPal access
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) - Model Context Protocol framework
- [Anthropic](https://anthropic.com) - Claude and the MCP specification
