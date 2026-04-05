"""
MyFitnessPal MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting
with MyFitnessPal data including food diary, exercises, measurements, goals,
water intake, and food search.

Authentication Methods (in order of priority):
1. Environment variables: MFP_USERNAME and MFP_PASSWORD
2. Stored session cookies: ~/.mfp_mcp/cookies.json
3. Browser cookies: Chrome/Firefox (fallback)
"""

import json
import logging
import os
import sys
from datetime import date, datetime, timedelta
from http.cookiejar import CookieJar, Cookie
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from collections import OrderedDict
import time

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("mfp_mcp")

# Initialize MCP server
mcp = FastMCP("myfitnesspal_mcp")

# Configuration paths
CONFIG_DIR = Path.home() / ".mfp_mcp"
COOKIES_FILE = CONFIG_DIR / "cookies.json"


# ============================================================================
# Authentication Helper Functions
# ============================================================================


def ensure_config_dir():
    """Ensure the config directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_cookies(cookies: Dict[str, str]):
    """
    Save session cookies to file for persistence.
    
    Args:
        cookies: Dictionary of cookie name -> value
    """
    ensure_config_dir()
    cookie_data = {
        "cookies": cookies,
        "saved_at": datetime.now().isoformat(),
    }
    with open(COOKIES_FILE, "w") as f:
        json.dump(cookie_data, f, indent=2)
    logger.info(f"Saved session cookies to {COOKIES_FILE}")


def load_cookies() -> Optional[Dict[str, str]]:
    """
    Load session cookies from file.
    
    Returns:
        Dictionary of cookies if file exists and is valid, None otherwise
    """
    if not COOKIES_FILE.exists():
        return None
    
    try:
        with open(COOKIES_FILE, "r") as f:
            cookie_data = json.load(f)
        
        # Check if cookies are less than 30 days old
        saved_at = datetime.fromisoformat(cookie_data.get("saved_at", "2000-01-01"))
        if datetime.now() - saved_at > timedelta(days=30):
            logger.info("Stored cookies are expired (>30 days old)")
            return None
        
        return cookie_data.get("cookies")
    except Exception as e:
        logger.warning(f"Failed to load cookies: {e}")
        return None


def dict_to_cookiejar(cookies_dict: Dict[str, str], domain: str = ".myfitnesspal.com") -> CookieJar:
    """
    Convert a dictionary of cookies to a CookieJar that can be used by myfitnesspal.Client.
    
    Args:
        cookies_dict: Dictionary of cookie name -> value
        domain: Domain for the cookies (default: .myfitnesspal.com)
    
    Returns:
        CookieJar: A CookieJar object populated with the cookies
    """
    jar = CookieJar()
    
    for name, value in cookies_dict.items():
        cookie = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=domain.startswith('.'),
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 86400 * 30,  # 30 days from now
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
    
    return jar


def create_mfp_client(cookiejar: Optional[CookieJar] = None):
    """
    Create a MyFitnessPal client using a plain requests-backed session.

    The upstream library defaults to a cloudscraper session, but on this host
    that path gets a 403 from `/user/auth_token` even when the exact same
    authenticated cookies work with a plain requests session.
    """
    import requests
    import myfitnesspal
    import myfitnesspal.client as myfitnesspal_client

    original_create_scraper = myfitnesspal_client.cloudscraper.create_scraper
    myfitnesspal_client.cloudscraper.create_scraper = (
        lambda sess=None, *args, **kwargs: (sess or requests.Session())
    )
    try:
        if cookiejar is None:
            return myfitnesspal.Client()
        return myfitnesspal.Client(cookiejar=cookiejar)
    finally:
        myfitnesspal_client.cloudscraper.create_scraper = original_create_scraper


def authenticate_with_credentials(username: str, password: str) -> Dict[str, str]:
    """
    Authenticate with MyFitnessPal using username/password.
    
    Args:
        username: MyFitnessPal username or email
        password: MyFitnessPal password
    
    Returns:
        Dictionary of session cookies
        
    Raises:
        RuntimeError: If authentication fails
    """
    # Log authentication attempt without exposing the username
    logger.info("Authenticating with credentials")
    
    # MyFitnessPal login URL and endpoints
    LOGIN_URL = "https://www.myfitnesspal.com/account/login"
    
    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as client:
            # First, get the login page to obtain CSRF token
            response = client.get(LOGIN_URL)
            response.raise_for_status()
            
            # Extract CSRF token from cookies or page
            cookies = dict(response.cookies)
            
            # Attempt login
            login_data = {
                "username": username,
                "password": password,
            }
            
            # Try the standard form login
            login_response = client.post(
                LOGIN_URL,
                data=login_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": LOGIN_URL,
                },
            )
            
            # Check if login was successful by looking for session cookies
            all_cookies = dict(client.cookies)
            
            # MFP uses various session cookie names
            session_indicators = ["user", "session", "auth", "logged_in"]
            has_session = any(
                any(indicator in name.lower() for indicator in session_indicators)
                for name in all_cookies.keys()
            )
            
            if has_session or len(all_cookies) > len(cookies):
                logger.info("Successfully authenticated with credentials")
                return all_cookies
            else:
                # Try to check if we can access authenticated content
                test_response = client.get("https://www.myfitnesspal.com/food/diary")
                if test_response.status_code == 200 and "login" not in str(test_response.url).lower():
                    return dict(client.cookies)
                    
                raise RuntimeError("Login appeared to fail - no session cookies received")
                
    except httpx.HTTPError as e:
        raise RuntimeError(f"HTTP error during authentication: {e}")
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {e}")


def get_mfp_client():
    """
    Get an authenticated MyFitnessPal client.
    
    Authentication is attempted in this order:
    1. Environment variables (MFP_USERNAME, MFP_PASSWORD)
    2. Stored session cookies (~/.mfp_mcp/cookies.json)
    3. Browser cookies (Chrome/Firefox)

    Returns:
        myfitnesspal.Client: Authenticated client instance

    Raises:
        RuntimeError: If all authentication methods fail
    """
    import myfitnesspal
    
    last_error = None
    
    # Method 1: Try environment variable credentials
    username = os.environ.get("MFP_USERNAME")
    password = os.environ.get("MFP_PASSWORD")
    
    if username and password:
        logger.info("Attempting authentication with environment credentials")
        
        # First check if we have valid stored cookies from a previous credential auth
        stored_cookies = load_cookies()
        if stored_cookies:
            logger.info("Found stored session cookies, testing validity...")
            try:
                cookiejar = dict_to_cookiejar(stored_cookies)
                client = create_mfp_client(cookiejar=cookiejar)
                # Test the connection
                _ = client.get_date(date.today())
                logger.info("Stored cookies are valid")
                return client
            except Exception as e:
                logger.info(f"Stored cookies invalid: {e}, re-authenticating...")
        
        # Authenticate with credentials and save cookies
        try:
            cookies = authenticate_with_credentials(username, password)
            save_cookies(cookies)
            
            # Create client with the new cookies
            cookiejar = dict_to_cookiejar(cookies)
            client = create_mfp_client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with credentials")
            return client
            
        except Exception as e:
            last_error = e
            logger.warning(f"Credential authentication failed: {e}")
            # Fall through to other methods
    
    # Method 2: Try stored session cookies (without credential auth)
    stored_cookies = load_cookies()
    if stored_cookies:
        logger.info("Attempting authentication with stored cookies")
        try:
            cookiejar = dict_to_cookiejar(stored_cookies)
            client = create_mfp_client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with stored cookies")
            return client
        except Exception as e:
            last_error = e
            logger.warning(f"Stored cookie authentication failed: {e}")
    
    # Method 3: Try browser cookies (default behavior)
    logger.info("Attempting authentication with browser cookies")
    try:
        client = create_mfp_client()
        # Test the connection
        _ = client.get_date(date.today())
        logger.info("Successfully authenticated with browser cookies")
        return client
    except Exception as e:
        last_error = e
        raise RuntimeError(
            f"All authentication methods failed. Last error: {str(last_error)}\n\n"
            "Please try one of these solutions:\n"
            "1. Set MFP_USERNAME and MFP_PASSWORD environment variables in Claude Desktop config\n"
            "2. Log into myfitnesspal.com in Chrome or Firefox\n"
            "3. Check ~/.mfp_mcp/cookies.json for stored session"
        )


# ============================================================================
# Data Formatting Helper Functions
# ============================================================================


def parse_date(date_str: Optional[str] = None) -> date:
    """
    Parse a date string or return today's date.

    Args:
        date_str: Date in YYYY-MM-DD format, or None for today

    Returns:
        date: Parsed date object
    """
    if date_str is None:
        return date.today()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def format_nutrition_dict(nutrition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format nutrition dictionary for consistent output.

    Args:
        nutrition: Raw nutrition dictionary

    Returns:
        dict: Formatted nutrition data
    """
    formatted = {}
    for key, value in nutrition.items():
        if hasattr(value, "magnitude"):
            # Handle pint quantities
            formatted[key] = float(value.magnitude)
        else:
            formatted[key] = value
    return formatted


def format_meal_entry(entry, entry_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Format a meal entry for output.

    Args:
        entry: MFP Entry object

    Returns:
        dict: Formatted entry data
    """
    data = {
        "name": entry.name,
        "short_name": getattr(entry, "short_name", None),
        "quantity": getattr(entry, "quantity", None),
        "unit": getattr(entry, "unit", None),
        "nutrition": format_nutrition_dict(entry.totals),
    }
    if entry_id:
        data["entry_id"] = entry_id
    return data


def format_exercise(exercise) -> Dict[str, Any]:
    """
    Format an exercise object for output.

    Args:
        exercise: MFP Exercise object

    Returns:
        dict: Formatted exercise data
    """
    entries = exercise.get_as_list()
    return {"name": exercise.name, "entries": entries}


def ordered_dict_to_dict(od: OrderedDict) -> Dict[str, Any]:
    """
    Convert OrderedDict with date keys to regular dict with string keys.

    Args:
        od: OrderedDict with date keys

    Returns:
        dict: Regular dict with string keys
    """
    return {str(k): v for k, v in od.items()}


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def format_response(data: Any, format_type: ResponseFormat, title: str = "") -> str:
    """
    Format response data based on requested format.

    Args:
        data: Data to format
        format_type: Output format (markdown or json)
        title: Optional title for markdown format

    Returns:
        str: Formatted response string
    """
    if format_type == ResponseFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    # Markdown format
    lines = []
    if title:
        lines.append(f"## {title}\n")

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"### {key}")
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                lines.append(f"### {key}")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item.get('name', str(item))}")
                        for k, v in item.items():
                            if k != "name":
                                lines.append(f"  - {k}: {v}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"- **{key}**: {value}")
    else:
        lines.append(str(data))

    return "\n".join(lines)


# ============================================================================
# Pydantic Input Models
# ============================================================================


class GetDiaryInput(BaseModel):
    """Input model for getting food diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SearchFoodInput(BaseModel):
    """Input model for searching foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query for food items (e.g., 'chicken breast', 'apple')",
        min_length=1,
        max_length=200,
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodDetailsInput(BaseModel):
    """Input model for getting food item details."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from search results)",
        min_length=1,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodCollectionInput(BaseModel):
    """Input model for fetching recent, frequent, or saved foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    limit: Optional[int] = Field(
        default=None,
        description="Maximum number of foods to return",
        ge=1,
        le=100,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetMeasurementsInput(BaseModel):
    """Input model for getting measurements."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to retrieve (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 30 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetMeasurementInput(BaseModel):
    """Input model for setting a measurement."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to set (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    value: float = Field(
        ...,
        description="Measurement value (e.g., 185.5 for weight in lbs)",
        gt=0,
    )


class GetExercisesInput(BaseModel):
    """Input model for getting exercises."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetGoalsInput(BaseModel):
    """Input model for getting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetGoalsInput(BaseModel):
    """Input model for setting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: Optional[int] = Field(
        default=None,
        description="Daily calorie goal (e.g., 2000)",
        ge=500,
        le=10000,
    )
    protein: Optional[int] = Field(
        default=None,
        description="Daily protein goal in grams (e.g., 150)",
        ge=0,
        le=1000,
    )
    carbohydrates: Optional[int] = Field(
        default=None,
        description="Daily carbohydrate goal in grams (e.g., 200)",
        ge=0,
        le=2000,
    )
    fat: Optional[int] = Field(
        default=None,
        description="Daily fat goal in grams (e.g., 65)",
        ge=0,
        le=500,
    )


class GetWaterInput(BaseModel):
    """Input model for getting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class GetReportInput(BaseModel):
    """Input model for getting nutrition reports."""

    model_config = ConfigDict(str_strip_whitespace=True)

    report_name: str = Field(
        default="Net Calories",
        description="Report name (e.g., 'Net Calories', 'Total Calories', 'Protein', 'Fat', 'Carbs')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 7 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class AddFoodToDiaryInput(BaseModel):
    """Input model for adding food to diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from mfp_search_food)",
        min_length=1,
    )
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    quantity: float = Field(
        default=1.0,
        description="Quantity/servings (e.g., 1.5 for 1.5 servings)",
        gt=0,
        le=100,
    )
    unit: Optional[str] = Field(
        default=None,
        description="Unit/serving size description (e.g., '1 cup', '100g'). If not provided, uses default serving size from food item.",
    )


class UpdateFoodEntryInput(BaseModel):
    """Input model for updating an existing diary entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    entry_id: str = Field(
        ...,
        description="Diary entry ID from mfp_get_diary",
        min_length=1,
    )
    date: Optional[str] = Field(
        default=None,
        description="Diary date in YYYY-MM-DD format. Required for historical entries; defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    meal: Optional[str] = Field(
        default=None,
        description="New meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks').",
    )
    quantity: Optional[float] = Field(
        default=None,
        description="New quantity/servings.",
        gt=0,
        le=100,
    )
    unit: Optional[str] = Field(
        default=None,
        description="New serving size label exactly as shown by MyFitnessPal (for example '350 ml').",
    )
    weight_id: Optional[str] = Field(
        default=None,
        description="Raw MyFitnessPal serving-size option ID. Overrides `unit` when both are provided.",
        min_length=1,
    )


class DeleteFoodEntryInput(BaseModel):
    """Input model for deleting an existing diary entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    entry_id: str = Field(
        ...,
        description="Diary entry ID from mfp_get_diary",
        min_length=1,
    )
    date: Optional[str] = Field(
        default=None,
        description="Diary date in YYYY-MM-DD format. Required for historical entries; defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class SetWaterInput(BaseModel):
    """Input model for setting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cups: float = Field(
        ...,
        description="Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit.",
        ge=0,
        le=50,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


# ============================================================================
# Diary Entry Creation Helper Functions
# ============================================================================


def get_diary_page_url(client, target_date: date) -> str:
    """Build the MyFitnessPal diary URL for a specific user and date."""
    from urllib import parse

    date_str = target_date.strftime("%Y-%m-%d")
    return parse.urljoin(
        client.BASE_URL_SECURE,
        f"food/diary/{client.effective_username}?date={date_str}",
    )


def get_diary_document(client, target_date: date):
    """Fetch the diary page document for a specific date."""
    return client._get_document_for_url(get_diary_page_url(client, target_date))


def extract_authenticity_token(document) -> str:
    """Extract the Rails authenticity token from a diary or edit form."""
    authenticity_token = document.xpath("(//input[@name='authenticity_token']/@value)[1]")
    if not authenticity_token:
        raise RuntimeError("Could not find authenticity token on the page")
    return authenticity_token[0]


def extract_csrf_param_and_token(document) -> Tuple[str, str]:
    """Extract the Rails CSRF param/token pair from page metadata or forms."""
    csrf_param = document.xpath("string(//meta[@name='csrf-param']/@content)") or "authenticity_token"
    csrf_token = document.xpath("string(//meta[@name='csrf-token']/@content)")
    if not csrf_token:
        csrf_token = extract_authenticity_token(document)
    return csrf_param, csrf_token


def normalize_meal_name(meal: str) -> str:
    """Normalize a meal name for comparisons and routing."""
    normalized = meal.strip().lower()
    if normalized == "snack":
        return "snacks"
    return normalized


def meal_name_to_id(meal: str) -> str:
    """Map user-facing meal names to MyFitnessPal's meal IDs."""
    meal_map = {
        "breakfast": "0",
        "lunch": "1",
        "dinner": "2",
        "snacks": "3",
        "snack": "3",
    }
    return meal_map.get(normalize_meal_name(meal), "0")


def meal_id_to_name(meal_id: Optional[Any]) -> Optional[str]:
    """Map MyFitnessPal meal IDs back to display names."""
    if meal_id is None:
        return None

    meal_map = {
        0: "Breakfast",
        1: "Lunch",
        2: "Dinner",
        3: "Snacks",
        "0": "Breakfast",
        "1": "Lunch",
        "2": "Dinner",
        "3": "Snacks",
    }
    return meal_map.get(meal_id, str(meal_id))


def get_diary_add_page_url(
    client,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> str:
    """
    Build the legacy add-to-diary page URL.

    The modern `/food/mine`, `/meal/mine`, and `/food/new` pages can redirect to
    `/account/logout` even when the account is otherwise authenticated. The
    legacy diary-add page still exposes stable AJAX endpoints for recent,
    frequent, and saved foods.
    """
    from urllib import parse

    target_date = target_date or date.today()
    return parse.urljoin(
        client.BASE_URL_SECURE,
        f"user/{client.effective_username}/diary/add?meal={meal_name_to_id(meal)}&date={target_date:%Y-%m-%d}",
    )


def get_diary_add_tab_headers(
    client,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> Dict[str, str]:
    """Build the AJAX headers required by the legacy add-page tab endpoints."""
    add_page_url = get_diary_add_page_url(client, meal=meal, target_date=target_date)
    document = client._get_document_for_url(add_page_url)
    _, csrf_token = extract_csrf_param_and_token(document)
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": add_page_url,
        "Origin": client.BASE_URL_SECURE.rstrip("/"),
        "X-CSRF-Token": csrf_token,
    }


def normalize_food_collection_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a legacy add-page item into a stable MCP response shape."""
    food = item.get("food", {})
    weight = item.get("weight") or {}
    brand_name = food.get("brand_name")
    description = food.get("description")
    if brand_name and brand_name != "Generic":
        name = f"{brand_name} - {description}"
    else:
        name = description or brand_name or "Unknown Food"

    nutritional_contents = food.get("nutritional_contents") or {}
    energy = nutritional_contents.get("energy") or {}

    return {
        "name": name,
        "description": description,
        "brand_name": brand_name,
        "date": item.get("date"),
        "meal": meal_id_to_name(item.get("meal_id")),
        "meal_id": item.get("meal_id"),
        "quantity": item.get("quantity"),
        "unit": weight.get("unit"),
        "serving_value": weight.get("value"),
        "nutrition_multiplier": weight.get("nutrition_multiplier"),
        "calories": energy.get("value"),
        "food_id": food.get("id"),
        "food_version": food.get("version"),
        "public": food.get("public"),
        "confirmations": food.get("confirmations"),
        "item_type": item.get("type"),
    }


def fetch_legacy_food_collection(
    client,
    category: str,
    limit: int,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """Fetch recent, frequent, or saved foods via the legacy add-page AJAX endpoints."""
    from urllib import parse

    category_map = {
        "recent": "recent",
        "frequent": "most_used",
        "my_foods": "my_foods",
    }
    if category not in category_map:
        raise RuntimeError(f"Unsupported legacy food collection '{category}'")

    headers = get_diary_add_tab_headers(client, meal=meal, target_date=target_date)
    endpoint = parse.urljoin(client.BASE_URL_SECURE, f"food/load_{category_map[category]}")

    items: List[Dict[str, Any]] = []
    base_index = 0
    page = 1
    while len(items) < limit:
        response = client.session.post(
            endpoint,
            data={"meal": meal_name_to_id(meal), "base_index": base_index, "page": page},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        batch = payload.get("items", [])
        if not batch:
            break

        items.extend(normalize_food_collection_item(item) for item in batch)
        base_index += len(batch)
        page += 1

    return items[:limit]


def extract_diary_entry_ids(client, target_date: date) -> Dict[str, List[Optional[str]]]:
    """
    Extract entry IDs from the diary page, grouped by meal.

    The upstream python-myfitnesspal library parses entry nutrition but discards
    the stable diary-entry IDs needed for edit/delete operations.
    """
    document = get_diary_document(client, target_date)
    entry_ids_by_meal: Dict[str, List[Optional[str]]] = {}

    for meal_header in document.xpath("//tr[@class='meal_header']"):
        meal_name = "".join(meal_header.xpath("./td[1]//text()")).strip().lower()
        ids: List[Optional[str]] = []
        row = meal_header
        while True:
            row = row.getnext()
            if row is None or row.attrib.get("class") is not None:
                break

            entry_link = row.xpath(".//a[@data-food-entry-id][1]")
            if entry_link:
                ids.append(entry_link[0].attrib.get("data-food-entry-id"))
                continue

            delete_link = row.xpath(".//td[contains(@class, 'delete')]//a/@href")
            if delete_link:
                ids.append(delete_link[0].split("/")[-1].split("?")[0])
            else:
                ids.append(None)

        entry_ids_by_meal[meal_name] = ids

    return entry_ids_by_meal


def get_diary_entry_snapshots(client, target_date: date) -> Dict[str, Dict[str, Any]]:
    """Return diary entries keyed by stable entry ID for a given date."""
    day = client.get_date(target_date)
    entry_ids_by_meal = extract_diary_entry_ids(client, target_date)
    snapshots: Dict[str, Dict[str, Any]] = {}

    for meal in day.meals:
        meal_entry_ids = entry_ids_by_meal.get(meal.name.lower(), [])
        for idx, entry in enumerate(meal.entries):
            entry_id = meal_entry_ids[idx] if idx < len(meal_entry_ids) else None
            if not entry_id:
                continue
            snapshot = format_meal_entry(entry, entry_id=entry_id)
            snapshot["meal"] = meal.name
            snapshots[entry_id] = snapshot

    return snapshots


def get_edit_entry_form(client, entry_id: str):
    """Fetch the edit form for a specific diary entry."""
    from urllib import parse
    import lxml.html

    edit_url = parse.urljoin(client.BASE_URL_SECURE, f"food/edit_entry/{entry_id}")
    response = client.session.get(edit_url)
    response.raise_for_status()
    document = lxml.html.document_fromstring(response.text)
    forms = document.xpath("//form[@id='edit_entry_form']")
    if not forms:
        raise RuntimeError(f"Could not load edit form for entry {entry_id}")
    return edit_url, forms[0]


def resolve_weight_id(form, weight_id: Optional[str], unit: Optional[str]) -> str:
    """Resolve the serving-size option to submit back to MyFitnessPal."""
    selected = form.xpath(".//select[@name='food_entry[weight_id]']/option[@selected='selected']/@value")
    if weight_id:
        return weight_id
    if unit:
        wanted = " ".join(unit.split()).lower()
        for option in form.xpath(".//select[@name='food_entry[weight_id]']/option"):
            label = " ".join("".join(option.itertext()).split()).lower()
            if label == wanted:
                return option.attrib["value"]
        raise RuntimeError(f"Serving size '{unit}' was not available for this entry")
    if selected:
        return selected[0]
    first_option = form.xpath(".//select[@name='food_entry[weight_id]']/option[1]/@value")
    if not first_option:
        raise RuntimeError("Could not determine a serving size for this entry")
    return first_option[0]


def resolve_food_serving_index(food_item, mfp_id: str, unit: Optional[str]) -> int:
    """Resolve the serving-size index for a food item."""
    servings = list(getattr(food_item, "servings", []))
    if not servings:
        raise RuntimeError(f"No serving sizes were available for food {mfp_id}")

    if not unit:
        return 0

    wanted = " ".join(unit.split()).lower()
    for idx, serving in enumerate(servings):
        candidates = {
            " ".join(str(serving).split()).lower(),
            f"{serving.value:g} {serving.unit}".lower(),
            serving.unit.lower(),
        }
        if wanted in candidates:
            return idx

    raise RuntimeError(f"Serving size '{unit}' was not available for food {mfp_id}")


def resolve_food_serving_id(client, mfp_id: str, unit: Optional[str]) -> str:
    """Resolve a food item's serving-size ID for add-to-diary operations."""
    food_item = client.get_food_item_details(mfp_id)
    servings = list(getattr(food_item, "servings", []))
    return servings[resolve_food_serving_index(food_item, mfp_id, unit)].serving_id


def build_food_search_query(food_item, mfp_id: str) -> str:
    """Build a search query that can be replayed on the legacy diary add page."""
    candidates = [
        getattr(food_item, "brand_name", None),
        getattr(food_item, "brand", None),
        getattr(food_item, "description", None),
        getattr(food_item, "name", None),
        getattr(food_item, "_name", None),
    ]

    parts: List[str] = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        normalized = " ".join(str(candidate).split())
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        parts.append(normalized)

    if not parts:
        raise RuntimeError(
            f"Could not derive a search query for food {mfp_id}; try searching the food again first."
        )

    if len(parts) >= 2 and parts[0].lower() in parts[1].lower():
        parts = parts[1:]

    return " ".join(parts[:2])


def resolve_legacy_add_flow(
    client,
    mfp_id: str,
    meal: str,
    target_date: date,
    unit: Optional[str],
) -> Dict[str, str]:
    """Resolve the legacy add-to-diary form data for an external MyFitnessPal food ID."""
    from urllib import parse
    import lxml.html

    meal_id = meal_name_to_id(meal)
    date_str = target_date.strftime("%Y-%m-%d")
    food_item = client.get_food_item_details(mfp_id)
    query = build_food_search_query(food_item, mfp_id)

    response = client.session.get(
        parse.urljoin(client.BASE_URL_SECURE, "food/search"),
        params={"meal": meal_id, "date": date_str, "search": query},
        headers={
            "Referer": parse.urljoin(
                client.BASE_URL_SECURE,
                f"user/{client.effective_username}/diary/add?meal={meal_id}&date={date_str}",
            )
        },
    )
    response.raise_for_status()

    document = lxml.html.document_fromstring(response.text)
    matches = document.xpath(f"//a[contains(@class, 'search') and @data-external-id='{mfp_id}']")
    if not matches:
        raise RuntimeError(
            f"Could not match MyFitnessPal food ID {mfp_id} on the diary add page using query '{query}'."
        )

    match = matches[0]
    authenticity_token = document.xpath(
        "string(//form[@action='/food/add']//input[@name='authenticity_token']/@value)"
    )
    if not authenticity_token:
        raise RuntimeError("Could not find the add-to-diary authenticity token")

    original_food_id = match.attrib.get("data-original-id")
    if not original_food_id:
        raise RuntimeError(f"Could not resolve the legacy food ID for {mfp_id}")

    legacy_weight_ids = [
        value for value in match.attrib.get("data-weight-ids", "").split(",") if value
    ]
    if not legacy_weight_ids:
        raise RuntimeError(f"Could not resolve serving-size options for food {mfp_id}")

    serving_index = resolve_food_serving_index(food_item, mfp_id, unit)
    if serving_index >= len(legacy_weight_ids):
        raise RuntimeError(
            f"Serving size index {serving_index} was not available in the legacy diary flow for food {mfp_id}"
        )

    return {
        "authenticity_token": authenticity_token,
        "legacy_food_id": original_food_id,
        "weight_id": legacy_weight_ids[serving_index],
        "meal_id": meal_id,
        "query": query,
        "matched_name": " ".join("".join(match.itertext()).split()),
        "search_url": response.url,
    }


def find_replacement_entry(
    before_entries: Dict[str, Dict[str, Any]],
    after_entries: Dict[str, Dict[str, Any]],
    original_entry: Dict[str, Any],
    requested_meal: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Find the most likely replacement entry when MyFitnessPal rewrites the entry ID."""
    new_entries = [
        entry for entry_id, entry in after_entries.items() if entry_id not in before_entries
    ]
    if not new_entries:
        return None

    target_meal = normalize_meal_name(requested_meal or original_entry["meal"])
    meal_matches = [
        entry for entry in new_entries if normalize_meal_name(entry["meal"]) == target_meal
    ]
    if len(meal_matches) == 1:
        return meal_matches[0]

    original_short_name = original_entry.get("short_name")
    if original_short_name:
        short_name_matches = [
            entry
            for entry in meal_matches or new_entries
            if entry.get("short_name") == original_short_name
        ]
        if len(short_name_matches) == 1:
            return short_name_matches[0]

    original_name = original_entry["name"]
    name_matches = [
        entry
        for entry in meal_matches or new_entries
        if original_name in entry["name"] or entry["name"] in original_name
    ]
    if len(name_matches) == 1:
        return name_matches[0]

    if len(new_entries) == 1:
        return new_entries[0]

    return None


def update_food_entry(
    client,
    entry_id: str,
    target_date: date,
    meal: Optional[str] = None,
    quantity: Optional[float] = None,
    unit: Optional[str] = None,
    weight_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an existing diary entry and return the confirmed resulting entry."""
    from urllib import parse

    before_entries = get_diary_entry_snapshots(client, target_date)
    original_entry = before_entries.get(entry_id)
    if not original_entry:
        raise RuntimeError(f"Diary entry {entry_id} was not found on {target_date}")

    edit_url, form = get_edit_entry_form(client, entry_id)

    def val(xpath: str, default: str = "") -> str:
        result = form.xpath(xpath)
        return result[0] if result else default

    payload = {
        "authenticity_token": val(".//input[@name='authenticity_token']/@value"),
        "food_entry[id]": val(".//input[@name='food_entry[id]']/@value"),
        "food_entry[date]": target_date.strftime("%Y-%m-%d"),
        "food_entry[quantity]": str(quantity if quantity is not None else val(".//input[@name='food_entry[quantity]']/@value")),
        "food_entry[weight_id]": resolve_weight_id(form, weight_id=weight_id, unit=unit),
        "food_entry[meal_id]": meal_name_to_id(meal) if meal else val(".//select[@name='food_entry[meal_id]']/option[@selected='selected']/@value"),
    }

    action = parse.urljoin(client.BASE_URL_SECURE, form.attrib["action"])
    response = client.session.post(
        action,
        data=payload,
        headers={"Referer": edit_url, "Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code not in (200, 204, 302, 303):
        raise RuntimeError(f"Failed to update food entry: HTTP {response.status_code}")

    after_entries = get_diary_entry_snapshots(client, target_date)
    current_entry = after_entries.get(entry_id)
    if current_entry is None:
        current_entry = find_replacement_entry(before_entries, after_entries, original_entry, meal)
    if current_entry is None:
        raise RuntimeError(f"Updated entry {entry_id} could not be confirmed on {target_date}")

    logger.info(
        "Successfully updated food entry %s for %s (current entry id: %s)",
        entry_id,
        target_date,
        current_entry["entry_id"],
    )
    return {
        "before": original_entry,
        "after": current_entry,
        "entry_id_changed": current_entry["entry_id"] != entry_id,
    }


def delete_food_entry(client, entry_id: str, target_date: date) -> Dict[str, Any]:
    """Delete an existing diary entry and return the deleted entry snapshot."""
    from urllib import parse

    before_entries = get_diary_entry_snapshots(client, target_date)
    existing_entry = before_entries.get(entry_id)
    if not existing_entry:
        raise RuntimeError(f"Diary entry {entry_id} was not found on {target_date}")

    diary_url = get_diary_page_url(client, target_date)
    document = get_diary_document(client, target_date)
    csrf_param, csrf_token = extract_csrf_param_and_token(document)
    delete_url = parse.urljoin(
        client.BASE_URL_SECURE,
        f"food/remove/{entry_id}",
    )

    response = client.session.post(
        delete_url,
        data={"_method": "delete", csrf_param: csrf_token},
        headers={"Referer": diary_url, "Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    if response.status_code not in (200, 204, 302, 303):
        raise RuntimeError(f"Failed to delete food entry: HTTP {response.status_code}")

    after_entries = get_diary_entry_snapshots(client, target_date)
    if entry_id in after_entries:
        raise RuntimeError(f"Diary entry {entry_id} still exists after delete")

    logger.info("Successfully deleted food entry %s for %s", entry_id, target_date)
    return existing_entry


def add_food_to_diary(
    client, mfp_id: str, meal: str, target_date: date, quantity: float = 1.0, unit: Optional[str] = None
) -> Dict[str, Any]:
    """
    Add a food item to the diary for a specific date and meal.
    
    Args:
        client: Authenticated myfitnesspal.Client instance
        mfp_id: MyFitnessPal food item ID
        meal: Meal name (Breakfast, Lunch, Dinner, Snacks)
        target_date: Date to add the food entry
        quantity: Number of servings (default 1.0)
        unit: Optional unit/serving size description
    
    Raises:
        RuntimeError: If the operation fails
    """
    try:
        from urllib import parse

        date_str = target_date.strftime("%Y-%m-%d")
        before_entries = get_diary_entry_snapshots(client, target_date)
        legacy_add = resolve_legacy_add_flow(client, mfp_id, meal, target_date, unit)
        add_food_url = parse.urljoin(client.BASE_URL_SECURE, "food/add")

        post_data = {
            "authenticity_token": legacy_add["authenticity_token"],
            "food_entry[food_id]": legacy_add["legacy_food_id"],
            "food_entry[date]": date_str,
            "food_entry[quantity]": str(quantity),
            "food_entry[weight_id]": legacy_add["weight_id"],
            "food_entry[meal_id]": legacy_add["meal_id"],
            "ajax": "true",
        }

        headers = {
            "Referer": legacy_add["search_url"],
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }

        response = client.session.post(add_food_url, data=post_data, headers=headers)
        response.raise_for_status()

        if response.status_code not in (200, 201, 204):
            raise RuntimeError(f"Failed to add food: HTTP {response.status_code}")

        content = response.text if hasattr(response, "text") else response.content.decode("utf-8", errors="ignore")
        if "error" in content.lower() and "success" not in content.lower():
            logger.warning("Possible error in response from MyFitnessPal API")

        after_entries = get_diary_entry_snapshots(client, target_date)
        new_entries = [
            entry for entry_id, entry in after_entries.items() if entry_id not in before_entries
        ]
        requested_meal = normalize_meal_name(meal)
        meal_matches = [
            entry for entry in new_entries if normalize_meal_name(entry["meal"]) == requested_meal
        ]
        if len(meal_matches) == 1:
            added_entry = meal_matches[0]
        elif len(new_entries) == 1:
            added_entry = new_entries[0]
        else:
            raise RuntimeError(
                f"Added food {mfp_id}, but could not uniquely identify the new diary entry on {target_date}"
            )

        logger.info(
            "Successfully added food %s to %s for %s as entry %s",
            mfp_id,
            meal,
            target_date,
            added_entry["entry_id"],
        )
        return added_entry

    except Exception as e:
        # Don't expose internal error details to avoid leaking sensitive information
        error_msg = str(e)
        # Only include safe error information
        if "HTTP" in error_msg or "status" in error_msg.lower():
            raise RuntimeError(f"Failed to add food to diary: {error_msg}")
        else:
            raise RuntimeError("Failed to add food to diary. Please check your authentication and try again.")


def set_water_intake(client, target_date: date, cups: float) -> None:
    """
    Set water intake for a specific date.
    
    Args:
        client: Authenticated myfitnesspal.Client instance
        target_date: Date to set water intake
        cups: Number of cups of water
    
    Raises:
        RuntimeError: If the operation fails
    """
    from urllib import parse
    
    try:
        # Get the diary page for the target date to extract CSRF token
        date_str = target_date.strftime("%Y-%m-%d")
        diary_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}?date={date_str}"
        )
        
        # Use the library's method to get the document
        document = client._get_document_for_url(diary_url)
        
        # Extract authenticity token
        authenticity_token = document.xpath(
            "(//input[@name='authenticity_token']/@value)[1]"
        )
        if not authenticity_token:
            raise RuntimeError("Could not find authenticity token on diary page")
        authenticity_token = authenticity_token[0]
        
        # Build the URL for setting water
        # MyFitnessPal uses /food/diary/{username}/water endpoint
        water_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}/water"
        )
        
        # Prepare the data for the POST request
        post_data = {
            "authenticity_token": authenticity_token,
            "date": date_str,
            "water": str(cups),
        }
        
        # Set water intake
        headers = {
            "Referer": diary_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }
        
        response = client.session.post(water_url, data=post_data, headers=headers)
        response.raise_for_status()
        
        if response.status_code != 200:
            raise RuntimeError(f"Failed to set water: HTTP {response.status_code}")
        
        logger.info(f"Successfully set water intake to {cups} cups for {target_date}")
        
    except Exception as e:
        # Don't expose internal error details to avoid leaking sensitive information
        error_msg = str(e)
        # Only include safe error information
        if "HTTP" in error_msg or "status" in error_msg.lower():
            raise RuntimeError(f"Failed to set water intake: {error_msg}")
        else:
            raise RuntimeError("Failed to set water intake. Please check your authentication and try again.")


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool(
    name="mfp_get_diary",
    annotations={
        "title": "Get Food Diary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_diary(params: GetDiaryInput) -> str:
    """
    Get the food diary for a specific date including all meals and their nutritional information.

    Returns meals (Breakfast, Lunch, Dinner, Snacks) with each food entry's name,
    quantity, and complete nutrition breakdown (calories, protein, carbs, fat, etc.).
    Also includes daily totals and goals.

    Args:
        params: GetDiaryInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Formatted diary data with meals, entries, nutrition, and goals
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)
        entry_ids_by_meal = extract_diary_entry_ids(client, target_date)

        # Build response data
        data = {
            "date": str(target_date),
            "meals": {},
            "daily_totals": {},
            "daily_goals": {},
            "water": day.water,
            "notes": day.notes or "",
        }

        # Process meals
        for meal in day.meals:
            meal_entry_ids = entry_ids_by_meal.get(meal.name.lower(), [])
            if len(meal_entry_ids) != len(meal.entries):
                logger.warning(
                    "Diary entry ID count mismatch for %s on %s: ids=%s entries=%s",
                    meal.name,
                    target_date,
                    len(meal_entry_ids),
                    len(meal.entries),
                )
            meal_data = {
                "entries": [
                    format_meal_entry(
                        entry,
                        entry_id=meal_entry_ids[idx] if idx < len(meal_entry_ids) else None,
                    )
                    for idx, entry in enumerate(meal.entries)
                ],
                "totals": format_nutrition_dict(meal.totals),
            }
            data["meals"][meal.name] = meal_data

        # Get daily totals and goals
        totals = {}
        for entry in day.entries:
            for key, value in entry.totals.items():
                val = float(value.magnitude) if hasattr(value, "magnitude") else value
                totals[key] = totals.get(key, 0) + val
        data["daily_totals"] = totals
        data["daily_goals"] = day.goals

        return format_response(
            data, params.response_format, f"Food Diary for {target_date}"
        )

    except Exception as e:
        return f"Error retrieving diary: {str(e)}"


@mcp.tool(
    name="mfp_search_food",
    annotations={
        "title": "Search Food Database",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_search_food(params: SearchFoodInput) -> str:
    """
    Search the MyFitnessPal food database for food items.

    Returns a list of matching foods with their name, brand, serving size,
    calories, and MFP ID (which can be used with mfp_get_food_details).

    Args:
        params: SearchFoodInput containing:
            - query (str): Search query (e.g., 'chicken breast')
            - limit (int): Maximum results to return (default 10)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of matching food items with basic nutrition info
    """
    try:
        client = get_mfp_client()
        results = client.get_food_search_results(params.query)

        # Limit results
        results = results[: params.limit]

        data = {"query": params.query, "count": len(results), "results": []}

        for item in results:
            data["results"].append(
                {
                    "name": item.name,
                    "brand": item.brand,
                    "serving": item.serving,
                    "calories": item.calories,
                    "mfp_id": item.mfp_id,
                }
            )

        return format_response(
            data, params.response_format, f"Food Search Results for '{params.query}'"
        )

    except Exception as e:
        return f"Error searching foods: {str(e)}"


@mcp.tool(
    name="mfp_get_food_details",
    annotations={
        "title": "Get Food Item Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_food_details(params: GetFoodDetailsInput) -> str:
    """
    Get detailed nutritional information for a specific food item by its MFP ID.

    Returns complete nutrition breakdown including calories, macros (protein, carbs, fat),
    fiber, sugar, sodium, cholesterol, vitamins, minerals, and available serving sizes.

    Args:
        params: GetFoodDetailsInput containing:
            - mfp_id (str): MyFitnessPal food item ID from search results
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Complete nutritional information for the food item
    """
    try:
        client = get_mfp_client()
        item = client.get_food_item_details(params.mfp_id)

        data = {
            "mfp_id": params.mfp_id,
            "description": getattr(item, "description", "N/A"),
            "brand_name": getattr(item, "brand_name", None),
            "verified": getattr(item, "verified", False),
            "calories": getattr(item, "calories", None),
            "nutrition": {
                "protein": getattr(item, "protein", None),
                "carbohydrates": getattr(item, "carbohydrates", None),
                "fat": getattr(item, "fat", None),
                "fiber": getattr(item, "fiber", None),
                "sugar": getattr(item, "sugar", None),
                "sodium": getattr(item, "sodium", None),
                "cholesterol": getattr(item, "cholesterol", None),
                "saturated_fat": getattr(item, "saturated_fat", None),
                "polyunsaturated_fat": getattr(item, "polyunsaturated_fat", None),
                "monounsaturated_fat": getattr(item, "monounsaturated_fat", None),
                "trans_fat": getattr(item, "trans_fat", None),
                "potassium": getattr(item, "potassium", None),
                "vitamin_a": getattr(item, "vitamin_a", None),
                "vitamin_c": getattr(item, "vitamin_c", None),
                "calcium": getattr(item, "calcium", None),
                "iron": getattr(item, "iron", None),
            },
            "servings": [],
        }

        # Get serving sizes if available
        if hasattr(item, "servings"):
            for serving in item.servings:
                data["servings"].append(
                    {
                        "label": str(serving),
                        "serving_id": serving.serving_id,
                        "value": serving.value,
                        "unit": serving.unit,
                        "nutrition_multiplier": serving.nutrition_multiplier,
                    }
                )

        return format_response(data, params.response_format, "Food Item Details")

    except Exception as e:
        return f"Error getting food details: {str(e)}"


@mcp.tool(
    name="mfp_get_recent_foods",
    annotations={
        "title": "Get Recent Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_recent_foods(params: GetFoodCollectionInput) -> str:
    """
    Get recently used foods from MyFitnessPal.

    Uses the legacy diary-add AJAX endpoint that still works when newer
    account pages like `/food/mine` redirect away from authenticated sessions.
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 10
        items = fetch_legacy_food_collection(client, category="recent", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "Recent Foods")
    except Exception as e:
        return f"Error getting recent foods: {str(e)}"


@mcp.tool(
    name="mfp_get_frequent_foods",
    annotations={
        "title": "Get Frequent Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_frequent_foods(params: GetFoodCollectionInput) -> str:
    """
    Get most-used foods from MyFitnessPal.

    This is backed by the legacy `load_most_used` endpoint exposed by the
    add-to-diary page.
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 10
        items = fetch_legacy_food_collection(client, category="frequent", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "Frequent Foods")
    except Exception as e:
        return f"Error getting frequent foods: {str(e)}"


@mcp.tool(
    name="mfp_get_my_foods",
    annotations={
        "title": "Get My Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_my_foods(params: GetFoodCollectionInput) -> str:
    """
    Get foods created or saved by the authenticated user.

    This uses the legacy `load_my_foods` endpoint from the add-to-diary page,
    which remains accessible in this workspace even when the modern `My Foods`
    page does not.
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 100
        items = fetch_legacy_food_collection(client, category="my_foods", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "My Foods")
    except Exception as e:
        return f"Error getting my foods: {str(e)}"


@mcp.tool(
    name="mfp_get_measurements",
    annotations={
        "title": "Get Body Measurements",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_measurements(params: GetMeasurementsInput) -> str:
    """
    Get body measurements (weight, body fat, etc.) over a date range.

    Returns historical measurement data with dates and values. Useful for
    tracking weight loss progress and body composition changes.

    Args:
        params: GetMeasurementsInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - start_date (str, optional): Start date, defaults to 30 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Measurement history with dates and values
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=30)

        measurements = client.get_measurements(params.measurement, start, end)

        data = {
            "measurement_type": params.measurement,
            "start_date": str(start),
            "end_date": str(end),
            "count": len(measurements),
            "values": ordered_dict_to_dict(measurements),
        }

        # Calculate summary stats if we have data
        if measurements:
            values = list(measurements.values())
            data["summary"] = {
                "latest": values[-1] if values else None,
                "earliest": values[0] if values else None,
                "change": round(values[-1] - values[0], 2) if len(values) >= 2 else 0,
                "min": min(values),
                "max": max(values),
                "average": round(sum(values) / len(values), 2),
            }

        return format_response(
            data, params.response_format, f"{params.measurement} History"
        )

    except Exception as e:
        return f"Error getting measurements: {str(e)}"


@mcp.tool(
    name="mfp_set_measurement",
    annotations={
        "title": "Log Body Measurement",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_measurement(params: SetMeasurementInput) -> str:
    """
    Log a new body measurement (weight, body fat, etc.) for today.

    Records the measurement value in MyFitnessPal for tracking progress.

    Args:
        params: SetMeasurementInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - value (float): Measurement value (e.g., 185.5)

    Returns:
        str: Confirmation message with the logged value
    """
    try:
        client = get_mfp_client()
        client.set_measurements(params.measurement, params.value)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.measurement}: {params.value}",
                "measurement": params.measurement,
                "value": params.value,
                "date": str(date.today()),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting measurement: {str(e)}"


@mcp.tool(
    name="mfp_get_exercises",
    annotations={
        "title": "Get Exercise Log",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_exercises(params: GetExercisesInput) -> str:
    """
    Get logged exercises for a specific date.

    Returns both cardiovascular and strength training exercises with their
    details (duration, calories burned, sets, reps, weight, etc.).

    Args:
        params: GetExercisesInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of exercises with details and calories burned
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "exercises": []}

        for exercise in day.exercises:
            data["exercises"].append(format_exercise(exercise))

        # Calculate total calories burned
        total_burned = 0
        for ex in data["exercises"]:
            for entry in ex.get("entries", []):
                if "nutrition_information" in entry:
                    total_burned += entry["nutrition_information"].get(
                        "calories burned", 0
                    )

        data["total_calories_burned"] = total_burned

        return format_response(
            data, params.response_format, f"Exercise Log for {target_date}"
        )

    except Exception as e:
        return f"Error getting exercises: {str(e)}"


@mcp.tool(
    name="mfp_get_goals",
    annotations={
        "title": "Get Nutrition Goals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_goals(params: GetGoalsInput) -> str:
    """
    Get the user's daily nutrition goals (calories, protein, carbs, fat, etc.).

    Returns the configured daily targets for all tracked nutrients.

    Args:
        params: GetGoalsInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily nutrition goals and targets
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "goals": day.goals}

        return format_response(data, params.response_format, "Daily Nutrition Goals")

    except Exception as e:
        return f"Error getting goals: {str(e)}"


@mcp.tool(
    name="mfp_set_goals",
    annotations={
        "title": "Update Nutrition Goals",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_set_goals(params: SetGoalsInput) -> str:
    """
    Update daily nutrition goals (calories, protein, carbs, fat).

    Sets new daily targets for the specified nutrients. Only updates the
    values that are provided; others remain unchanged.

    Args:
        params: SetGoalsInput containing:
            - calories (int, optional): Daily calorie goal
            - protein (int, optional): Daily protein goal in grams
            - carbohydrates (int, optional): Daily carb goal in grams
            - fat (int, optional): Daily fat goal in grams

    Returns:
        str: Confirmation message with updated goals
    """
    try:
        # Check that at least one goal is provided
        if not any(
            [params.calories, params.protein, params.carbohydrates, params.fat]
        ):
            return "Error: Please provide at least one goal to update (calories, protein, carbohydrates, or fat)"

        client = get_mfp_client()

        # Build kwargs for set_new_goal
        kwargs = {}
        if params.calories:
            kwargs["energy"] = params.calories
        if params.protein:
            kwargs["protein"] = params.protein
        if params.carbohydrates:
            kwargs["carbohydrates"] = params.carbohydrates
        if params.fat:
            kwargs["fat"] = params.fat

        client.set_new_goal(**kwargs)

        return json.dumps(
            {
                "success": True,
                "message": "Successfully updated nutrition goals",
                "updated_goals": {
                    "calories": params.calories,
                    "protein": params.protein,
                    "carbohydrates": params.carbohydrates,
                    "fat": params.fat,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting goals: {str(e)}"


@mcp.tool(
    name="mfp_get_water",
    annotations={
        "title": "Get Water Intake",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_water(params: GetWaterInput) -> str:
    """
    Get water intake for a specific date.

    Returns the number of cups/glasses of water logged for the day.

    Args:
        params: GetWaterInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Water intake amount for the specified date
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {
            "date": str(target_date),
            "water_cups": day.water,
            "water_ml": day.water * 236.588,  # Convert cups to ml
        }

        return json.dumps(data, indent=2)

    except Exception as e:
        return f"Error getting water intake: {str(e)}"


@mcp.tool(
    name="mfp_add_food_to_diary",
    annotations={
        "title": "Add Food to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_add_food_to_diary(params: AddFoodToDiaryInput) -> str:
    """
    Add a food item to your MyFitnessPal food diary for a specific date and meal.

    This tool adds a food entry to your diary. You can search for foods using
    mfp_search_food to find the food ID (mfp_id) needed for this tool.

    Args:
        params: AddFoodToDiaryInput containing:
            - mfp_id (str): MyFitnessPal food item ID (from mfp_search_food)
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - quantity (float): Number of servings (default: 1.0)
            - unit (str, optional): Unit/serving size (e.g., '1 cup', '100g')

    Returns:
        str: Confirmation message with details of the added food entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Normalize meal name (capitalize first letter)
        meal = params.meal.strip().capitalize()
        if meal.lower() == "snack":
            meal = "Snacks"

        # Add food to diary
        added_entry = add_food_to_diary(
            client=client,
            mfp_id=params.mfp_id,
            meal=meal,
            target_date=target_date,
            quantity=params.quantity,
            unit=params.unit,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully added {added_entry['name']} to {added_entry['meal']}",
                "date": str(target_date),
                "meal": added_entry["meal"],
                "food_id": params.mfp_id,
                "food_name": added_entry["name"],
                "entry_id": added_entry["entry_id"],
                "quantity": added_entry["quantity"],
                "unit": added_entry["unit"],
                "nutrition": added_entry["nutrition"],
            },
            indent=2,
        )

    except Exception as e:
        return f"Error adding food to diary: {str(e)}"


@mcp.tool(
    name="mfp_update_food_entry",
    annotations={
        "title": "Update Diary Entry",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_update_food_entry(params: UpdateFoodEntryInput) -> str:
    """
    Update an existing MyFitnessPal diary entry.

    Supports changing the meal, quantity, serving size, and date for an entry
    previously returned by mfp_get_diary.
    """
    try:
        if params.meal is None and params.quantity is None and params.unit is None and params.weight_id is None:
            return "Error updating food entry: provide at least one of meal, quantity, unit, or weight_id."

        client = get_mfp_client()
        target_date = parse_date(params.date)
        result = update_food_entry(
            client=client,
            entry_id=params.entry_id,
            target_date=target_date,
            meal=params.meal,
            quantity=params.quantity,
            unit=params.unit,
            weight_id=params.weight_id,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully updated diary entry {params.entry_id}",
                "entry_id": params.entry_id,
                "current_entry_id": result["after"]["entry_id"],
                "entry_id_changed": result["entry_id_changed"],
                "date": str(target_date),
                "meal": result["after"]["meal"],
                "quantity": result["after"]["quantity"],
                "unit": result["after"]["unit"],
                "weight_id": params.weight_id,
                "confirmed_entry_name": result["after"]["name"],
                "confirmed_meal": result["after"]["meal"],
            },
            indent=2,
        )
    except Exception as e:
        return f"Error updating food entry: {str(e)}"


@mcp.tool(
    name="mfp_delete_food_entry",
    annotations={
        "title": "Delete Diary Entry",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_delete_food_entry(params: DeleteFoodEntryInput) -> str:
    """
    Delete an existing MyFitnessPal diary entry.

    Deletes a diary entry identified by the `entry_id` returned by mfp_get_diary.
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        deleted_entry = delete_food_entry(client=client, entry_id=params.entry_id, target_date=target_date)
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully deleted diary entry {params.entry_id}",
                "entry_id": params.entry_id,
                "date": str(target_date),
                "deleted_entry_name": deleted_entry["name"],
                "deleted_meal": deleted_entry["meal"],
            },
            indent=2,
        )
    except Exception as e:
        return f"Error deleting food entry: {str(e)}"


@mcp.tool(
    name="mfp_set_water",
    annotations={
        "title": "Log Water Intake",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_water(params: SetWaterInput) -> str:
    """
    Log water intake for a specific date.

    Sets the number of cups of water consumed for the day. MyFitnessPal uses
    cups as the unit (1 cup = ~237ml).

    Args:
        params: SetWaterInput containing:
            - cups (float): Number of cups of water (e.g., 2.5 for 2.5 cups)
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the logged water amount
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        
        # Set water intake
        set_water_intake(client=client, target_date=target_date, cups=params.cups)
        
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.cups} cups of water",
                "date": str(target_date),
                "cups": params.cups,
                "milliliters": round(params.cups * 236.588, 2),
            },
            indent=2,
        )
        
    except Exception as e:
        return f"Error setting water intake: {str(e)}"


@mcp.tool(
    name="mfp_get_report",
    annotations={
        "title": "Get Nutrition Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_report(params: GetReportInput) -> str:
    """
    Get a nutrition report over a date range.

    Returns daily values for the specified nutrient/metric over the date range.
    Useful for analyzing trends and patterns in nutrition intake.

    Args:
        params: GetReportInput containing:
            - report_name (str): Report type (e.g., 'Net Calories', 'Protein')
            - start_date (str, optional): Start date, defaults to 7 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily values and summary statistics for the report period
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=7)

        report = client.get_report(
            report_name=params.report_name,
            report_category="Nutrition",
            lower_bound=start,
            upper_bound=end,
        )

        data = {
            "report_name": params.report_name,
            "start_date": str(start),
            "end_date": str(end),
            "values": (
                ordered_dict_to_dict(report) if isinstance(report, OrderedDict) else report
            ),
        }

        # Calculate summary stats
        if report:
            values = list(report.values())
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            if numeric_values:
                data["summary"] = {
                    "total": sum(numeric_values),
                    "average": round(sum(numeric_values) / len(numeric_values), 2),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                }

        return format_response(
            data, params.response_format, f"{params.report_name} Report"
        )

    except Exception as e:
        return f"Error getting report: {str(e)}"


# ============================================================================
# Cookie Management Tool
# ============================================================================


@mcp.tool()
def refresh_browser_cookies(browser: str = "chrome") -> str:
    """
    Extract and save session cookies from your web browser.
    
    Use this tool when authentication fails and you need to refresh your
    MyFitnessPal session. You must be logged into myfitnesspal.com in your
    browser for this to work.
    
    Args:
        browser: Which browser to extract cookies from ("chrome" or "firefox")
    
    Returns:
        Success message or error description
    """
    import browser_cookie3
    
    try:
        # Get browser cookie function
        if browser.lower() == "chrome":
            cj = browser_cookie3.chrome(domain_name='.myfitnesspal.com')
        elif browser.lower() == "firefox":
            cj = browser_cookie3.firefox(domain_name='.myfitnesspal.com')
        else:
            return f"Unsupported browser: {browser}. Use 'chrome' or 'firefox'."
        
        # Extract cookies to dictionary
        cookies = {c.name: c.value for c in cj}
        
        # Check for session token
        if '__Secure-next-auth.session-token' not in cookies:
            return (
                f"No session token found in {browser}. "
                "Please make sure you are logged into myfitnesspal.com in your browser, "
                "then try again."
            )
        
        # Save cookies
        save_cookies(cookies)
        
        # Verify they work
        try:
            cookiejar = dict_to_cookiejar(cookies)
            client = create_mfp_client(cookiejar=cookiejar)
            _ = client.get_date(date.today())
            
            return (
                f"Successfully extracted and verified {len(cookies)} cookies from {browser}. "
                "Authentication is now working!"
            )
        except Exception as e:
            return (
                f"Cookies were extracted from {browser} but verification failed: {e}. "
                "The session may have expired - try logging into myfitnesspal.com again."
            )
            
    except Exception as e:
        error_msg = str(e)
        if "Operation not permitted" in error_msg:
            return (
                f"Permission denied reading {browser} cookies. "
                "This can happen due to macOS security restrictions. "
                "Try running this command in Terminal instead:\n\n"
                f"{COOKIES_FILE.parent}/../venv/bin/python -c \""
                "import browser_cookie3, json, os; "
                "from datetime import datetime; "
                f"cj = browser_cookie3.{browser}(domain_name='.myfitnesspal.com'); "
                "cookies = {c.name: c.value for c in cj}; "
                "os.makedirs(os.path.expanduser('~/.mfp_mcp'), exist_ok=True); "
                "open(os.path.expanduser('~/.mfp_mcp/cookies.json'), 'w').write("
                "json.dumps({'cookies': cookies, 'saved_at': datetime.now().isoformat()}, indent=2)); "
                "print('Cookies refreshed!')\""
            )
        return f"Error extracting cookies from {browser}: {e}"


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
