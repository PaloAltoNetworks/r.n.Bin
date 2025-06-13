from colorama import init, Fore, Style
init() # Initialize colorama for the current terminal
# colors.py
"""
Defines ANSI escape codes for colored console output, following the
Palo Alto Networks Unit 42 color scheme.
"""

# Reset any applied formatting
COLOR_RESET = "\033[0m"

# Standard ANSI colors (using approximations from the PAN images)
# Note:  These may not be a perfect match to the PAN colors, but are
#       reasonable ANSI approximations within the limitations of
#       standard terminal color support.  Hex codes from images are noted.
COLOR_BLACK = "\033[30m"  # (Approx) -  Base black, keep as is
COLOR_FIRE_RED_BASE = "\033[31m"    # (Approx) - Basic fallback if Fire Red isn't bright enough
COLOR_INTELLIGENCE_GREEN_BASE = "\033[32m"  # (Approx) - Basic fallback if Intelligence Green isn't bright enough
COLOR_SECURITY_YELLOW_BASE = "\033[33m" # (Approx) - Basic fallback if Security Yellow isn't bright enough
COLOR_CLOUD_BLUE_BASE = "\033[34m"   # (Approx) - Basic fallback if Cloud Blue isn't bright enough
COLOR_MAGENTA = "\033[35m" # (Approx) -  Not a PAN core color, but provide a fallback
COLOR_CYAN = "\033[36m"    # (Approx) - Not a PAN core color, but provide a fallback
COLOR_WHITE = "\033[37m"   # (Approx) -  Base white, keep as is

# Bright/Light ANSI colors (Customized to PAN Unit 42 scheme)
COLOR_GRAY = "\033[90m" # (Approx) - Keep as is; gray fallback in some terminals
COLOR_FIRE_RED = "\033[91m"   # Fire Red (C84727,  R200 G71 B39, but using Bright Red ANSI)
COLOR_INTELLIGENCE_GREEN = "\033[92m" # Intelligence Green (00CC66, R0 G204 B102, but using Bright Green ANSI)
COLOR_SECURITY_YELLOW = "\033[93m"# Security Yellow (FFCB06, R255 G203 B6, but using Bright Yellow ANSI)
COLOR_CLOUD_BLUE = "\033[94m"  # Cloud Blue (00C0E8, R0 G192 B232, but using Bright Blue ANSI)
COLOR_CYBER_ORANGE = Fore.RED + Fore.YELLOW# Cyber Orange (FA582D, Approximate - as no direct match, and for emphasis)
COLOR_CYAN_BRIGHT = "\033[96m"  # (Approx) - Used for Prompts - leave as is for now
COLOR_WHITE_BRIGHT = "\033[97m" # (Approx) - Keep as is as general bright white

# Common text styles (Keep as is)
COLOR_BOLD = "\033[1m"
COLOR_ITALIC = "\033[3m"
COLOR_UNDERLINE = "\033[4m"
COLOR_STRIKETHROUGH = "\033[9m"

# Semantic color aliases - Customized for Palo Alto Networks Unit 42
INFO_COLOR = COLOR_INTELLIGENCE_GREEN      # For successful operations, [+] messages - Intelligence Green
WARNING_COLOR = COLOR_SECURITY_YELLOW  # For warnings, [!] messages - Security Yellow
ERROR_COLOR = COLOR_FIRE_RED       # For errors, [!] messages - Fire Red
PROMPT_COLOR = COLOR_CYAN_BRIGHT     # For user input prompts - Bright Cyan (existing good choice)
HIGHLIGHT_COLOR = COLOR_SECURITY_YELLOW # For important numerical data (tokens, cost) - Security Yellow
HEADER_COLOR = COLOR_CLOUD_BLUE     # For section headers or visual separators - Cloud Blue
STREAM_COLOR = COLOR_CYBER_ORANGE    # For streaming LLM output -Cyber Orange
