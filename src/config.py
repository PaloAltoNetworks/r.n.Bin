import vertexai
from vertexai.generative_models import SafetySetting, HarmCategory, HarmBlockThreshold
from colors import *
import json
import os
import sys
import logging
from dotenv import load_dotenv

#  Load environment variables from .env file 
load_dotenv()

#  Retrieve project and location from environment variables 
project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
location = os.getenv("GOOGLE_CLOUD_LOCATION")

#  Validate that the environment variables are set 
if not project_id or not location:
    logging.error("FATAL: GOOGLE_CLOUD_PROJECT and/or GOOGLE_CLOUD_LOCATION not set in .env file.")
    sys.exit(
        f"{ERROR_COLOR}Error: Please set GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION in a .env file.{COLOR_RESET}"
    )

#  Load Prompts from External File 
try:
    with open('prompts.json', 'r', encoding='utf-8') as f:
        all_prompts = json.load(f)

    # Unpack prompts into variables to maintain compatibility with original code
    SYSTEM_INSTRUCTIONS = all_prompts.get("SYSTEM_INSTRUCTIONS", {})
    SYSTEM_INSTRUCTION_RENAME = SYSTEM_INSTRUCTIONS.get("RENAME_FUNCTIONS", "")
    SYSTEM_INSTRUCTION_SUMMARY_PERSONAS = SYSTEM_INSTRUCTIONS.get("SUMMARY_PERSONAS", {})
    BINARY_PROMPT_TEMPLATES = all_prompts.get("BINARY_PROMPT_TEMPLATES", {})
    SUMMARY_PROMPT_TEMPLATES = all_prompts.get("SUMMARY_PROMPT_TEMPLATES", {})

    # Check if any crucial prompts are missing
    if not all([SYSTEM_INSTRUCTION_RENAME, SYSTEM_INSTRUCTION_SUMMARY_PERSONAS, BINARY_PROMPT_TEMPLATES, SUMMARY_PROMPT_TEMPLATES]):
        logging.warning("Warning: One or more prompt sections are missing or empty in prompts.json.")

except FileNotFoundError:
    logging.error(f"FATAL: Prompt file 'prompts.json' not found in the current directory ({os.getcwd()}).")
    sys.exit(f"{ERROR_COLOR}Error: Could not find prompts.json. Please ensure it's in the same directory as the script.{COLOR_RESET}")
except json.JSONDecodeError as e:
    logging.error(f"FATAL: Could not parse 'prompts.json'. It may contain a syntax error. Details: {e}")
    sys.exit(f"{ERROR_COLOR}Error: Could not parse prompts.json. Please check the file for JSON syntax errors.{COLOR_RESET}")

try:
    vertexai.init(project=project_id, location=location)
    VERTEX_AI_INITIALIZED = True
    print(f"Vertex AI initialized successfully for project.")
except Exception as e:
    logging.error(f"Could not initialize Vertex AI. LLM features will not work. Error: {e}")
    print(f"{WARNING_COLOR}Warning: Could not initialize Vertex AI. LLM features will not work. Error: {e}{COLOR_RESET}")
    VERTEX_AI_INITIALIZED = False


INPUT_TOKEN_PRICING_PER_MILLION = {
    "gemini-1.5-pro-002": {
        "threshold": 200000,
        "under_threshold": 1.25,
        "over_threshold": 2.50,
    },
    "gemini-2.0-flash-001": 0.15,
}

GENERATION_CONFIG = {
    "max_output_tokens": 8192,
    "temperature": 1,
    "top_p": 0.95,
}

SAFETY_SETTINGS = [
    SafetySetting(
        category=HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=HarmBlockThreshold.BLOCK_NONE
    ),
    SafetySetting(
        category=HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=HarmBlockThreshold.BLOCK_NONE
    ),
    SafetySetting(
        category=HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=HarmBlockThreshold.BLOCK_NONE
    ),
    SafetySetting(
        category=HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=HarmBlockThreshold.BLOCK_NONE
    ),
]

USER_MODELS = {
    "gemini-2.0-flash-001": "gemini-2.0-flash-001",
    "gemini-1.5-pro-002": "gemini-1.5-pro-002"
}
