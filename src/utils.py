import hashlib
import os
import re
import pyfiglet
import json
import logging
from colors import *
from pydantic import BaseModel, Field, ValidationError, TypeAdapter
from typing import Dict, Tuple
import json
from llm_response_model import FunctionDetails
logger = logging.getLogger(__name__)


def generate_rnbin_ascii_art(font="standard", width=80):
    """Generates ASCII art for "rnBin" using the pyfiglet library."""
    try:
        result = pyfiglet.figlet_format("r.n.Bin", font=font, width=width)
        return result
    except Exception as e:
        logging.error(f"Error generating ASCII art: {e}")
        print(f"{ERROR_COLOR}Error generating ASCII art: {e}{COLOR_RESET}")
        return None


def sha256_hash_bytes(data: bytes) -> str:
    """Generate the SHA-256 hash of the input buffer (bytes)."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def read_file(file_path, logger):
    """Reads the content of a file with UTF-8 or UTF-16 encoding."""
    if not os.path.isfile(file_path):
        logger.error(f"Error: File '{file_path}' does not exist.")
        print(f"{ERROR_COLOR}Error: File '{file_path}' does not exist.{COLOR_RESET}")
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            buffer = file.read()
            logger.debug(f"Successfully read {len(buffer)} characters from '{file_path}' (UTF-8).")
            print(f"{INFO_COLOR}Successfully read {len(buffer)} characters from '{file_path}' (UTF-8).{COLOR_RESET}")
            return buffer
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='utf-16') as file:
                buffer = file.read()
                logger.debug(f"Successfully read {len(buffer)} characters from '{file_path}' (UTF-16).")
                print(f"{INFO_COLOR}Successfully read {len(buffer)} characters from '{file_path}' (UTF-16).{COLOR_RESET}")
                return buffer
        except Exception as e:
            logger.error(f"Error reading file '{file_path}' (UTF-8 and UTF-16 attempts failed): {e}")
            print(f"{ERROR_COLOR}Error reading file '{file_path}' (UTF-8 and UTF-16 attempts failed): {e}{COLOR_RESET}")
            return None
    except Exception as e:
        logger.error(f"Error reading file '{file_path}': {e}")
        print(f"{ERROR_COLOR}Error reading file '{file_path}': {e}{COLOR_RESET}")
        return None


def read_bytes(file_path):
    """Reads the content of a file as bytes."""
    try:
        with open(file_path, 'rb') as file:
            buffer = file.read()
            return buffer
    except FileNotFoundError:
        return None
    except Exception as e:
        return None


def write_file(output_dir, file_name, content, logger):
    """Writes content to a file in the specified output directory."""
    full_path = os.path.join(output_dir, file_name)  # Join directory and file name
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Successfully wrote content to: {full_path}")
        print(f"{INFO_COLOR}Successfully wrote content to: {full_path}{COLOR_RESET}")

        return True
    except Exception as e:
        logger.error(f"Error writing file {full_path}: {e}")
        print(f"{ERROR_COLOR}Error writing file {full_path}: {e}{COLOR_RESET}")
        return False


def extract_json_from_llm_response(json_string):
    """
    Extracts a valid JSON object from a potentially truncated JSON string.
    Identifies the last known good entry using '},' and replaces it with '}}'
    to enclose the set correctly, effectively scraping the truncated entry.

    Args:
     json_string: The potentially truncated JSON string.

    Returns:
     A dictionary representing the parsed JSON object, or None if no valid
     JSON object can be extracted.
    """
    json_string = json_string.strip()

    # Remove ```json and ``` if present
    json_string = re.sub(r'```json|```', '', json_string).strip()

    if not json_string.startswith('{'):
        return None

    last_entry_end_index = json_string.rfind('},')

    if last_entry_end_index != -1:
        # Replace the last '},' with '}}'
        modified_json = json_string[:last_entry_end_index] + '}}'

        try:
            return json.loads(modified_json)
        except json.JSONDecodeError:
            pass  # Parsing failed, even after replacement

    # If all else fails, return None
    return None


#  Type Alias for the entire JSON structure
# This tells Pydantic to expect a dictionary mapping strings to our FunctionDetails model.
FunctionMapping = Dict[str, FunctionDetails]


def load_function_mapping_with_pydantic(json_data: str | Dict, logger) -> Dict[str, Tuple[str, str]]:
    """
    Parses JSON data into a function mapping using Pydantic for robust validation.

    Returns a dictionary in the original format: {name: (descriptive_name, description)}
    """
    try:
        if isinstance(json_data, str):
            parsed_models = TypeAdapter(FunctionMapping).validate_json(json_data)
        else:
            parsed_models = TypeAdapter(FunctionMapping).validate_python(json_data)

        # Convert from Pydantic models back to the original tuple format for compatibility.
        function_data = {
            current_name: (details.DescriptiveName, details.Description)
            for current_name, details in parsed_models.items()
        }
        return function_data

    except ValidationError as e:
        # Pydantic's error messages are incredibly detailed.
        logger.error(f"Pydantic Validation Error parsing function data: {e}")
        print(f"{ERROR_COLOR}Invalid JSON structure or content. Details:\n{e}{COLOR_RESET}")
        return {}  # Return an empty dict on validation failure
    except Exception as e:
        # Catch any other unexpected errors.
        logger.error(f"An unexpected error occurred while processing JSON data: {e}")
        print(f"{ERROR_COLOR}An unexpected error occurred: {e}{COLOR_RESET}")
        return {}