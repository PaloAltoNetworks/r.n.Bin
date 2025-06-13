# ida_orchestrator.py

import os
import subprocess
import sys
import time
import logging
from utils import *
from colors import *
import idapro
import ida_hexrays
import ida_undo
import idaapi


def run_ida_headless_api_mode(file_path, logger, sha256_hash_value, output_dir):
    """
    Run IDA Pro in  to generate a C file or ASM file from the input binary file. This decision was made over walking the getFunc API and decompile_func API.

    Args:
        file_path (str): Path to the binary file to be analyzed.
    """
    if not os.path.isfile(file_path):
        logger.info(
            f"{ERROR_COLOR}Error:{COLOR_RESET} File '{file_path}' does not exist.")
        return None
    c_file_name_ida = f"{sha256_hash_value}.c"
    c_file_path = os.path.join(output_dir, c_file_name_ida)

    try:
        print(f"Opening database {file_path}...")
        idapro.open_database(file_path, True)
        print(f"Successfully opened database {file_path}...")

        # Create an undo point
        if ida_undo.create_undo_point(b"Initial state, auto analysis"):
            print(f"Successfully created an undo point...")
        else:
            print(f"Failed to created an undo point...")

        # Run auto analysis
        print(f"Running auto analysis...")
        idaapi.auto_wait()

        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler not available.")
            return

        ok = ida_hexrays.decompile_many(
            outfile=c_file_path,
            funcaddrs='',
            flags=0,
        )
        idapro.close_database()
        if ok:
            print(f"Successfully exported C file to {c_file_path}")
            return c_file_path
        else:
            print("Failed to decompile all functions.")

    except FileNotFoundError:
        logger.info(f"Error: Ensure IDA Pro is installed and in your PATH.")
        print(f"{ERROR_COLOR}Error: Ensure IDA Pro is installed and in your PATH.{COLOR_RESET}")
        return None
    except subprocess.CalledProcessError as e:
        logger.info(f"Error: IDA Pro failed with exit code {e.returncode}.")
        print(f"{ERROR_COLOR}Error: IDA Pro failed with exit code {e.returncode}.{COLOR_RESET}")
        return None


def find_i64_file(user_input, logger):
    """Checks for existing .i64 file (IDA database)."""
    # Assuming IDA creates the .i64 file next to the binary, potentially with the original basename
    expected_ida_path = f"{user_input}.i64"
    if os.path.exists(expected_ida_path):
        logger.info(f"Found '.i64' file at: '{expected_ida_path}'.")
        print(f"{INFO_COLOR}Found '.i64' file at:{COLOR_RESET} '{expected_ida_path}'.")
        return expected_ida_path
    else:
        logger.info(f"'.i64' file not found at: '{expected_ida_path}'.")
        print(f"{INFO_COLOR}'.i64' file not found at:{COLOR_RESET} '{expected_ida_path}'.")
        return None


def find_c_file(c_file_path, logger):
    """Checks for existing .c file (decompiled code)."""
    if os.path.exists(c_file_path):
        logger.info(f"C file found at: '{c_file_path}'.")
        print(f"{INFO_COLOR}C file found at:{COLOR_RESET} '{c_file_path}'.")

        return c_file_path
    else:
        logger.info(f"C file not found at: '{c_file_path}'.")
        print(f"{INFO_COLOR}C file not found at:{COLOR_RESET} '{c_file_path}'.")

        return None

def find_extracted_functions_file(file_path, logger):
    """Checks for existing _extracted_functions.txt file."""
    if os.path.exists(file_path):
        logger.info(f"Extracted functions file found at: '{file_path}'.")
        print(f"{INFO_COLOR}Extracted functions file found at:{COLOR_RESET} '{file_path}'.")
        return file_path
    else:
        logger.info(f"Extracted functions file not found at: '{file_path}'.")
        print(f"{INFO_COLOR}Extracted functions file not found at:{COLOR_RESET} '{file_path}'.")
        return None

def run_ida_read_file(user_input_path, logger, sha256_hash_value, output_dir):
    """
    Runs IDA to generate the .c file and then reads it.
    """
    logger.info(f"Running IDA Pro on: '{user_input_path}'...")
    print(f"{INFO_COLOR}Running IDA Pro on:{COLOR_RESET} '{user_input_path}'...")

    c_file_path = run_ida_headless_api_mode(user_input_path, logger, sha256_hash_value,
                                        output_dir)

    if c_file_path and os.path.exists(c_file_path):
        return read_file(c_file_path, logger)
    else:
        logger.info(f"Failed to generate C file for: '{user_input_path}'.")
        print(f"{ERROR_COLOR}Failed to generate C file for:{COLOR_RESET} '{user_input_path}'.")
        return None
