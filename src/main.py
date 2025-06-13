import os
import time
import logging
import questionary
import json
import sys
import re

from ida_orchestrator import run_ida_read_file, find_i64_file, find_c_file, find_extracted_functions_file, \
    find_extracted_functions_file
from llm_analyzer import LLMAnalyzer
from utils import generate_rnbin_ascii_art, sha256_hash_bytes, read_bytes, read_file, write_file
from ida_api_methods_stub import first_pass_renaming, refine_sub_functions, enumerate_functions, \
    decompile_and_extract_userland_functions
from config import USER_MODELS, BINARY_PROMPT_TEMPLATES, SUMMARY_PROMPT_TEMPLATES, SYSTEM_INSTRUCTION_SUMMARY_PERSONAS, \
    SYSTEM_INSTRUCTION_RENAME, INPUT_TOKEN_PRICING_PER_MILLION

from colors import *
from colorama import init, Fore, Style

init()

llm_analyzer = None

INPUT_TOKEN_PRICING_PER_MILLION = {
    "gemini-1.5-pro-002": {
        "threshold": 200000,
        "under_threshold": 1.25,
        "over_threshold": 2.50,
    },
    "gemini-1.5-flash-002": 0.15,
    "gemini-2.0-flash-001": 0.15,
}


def calculate_input_cost(model_name: str, input_tokens: int) -> float | None:
    pricing_info = INPUT_TOKEN_PRICING_PER_MILLION.get(model_name)
    if pricing_info is None:
        logger.warning(f"Pricing data not available for model '{model_name}'. Cannot estimate cost.")
        return None
    price_per_million = 0.0
    if isinstance(pricing_info, dict):
        threshold = pricing_info.get("threshold", 0)
        if input_tokens <= threshold:
            price_per_million = pricing_info.get("under_threshold", 0)
        else:
            price_per_million = pricing_info.get("over_threshold", pricing_info.get("under_threshold", 0))
    else:
        price_per_million = pricing_info
    cost = (input_tokens / 1_000_000.0) * price_per_million
    return cost


def configure_logger(sha256_hash, output_dir="."):
    log_filename = f"{sha256_hash}_ida_analysis.log"
    log_filepath = os.path.join(output_dir, log_filename)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    try:
        file_handler = logging.FileHandler(log_filepath, mode='w', encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"{ERROR_COLOR}ERROR: Could not create log file handler at {log_filepath}: {e}{Style.RESET_ALL}")
    return logger


logger = logging.getLogger()


if __name__ == "__main__":
    input_tokens = 0
    ascii_art = generate_rnbin_ascii_art(font="standard")
    if ascii_art:
        print(f"{PROMPT_COLOR}{ascii_art}{COLOR_RESET}")
    print("\nWelcome to r.n.Bin: Binary Analysis & Annotation Tool\n")
    ts_start = time.time()
    user_input = input(
        f"\n{PROMPT_COLOR}Enter the path to the binary file: {COLOR_RESET}").strip(
        "\"")

    output_base_dir = os.path.dirname(user_input)
    if not output_base_dir:
        output_base_dir = os.getcwd()
    try:
        os.makedirs(output_base_dir, exist_ok=True)
    except OSError as e:
        print(f"{ERROR_COLOR}ERROR: Could not create output directory {output_base_dir}: {e}{COLOR_RESET}")
        exit()

    hash_data = read_bytes(user_input)
    if hash_data is None:
        logger = configure_logger("startup_error", output_base_dir)
        logger.error(f"Could not read the file: {user_input}")
        print(f"{ERROR_COLOR}Could not read the file: {user_input}{COLOR_RESET}")
        exit()
    sha256_hash_value = sha256_hash_bytes(hash_data)

    logger = configure_logger(sha256_hash_value, output_base_dir)
    print(f"{INFO_COLOR}Analyzing file:{COLOR_RESET} {user_input}")
    print(f"{INFO_COLOR}SHA256:{COLOR_RESET} {sha256_hash_value}")
    logger.info(f"Analyzing file:{user_input}")
    logger.info(f"SHA256:{sha256_hash_value}")

    first_pass_buffer = None  # This will hold either the full C output or the extracted functions
    idb_path = None

    try:
        user_input_basename = os.path.basename(user_input)
        idb_path = find_i64_file(user_input, logger)
        c_file_path = os.path.join(output_base_dir, f"{sha256_hash_value}.c")

        check_for_c_file = find_c_file(c_file_path, logger)

        if check_for_c_file:
            first_pass_buffer = read_file(check_for_c_file, logger)
            if first_pass_buffer:
                logger.info(f"Existing C file found. No need to execute IDA in headless mode.")
                print(f"{INFO_COLOR}Existing C file found. No need to execute IDA in headless mode.{COLOR_RESET}")
            else:
                logger.warning(f"Existing C file '{check_for_c_file}' was empty or unreadable. Regenerating.")
                print(
                    f"{WARNING_COLOR}Existing C file '{check_for_c_file}' was empty or unreadable. Regenerating.{COLOR_RESET}")
                check_for_c_file = None
        else:
            logger.info(f"No existing C file found. Continuing...")
            print(f"{INFO_COLOR}No existing C file found. Continuing...{COLOR_RESET}")

        if idb_path is None or check_for_c_file is None:
            logger.info("Running IDA in headless mode to generate analysis files.")
            print(f"{INFO_COLOR}Running IDA in headless mode to generate analysis files.{COLOR_RESET}")

            first_pass_buffer = run_ida_read_file(user_input, logger, sha256_hash_value,
                                                  output_base_dir)
            idb_path = find_i64_file(user_input, logger)

        if first_pass_buffer is None:
            logger.error(
                "Failed to get decompiled code buffer after attempting to read or generate. Aborting analysis.")
            print(
                f"{ERROR_COLOR}Failed to get decompiled code buffer after attempting to read or generate. Aborting analysis.{COLOR_RESET}")
            exit()

        # Scrape the potential user-defined functions and their EAs
        sub_functions_set_names = enumerate_functions(idb_path, "name")
        sub_functions_set_eas = enumerate_functions(idb_path, "ea")

        total_sub_functions = len(sub_functions_set_names)

        logger.info(
            f"Identified approximately {total_sub_functions} user-defined functions for potential renaming ({total_sub_functions} unique).")
        print(
            f"{INFO_COLOR}Identified approximately {HIGHLIGHT_COLOR}{total_sub_functions}{COLOR_RESET}{INFO_COLOR} user-defined functions for potential renaming ({HIGHLIGHT_COLOR}{total_sub_functions}{COLOR_RESET}{INFO_COLOR} unique).{COLOR_RESET}")

        default_model_for_costing = list(USER_MODELS.keys())[0]

        # Token counting for the full buffer (initial `first_pass_buffer`)
        try:
            input_tokens = LLMAnalyzer(model_name=default_model_for_costing, logger=logger).count_tokens(
                first_pass_buffer)
            if input_tokens > 0:
                logger.info(f"Estimated input tokens for the full buffer: {input_tokens:,}")
                print(
                    f"{INFO_COLOR}Estimated input tokens for the full buffer: {HIGHLIGHT_COLOR}{input_tokens:,}{COLOR_RESET}")
                estimated_cost = calculate_input_cost(default_model_for_costing, input_tokens)
                if estimated_cost is not None:
                    logger.info(
                        f"Estimated cost for this input chunk with '{default_model_for_costing}': ${estimated_cost:.6f} USD (Estimate only, actual cost may vary.)")
                    print(
                        f"{INFO_COLOR}Estimated cost for this input chunk with '{default_model_for_costing}': {HIGHLIGHT_COLOR}${estimated_cost:.6f} USD{COLOR_RESET} (Estimate only, actual cost may vary.)")
            elif input_tokens == 0:
                logger.warning(f"Token count returned 0 for the initial buffer.")
                print(f"{WARNING_COLOR}Token count returned 0 for the initial buffer.{COLOR_RESET}")
        except Exception:
            logger.exception(f"An error occurred while counting initial tokens:")
            print(f"{ERROR_COLOR}An error occurred while counting initial tokens:{COLOR_RESET}")
            input_tokens = 0

        extracted_functions = False  # Flag to indicate if we're using an extracted function buffer


        extracted_functions_file_path = os.path.join(output_base_dir, f"{sha256_hash_value}_extracted_functions.txt")
        existing_extracted_file = find_extracted_functions_file(extracted_functions_file_path, logger)

        if existing_extracted_file:
            extracted_functions_buffer_content = read_file(existing_extracted_file, logger)
            if extracted_functions_buffer_content:
                logger.info(f"Using existing extracted functions file '{existing_extracted_file}'.")
                print(f"{INFO_COLOR}Using existing extracted functions file '{existing_extracted_file}'.{COLOR_RESET}")
                first_pass_buffer = extracted_functions_buffer_content  # Use the content from the file
                extracted_functions = True  # Mark as extracted
                # Re-count tokens after using the extracted file
                try:
                    input_tokens = LLMAnalyzer(model_name=default_model_for_costing, logger=logger).count_tokens(
                        first_pass_buffer)
                    logger.info(f"Estimated input tokens from existing extracted file: {input_tokens:,}")
                    print(
                        f"{INFO_COLOR}Estimated input tokens from existing extracted file: {HIGHLIGHT_COLOR}{input_tokens:,}{COLOR_RESET}")
                    estimated_cost = calculate_input_cost(default_model_for_costing, input_tokens)
                    if estimated_cost is not None:
                        logger.info(
                            f"Estimated cost for existing extracted input chunk with '{default_model_for_costing}': ${estimated_cost:.6f} USD (Estimate only).")
                        print(
                            f"{INFO_COLOR}Estimated cost for existing extracted input chunk with '{default_model_for_costing}': {HIGHLIGHT_COLOR}${estimated_cost:.6f} USD{COLOR_RESET} (Estimate only).")
                except Exception:
                    logger.exception(f"An error occurred while counting tokens for existing extracted file:")
                    print(
                        f"{ERROR_COLOR}An error occurred while counting tokens for existing extracted file:{COLOR_RESET}")
                    input_tokens = 0
            else:
                logger.warning(
                    f"Existing extracted functions file '{existing_extracted_file}' was empty or unreadable. Regenerating if prompted.")
                print(
                    f"{WARNING_COLOR}Existing extracted functions file '{existing_extracted_file}' was empty or unreadable. Regenerating if prompted.{COLOR_RESET}")

        # Only prompt for extraction IF no existing extracted file was found/used
        # AND the current buffer is large or token count failed (input_tokens == 0 check).
        if not extracted_functions and (input_tokens > 1800000 or input_tokens == 0):
            logger.info(
                f"Buffer size ({input_tokens} tokens) is potentially large or count failed. Suggesting extraction.")
            print(
                f"Buffer size {HIGHLIGHT_COLOR}({input_tokens}{COLOR_RESET} tokens) is potentially large or count failed. Suggesting extraction.")

            extract_function_selection = questionary.confirm(
                f"[!] - The code buffer is large. Extract function boundaries to reduce text size and potentially token cost?",
                default=True).ask()

            if extract_function_selection:
                logger.info(f"User chose to extract function boundaries.")
                print(f"{INFO_COLOR}User chose to extract function boundaries.{COLOR_RESET}")
                extracted_buffer_dict = decompile_and_extract_userland_functions(idb_path, sub_functions_set_eas)

                if extracted_buffer_dict:
                    formatted_extracted_text = ""
                    for addr, pseudocode in extracted_buffer_dict.items():
                        formatted_extracted_text += f"\n// Function at {addr}\n"
                        formatted_extracted_text += f"{pseudocode}\n"

                    first_pass_buffer = formatted_extracted_text

                    # Use the determined path for extracted functions file
                    write_file(output_base_dir,
                               extracted_functions_file_path,
                               first_pass_buffer, logger)
                    try:
                        input_tokens = LLMAnalyzer(
                            model_name=default_model_for_costing,
                            logger=logger).count_tokens(first_pass_buffer)
                        logger.info(f"Estimated input tokens after extraction: {input_tokens:,}")
                        print(
                            f"{INFO_COLOR}Estimated input tokens after extraction: {HIGHLIGHT_COLOR}{input_tokens:,}{COLOR_RESET}")

                        estimated_cost = calculate_input_cost(
                            default_model_for_costing, input_tokens)
                        if estimated_cost is not None:
                            logger.info(
                                f"Estimated cost for extracted input chunk with '{default_model_for_costing}': ${estimated_cost:.6f} USD (Estimate only).")
                            print(
                                f"{INFO_COLOR}Estimated cost for extracted input chunk with '{default_model_for_costing}': {HIGHLIGHT_COLOR}${estimated_cost:.6f} USD{COLOR_RESET} (Estimate only).")

                    except Exception:
                        logger.exception(f"An error occurred while counting extracted tokens:")
                        print(f"{ERROR_COLOR}An error occurred while counting extracted tokens:{COLOR_RESET}")
                        input_tokens = 0

                    extracted_functions = True  # Mark as extracted
                else:
                    logger.warning(f"Extraction yielded empty buffer. Proceeding with original full buffer.")
                    print(
                        f"{WARNING_COLOR}Extraction yielded empty buffer. Proceeding with original full buffer.{COLOR_RESET}")
                    extracted_functions = False  # Keep as False if extraction failed
            else:
                logger.info("User chose NOT to extract function boundaries.")

        llm_model_choice = questionary.select(
            f"\n[!] - Choose a Gemini Model for analysis: (Not responsible for the cost.)",
            choices=list(USER_MODELS.keys())
        ).ask()
        if not llm_model_choice:
            logger.info(f"Model selection cancelled by user. Aborting analysis.")
            print(f"{INFO_COLOR}Model selection cancelled by user. Aborting analysis.{COLOR_RESET}")
            exit()

        llm_analyzer = LLMAnalyzer(model_name=llm_model_choice, logger=logger)

        proceed_action = questionary.select(
            f"\n[!] - What do you want to do?",
            choices=[
                "Perform function renaming then generate a summary.",
                "Generate summary report only (skip renaming).",
                "Exit program."
            ]
        ).ask()

        if proceed_action == "Exit program.":
            logger.info(f"User aborted analysis.")
            print(f"{INFO_COLOR}Analysis aborted by the user.{COLOR_RESET}")
            exit()

        perform_renaming = (proceed_action == "Perform function renaming then generate a summary.")
        skip_renaming_but_summarize_only = (proceed_action == "Generate summary report only (skip renaming).")

        renaming_attempted = False
        first_pass_success = True
        refinement_process_successful = True
        summarize_confirmed = False

        if perform_renaming:
            prompt_selection_for_renaming = questionary.select(
                f"\n[!] - Choose a prompt related to the binary for renaming functions:",
                choices=list(BINARY_PROMPT_TEMPLATES.keys())
            ).ask()

            if not prompt_selection_for_renaming:
                logger.info(f"Renaming prompt selection cancelled by user. Skipping renaming.")
                print(f"{INFO_COLOR}Renaming prompt selection cancelled by user. Skipping renaming.{COLOR_RESET}")
                perform_renaming = False
                renaming_attempted = False
            else:
                llm_analyzer.prompt_selection = prompt_selection_for_renaming

                ida_rename_prefix_selection = questionary.text(
                    f"\n[!] - Choose a prefix for the LLM-renamed functions.",
                    default="llm_"
                ).ask()
                if ida_rename_prefix_selection is None:
                    logger.info(f"Prefix selection cancelled by user. Skipping renaming.")
                    print(f"{INFO_COLOR}Prefix selection cancelled by user. Skipping renaming.{COLOR_RESET}")
                    perform_renaming = False
                    renaming_attempted = False
                else:
                    if total_sub_functions > 0:
                        renaming_attempted = True
                        logger.info(
                            f"Proceeding with renaming {total_sub_functions} functions using '{llm_model_choice}' and prompt '{prompt_selection_for_renaming}'.")
                        print(
                            f"Proceeding with renaming {HIGHLIGHT_COLOR}{total_sub_functions}{COLOR_RESET} functions using '{HIGHLIGHT_COLOR}{llm_model_choice}{COLOR_RESET}' and prompt '{HIGHLIGHT_COLOR}{prompt_selection_for_renaming}{COLOR_RESET}'.")

                        first_pass_success = first_pass_renaming(
                            sub_functions_set_names, first_pass_buffer, idb_path,
                            ida_rename_prefix_selection, logger, llm_model_choice, prompt_selection_for_renaming,
                            llm_analyzer
                        )

                        if first_pass_success:
                            logger.info(f"First pass renaming successfully processed. Initiating refinement stage.")
                            print(
                                f"{INFO_COLOR}First pass renaming successfully processed. Initiating refinement stage.{COLOR_RESET}")

                            current_sub_functions_in_idb_names = enumerate_functions(idb_path, "name")
                            remaining_count_after_first_pass = len(current_sub_functions_in_idb_names)

                            logger.info(
                                f"{HIGHLIGHT_COLOR}{remaining_count_after_first_pass}{COLOR_RESET} 'sub_' functions remain after first pass.")
                            print(
                                f"{HIGHLIGHT_COLOR}{remaining_count_after_first_pass}{COLOR_RESET} 'sub_' functions remain after first pass.")

                            refinement_process_successful = refine_sub_functions(
                                idb_path=idb_path,
                                sub_functions=sub_functions_set_names,
                                sha256_hash_value=sha256_hash_value,
                                ida_rename_prefix_selection=ida_rename_prefix_selection,
                                logger=logger,
                                user_input=user_input,
                                model_selection=llm_model_choice,
                                prompt_selection=prompt_selection_for_renaming,
                                output_base_dir=output_base_dir,
                                llm_analyzer_instance=llm_analyzer,
                                sub_functions_remaining=current_sub_functions_in_idb_names,
                                extracted_functions_flag=extracted_functions
                            )

                            if refinement_process_successful:
                                logger.info(f"Refinement stage finished.")
                                print(f"{INFO_COLOR}Refinement stage finished.{COLOR_RESET}")
                            else:
                                logger.warning(f"Refinement process did not complete successfully.")
                                print(f"{WARNING_COLOR}Refinement process did not complete successfully.{COLOR_RESET}")

                        else:
                            logger.error(f"First pass renaming failed. Skipping refinement.")
                            print(f"{ERROR_COLOR}First pass renaming failed. Skipping refinement.{COLOR_RESET}")
                            refinement_process_successful = False

                    else:
                        logger.info(
                            f"No 'sub_' or 'main'-like functions found for renaming by LLM. Skipping renaming process.")
                        print(
                            f"{INFO_COLOR}No 'sub_' or 'main'-like functions found for renaming by LLM. Skipping renaming process.{COLOR_RESET}")
                        renaming_attempted = False
                        first_pass_success = True
                        refinement_process_successful = True

        logger.info(f"Running IDA Pro to get final updated C file for summary.")
        print(f"{INFO_COLOR}Running IDA Pro to get final updated C file for summary.{COLOR_RESET}")
        final_pass_buffer = run_ida_read_file(user_input, logger, sha256_hash_value,
                                              output_base_dir)

        if final_pass_buffer:
            if extracted_functions:  # This flag will be true if we loaded or extracted before.
                logger.info("Re-extracting function boundaries for summary based on previous choice.")
                print(
                    f"{INFO_COLOR}Re-extracting function boundaries for summary based on previous choice.{COLOR_RESET}")

                # Use sub_functions_set_eas here as this is the extraction path
                temp_extracted_buffer_dict = decompile_and_extract_userland_functions(idb_path,
                                                                                      sub_functions_set_eas)

                if temp_extracted_buffer_dict:
                    formatted_extracted_text = ""
                    for addr, pseudocode in temp_extracted_buffer_dict.items():
                        formatted_extracted_text += f"\n// Function at {addr}\n"
                        formatted_extracted_text += f"{pseudocode}\n"

                    final_pass_buffer = formatted_extracted_text
                    logger.info("Summary buffer successfully re-extracted.")
                else:
                    logger.warning(
                        f"Re-extraction for summary yielded empty buffer. Summary might be incomplete or fail.")
                    print(
                        f"{WARNING_COLOR}Re-extraction for summary yielded empty buffer. Summary might be incomplete or fail.{COLOR_RESET}")

            if skip_renaming_but_summarize_only:
                summarize_confirmed = True
                logger.info("Proceeding with summary generation (user chose summary-only mode).")
            elif perform_renaming and (first_pass_success and refinement_process_successful):
                summarize_confirmed = questionary.confirm(
                    f"[!] Renaming operations completed. Do you want to generate a summary report of the decompiled code?",
                    default=True
                ).ask()
            elif (not perform_renaming and not skip_renaming_but_summarize_only) or (
                    renaming_attempted and not (first_pass_success and refinement_process_successful)):
                summarize_confirmed = questionary.confirm(
                    f"[!] Do you want to generate a summary report of the decompiled code?",
                    default=True
                ).ask()

            if summarize_confirmed:
                system_persona_key = questionary.select(
                    f"\n[!] - Choose a System Instruction Persona for generating summary:",
                    choices=list(SYSTEM_INSTRUCTION_SUMMARY_PERSONAS.keys())
                ).ask()

                if system_persona_key:
                    logger.info(f"Starting summary generation stage with persona: {system_persona_key}")
                    print(
                        f"{INFO_COLOR}Starting summary generation stage with persona: {system_persona_key}{COLOR_RESET}")

                    summary_prompt_key = questionary.select(
                        f"\n[!] - Choose a Summary prompt for generating a summary:",
                        choices=list(SUMMARY_PROMPT_TEMPLATES.keys())
                    ).ask()

                    if summary_prompt_key:
                        logger.info(f"Using summary prompt: {summary_prompt_key}")
                        print(f"{INFO_COLOR}Using summary prompt: {summary_prompt_key}{COLOR_RESET}")

                        try:
                            summary_report = llm_analyzer.summarize_malware_report(
                                final_pass_buffer, system_persona_key, summary_prompt_key
                            )

                            if summary_report:
                                full_summary_log = (
                                        "\n--- Malware Summary Report ---\n" + summary_report +
                                        "\n--- End of Malware Summary ---")
                                logger.info(full_summary_log)
                                print(full_summary_log)
                            else:
                                logger.warning(f"Malware summary generation failed.")
                                print(f"{WARNING_COLOR}Malware summary generation failed.{COLOR_RESET}")

                        except Exception as e:
                            logger.exception(f"An unexpected error occurred during summary generation: {e}")
                            print(
                                f"{ERROR_COLOR}An unexpected error occurred during summary generation: {e}{COLOR_RESET}")
                    else:
                        logger.info(f"Summary prompt selection cancelled. Skipping summary generation.")
                        print(
                            f"{INFO_COLOR}Summary prompt selection cancelled. Skipping summary generation.{COLOR_RESET}")
                else:
                    logger.info(f"System persona selection cancelled. Skipping summary generation.")
                    print(f"{INFO_COLOR}System persona selection cancelled. Skipping summary generation.{COLOR_RESET}")
            else:
                logger.info(f"Skipping summary generation as requested.")
                print(f"{INFO_COLOR}Skipping summary generation as requested.{COLOR_RESET}")

        else:
            logger.error(f"Cannot generate summary as final code buffer is empty.")
            print(f"{ERROR_COLOR}Cannot generate summary as final code buffer is empty.{COLOR_RESET}")

    finally:
        elapsed_time = time.time() - ts_start
        logger.info(f"Total elapsed time: {elapsed_time:.2f}s")
        print(f"{INFO_COLOR}Total elapsed time: {HIGHLIGHT_COLOR}{elapsed_time:.2f}s{COLOR_RESET}")

    print(f"\n{INFO_COLOR}Analysis complete. Check the log file for full details.{COLOR_RESET}")