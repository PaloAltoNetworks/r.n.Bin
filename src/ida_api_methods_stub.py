import idapro
import ida_funcs
import idc
import idautils
import ida_kernwin
import ida_hexrays
import ida_lines

import questionary

from llm_analyzer import LLMAnalyzer
from ida_orchestrator import *
from typing import Set, Dict, Optional
from colors import *

llm_analyzer = LLMAnalyzer()


def enumerate_functions(idb_path, function_output_type) -> Set[str] | Set[int]:
    """
    Enumerates functions from an IDA Pro database (.i64 file).
    It returns a set of names (or EAs) for functions that are potentially generic (`sub_...`),
    common entry points (`main`, `wmain`, `...CRTStartup`),
    AND are NOT marked by IDA as library functions.
    This updated version includes common entry points and significant functions
    for Go, Rust, and Nim executables often found in IDA Pro's analysis.
    """
    idapro.open_database(idb_path, False)

    if function_output_type == "name":
        user_defined_func_set: Set[str] = set()
    elif function_output_type == "ea":
        user_defined_func_set: Set[int] = set()
    else:
        raise ValueError("function_output_type must be 'name' or 'ea'")

    for func_ea in idautils.Functions():
        function_name = idc.get_func_name(func_ea)


        f = ida_funcs.get_func(func_ea)


        if f and ((f.flags & ida_funcs.FUNC_LIB) or (f.flags & ida_funcs.FUNC_THUNK)):
            continue


        is_sub_function = function_name.startswith('sub_')
        is_main_entry_point = (
                function_name == 'main' or
                function_name == 'wmain' or
                function_name.lower().endswith('crtstartup')
        )


        is_language_specific = (
            # Go-specific patterns:
                function_name.startswith('go.') or
                function_name.startswith('main.') or
                function_name.startswith('main_') or
                (function_name.endswith('.main') and '.' in function_name) or
                function_name.startswith('runtime') or
                # function_name.startswith('net_') or

                # Rust-specific patterns:
                '::' in function_name or
                function_name == 'std::rt::lang_start_internal' or
                function_name == 'core::panicking::panic_fmt' or
                function_name == 'rust_begin_unwind' or
                function_name.startswith('rust_') or

                # Nim-specific patterns:
                function_name == 'NimMainModule' or
                function_name.startswith('_NimMain_')
        )


        if is_sub_function or is_main_entry_point or is_language_specific:
            if function_output_type == "name":
                user_defined_func_set.add(function_name)
            elif function_output_type == "ea":
                user_defined_func_set.add(func_ea)

    idapro.close_database()
    return user_defined_func_set


#  Helper Stubs for external functions 
def parse_address(address_val) -> int:
    """
    Converts various address inputs (string, int) to an IDA EA (int).
    For this context, `func_ea` will already be an int, so it's a passthrough.
    """
    if isinstance(address_val, str):
        try:
            return int(address_val, 16) if address_val.startswith('0x') else int(address_val)
        except ValueError:
            print(f"Warning: Could not parse address string '{address_val}'. Returning BADADDR.")
            return idc.BADADDR
    return address_val


def decompile_checked(ea: int) -> Optional[ida_hexrays.cfunc_t]:
    """
    Attempts to decompile a function at the given EA using Hex-Rays.
    Handles initialization and common errors.
    Returns the cfunc_t object on success, None on failure.
    """
    # Ensure Hex-Rays plugin is available and initialized
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays plugin is not initialized or not available.")
        return None

    f = ida_funcs.get_func(ea)
    if not f:
        # print(f"No function object found at EA: {hex(ea)}") # Too verbose, but useful for debugging
        return None

    try:
        cfunc = ida_hexrays.decompile(f)
        if not cfunc:
            err_msg = ida_hexrays.get_dcl_errstr()
            # print(f"Decompilation failed for {idc.get_func_name(ea)} ({hex(ea)}). Error: {err_msg}") # Too verbose
            return None
        return cfunc
    except Exception as e:
        print(f"Exception during decompilation of {idc.get_func_name(ea)} ({hex(ea)}): {e}")
        return None


def decompile_single_function(func_ea: int) -> Optional[str]:
    """
    Decompiles a single function at the given Effective Address (EA)
    and returns its pseudocode as a string.
    Returns None if decompilation fails.
    """
    # Ensure Hex-Rays is ready
    if not ida_hexrays.init_hexrays_plugin():
        return None

    cfunc = decompile_checked(func_ea)
    if not cfunc:
        return None  # Decompilation failed or function not found

    sv = cfunc.get_pseudocode()
    pseudocode_lines = []

    # Iterate through the lines and remove IDA's formatting tags
    for sl in sv:
        line = ida_lines.tag_remove(sl.line)
        pseudocode_lines.append(line)

    return "\n".join(pseudocode_lines).strip()




def decompile_and_extract_userland_functions(idb_path, function_eas_to_decompile: Set[int]) -> Dict[str, str]:
    """
    Takes a set of function EAs, decompiles them, and
    returns a dictionary mapping *formatted hexadecimal addresses* to their pseudocode.

    This function *only* performs decompilation for the EAs provided;
    it does not perform any filtering itself.
    """
    idapro.open_database(idb_path, False)
    decompiled_results: Dict[str, str] = {}
    print(f"{INFO_COLOR}Starting decompilation of specified userland functions...{COLOR_RESET}")

    for func_ea in function_eas_to_decompile:
        function_name = idc.get_func_name(func_ea)
        formatted_ea_key = f"0x{func_ea:X}"

        if not function_name:
            print(
                f"{WARNING_COLOR}WARNING: No name found for EA {hex(func_ea)}. Using '{formatted_ea_key}' as primary identifier.{COLOR_RESET}")
            display_name = formatted_ea_key
        else:
            display_name = function_name

        print(f"Processing function: {display_name} ({formatted_ea_key})")

        pseudocode = decompile_single_function(func_ea)

        if pseudocode:
            decompiled_results[formatted_ea_key] = pseudocode
        else:
            print(
                f"{WARNING_COLOR}Failed to decompile {display_name} ({formatted_ea_key}). See previous debug messages for details.{COLOR_RESET}")

    print(f"{INFO_COLOR}Finished. Decompiled {len(decompiled_results)} functions from the provided list.{COLOR_RESET}")
    idapro.close_database()
    return decompiled_results


def rename_and_comment_functions(llm_json_dict: dict, prefix: str, logger: logging.Logger):
    """
    Renames and comments functions based on the parsed LLM function analysis dictionary.
    Handles naming collisions by appending numbers.

    Args:
       llm_json_dict (dict): Parsed JSON dictionary from LLM analysis.
                     Keys are original function names (e.g., 'sub_...', 'main').
                     Values are dicts like {'DescriptiveName': '...', 'Description': '...'}.
       prefix (str): The prefix string chosen by the user (e.g., 'llm_').
       logger (logging.Logger): The logger instance.
    """
    if not llm_json_dict:
        logger.warning(f"No renaming data from LLM (empty dictionary). Skipping application.")
        print(f"{WARNING_COLOR}No renaming data from LLM (empty dictionary). Skipping application.{COLOR_RESET}")
        return False

    logger.info(f"Applying LLM renaming and comments from JSON with prefix '{prefix}'.")
    print(f"Applying LLM renaming and comments from JSON with prefix '{HIGHLIGHT_COLOR}{prefix}{COLOR_RESET}'.")

    applied_count = 0
    ignored_count = 0
    failed_set_name_count = 0

    MAX_RENAME_ATTEMPTS = 10

    for original_name, details in llm_json_dict.items():
        try:
            descriptive_name = details.get("DescriptiveName", "").strip()
            description = details.get("Description", "").strip()

            if not descriptive_name:
                logger.debug(f"LLM provided no 'DescriptiveName' for original name '{original_name}'. Skipping.")
                print(
                    f"{WARNING_COLOR}LLM provided no 'DescriptiveName' for original name '{original_name}'. Skipping.{COLOR_RESET}")
                ignored_count += 1
                continue

            safe_descriptive_name = descriptive_name.replace(" ", "_")
            safe_descriptive_name = re.sub(r'[^\w$@?~#]', '', safe_descriptive_name)

            if not safe_descriptive_name:
                logger.warning(
                    f"LLM provided 'DescriptiveName' '{descriptive_name}' for '{original_name}' which resulted in an empty or invalid safe name after cleanup. Skipping.")
                print(
                    f"{WARNING_COLOR}LLM provided 'DescriptiveName' '{descriptive_name}' for '{original_name}' which resulted in an empty or invalid safe name after cleanup. Skipping.{COLOR_RESET}")
                ignored_count += 1
                continue

            func_ea = idc.get_name_ea_simple(original_name)

            if func_ea == idc.BADADDR:
                logger.debug(
                    f"Original function name '{original_name}' from LLM response not found in IDA database. Skipping rename/comment.")
                print(
                    f"{WARNING_COLOR}Original function name '{original_name}' from LLM response not found in IDA database. Skipping rename/comment.{COLOR_RESET}")
                ignored_count += 1
                continue

            current_name_in_idb = idc.get_func_name(func_ea)

            base_target_name = f"{prefix}{safe_descriptive_name}"
            current_attempt_name = base_target_name
            attempt = 1
            naming_success = False

            while attempt <= MAX_RENAME_ATTEMPTS:
                existing_ea = idc.get_name_ea_simple(current_attempt_name)

                if existing_ea == idc.BADADDR:
                    final_new_name = current_attempt_name
                    naming_success = True
                    break
                elif existing_ea == func_ea:
                    logger.debug(
                        f"Function at EA {func_ea:x} ('{original_name}') is already named '{current_attempt_name}'. No rename needed.")
                    print(
                        f"{WARNING_COLOR}Function at EA {func_ea:x} ('{original_name}') is already named '{current_attempt_name}'. No rename needed.{COLOR_RESET}")
                    naming_success = True
                    break
                else:
                    logger.debug(
                        f"Desired name '{current_attempt_name}' for '{original_name}' (EA {func_ea:x}) already exists at EA {existing_ea:x}. Trying suffix _{attempt + 1}.")
                    print(
                        f"{WARNING_COLOR}Desired name '{current_attempt_name}' for '{original_name}' (EA {func_ea:x}) already exists at EA {existing_ea:x}. Trying suffix _{attempt + 1}.{COLOR_RESET}")
                    attempt += 1
                    current_attempt_name = f"{base_target_name}_{attempt}"

            if naming_success:
                if idc.set_name(func_ea, final_new_name, idc.SN_AUTO):
                    logger.info(f"Renamed - '{original_name} - (EA {func_ea:x}) to {final_new_name}.")
                    print(
                        f"Renamed - '{INFO_COLOR}{original_name} - (EA {func_ea:x}){COLOR_RESET} to {HIGHLIGHT_COLOR}{final_new_name}{COLOR_RESET}.")
                    applied_count += 1
                    if description:
                        try:
                            target_function_item = ida_funcs.get_func(func_ea)
                            if target_function_item:
                                if ida_funcs.set_func_cmt(target_function_item, description + "\n", 0):
                                    logger.info(f"Added comment to '{final_new_name}'.")
                                    print(f"Added comment to {INFO_COLOR}'{final_new_name}'{COLOR_RESET}.")
                                else:
                                    logger.warning(f"Failed to add comment to '{final_new_name}' (EA {func_ea:x}).")
                                    print(
                                        f"{WARNING_COLOR}Failed to add comment to '{final_new_name}' (EA {func_ea:x}).{COLOR_RESET}")
                            else:
                                logger.warning(
                                    f"Could not get function item for EA {func_ea:x} (name: '{final_new_name}') to add comment.")
                                print(
                                    f"{WARNING_COLOR}Could not get function item for EA {func_ea:x} (name: '{final_new_name}') to add comment.{COLOR_RESET}")
                        except Exception as comment_e:
                            logger.exception(
                                f"An error occurred while adding comment for '{final_new_name}' (EA {func_ea:x}):")
                            print(
                                f"{ERROR_COLOR}An error occurred while adding comment for '{final_new_name}' (EA {func_ea:x}):{COLOR_RESET}")
                else:
                    logger.error(
                        f"IDA's set_name API failed to rename '{original_name}' (EA {func_ea:x}) to '{final_new_name}'.")
                    print(
                        f"{ERROR_COLOR}IDA's set_name API failed to rename '{original_name}' (EA {func_ea:x}) to '{final_new_name}'.{COLOR_RESET}")
                    failed_set_name_count += 1
                    ignored_count += 1
            else:
                logger.error(
                    f"Naming process failed for '{original_name}' (EA {func_ea:x}) after {MAX_RENAME_ATTEMPTS} attempts for base name '{base_target_name}'. Skipping.")
                print(
                    f"{ERROR_COLOR}Naming process failed for '{original_name}' (EA {func_ea:x}) after {MAX_RENAME_ATTEMPTS} attempts for base name '{base_target_name}'. Skipping.{COLOR_RESET}")
                failed_set_name_count += 1
                ignored_count += 1

        except Exception as e:
            logger.exception(
                f"An unexpected error occurred while processing LLM suggestion for original name '{original_name}':")
            ignored_count += 1

    logger.info(f"Finished applying LLM suggestions. Attempted to process {len(llm_json_dict)} suggestions.")
    print(
        f"Finished applying LLM suggestions. Attempted to process {HIGHLIGHT_COLOR}{len(llm_json_dict)}{COLOR_RESET} suggestions.")

    logger.info(f"Successfully applied rename/comment: {applied_count}.")
    print(f"Successfully applied rename/comment: {HIGHLIGHT_COLOR}{applied_count}.{COLOR_RESET}")

    logger.info(
        f"Failed set_name calls: {failed_set_name_count} (May indicate persistent collisions or IDA naming issues).")
    print(
        f"Failed set_name calls: {HIGHLIGHT_COLOR}{failed_set_name_count}{COLOR_RESET} (May indicate persistent collisions or IDA naming issues).")

    logger.info(f"Ignored suggestions (not found/empty name/initial error): {ignored_count}.")
    print(f"Ignored suggestions (not found/empty name/initial error): {HIGHLIGHT_COLOR}{ignored_count}.{COLOR_RESET}")

    return True



def first_pass_renaming(sub_func_list, decompiled_buffer, idb_path,
                        ida_rename_prefix_selection, logger,
                        model_selection, prompt_selection,
                        llm_analyzer_instance: LLMAnalyzer):
    """
    Performs the first pass of renaming user-defined functions using the LLM.

    Args:
      sub_func_list (Iterable[str]): List or set of original user function names (e.g., 'sub_...').
      decompiled_buffer (str): The decompiled C code buffer from IDA.
      idb_path (str): Path to the IDA database (.i64).
      ida_rename_prefix_selection (str): The prefix string chosen by the user.
      logger (logging.Logger): The logger instance.
      model_selection (str): The user-selected Gemini model name.
      prompt_selection (str): The user-selected prompt template key.
      llm_analyzer_instance (LLMAnalyzer): The configured LLMAnalyzer instance.

    Returns:
      bool: True if the first pass was successful, False otherwise.
    """

    combined_prompt_data = (
        f"Original Function Names to analyze and rename:\n"
        f"{', '.join(sorted(list(sub_func_list)))}\n\n"
        f"Decompiled Code:\n{decompiled_buffer}"
    )

    logger.info(f"Calling LLM for first pass renaming...")
    print(f"{INFO_COLOR}Calling LLM for first pass renaming...{COLOR_RESET}")

    response_text = llm_analyzer_instance._generate_response(
        prompt_key=prompt_selection,
        documents=combined_prompt_data,
        specific_model=model_selection
    )

    if response_text:
        parsed_llm_response = None
        try:
            parsed_llm_response = json.loads(response_text)
            if not isinstance(parsed_llm_response, dict):
                logger.error(
                    f"LLM response parsed but is not a dictionary (Type: {type(parsed_llm_response)}). Cannot apply renaming.")
                print(
                    f"{ERROR_COLOR}LLM response parsed but is not a dictionary (Type: {type(parsed_llm_response)}). Cannot apply renaming.{COLOR_RESET}")
                if len(response_text) < 2000:
                    logger.error(f"{ERROR_COLOR}Problematic LLM response: {response_text}{COLOR_RESET}")
                    print(f"Problematic LLM response: {response_text}")
                return False

            logger.info(f"Opening database {idb_path}, adding first pass of JSON.")
            print(f"{INFO_COLOR}Opening database {idb_path}, adding first pass of JSON.{COLOR_RESET}")

            idapro.open_database(idb_path, False)
            rename_and_comment_functions(parsed_llm_response, ida_rename_prefix_selection, logger)
            idapro.close_database()
            logger.info(f"Closing database after first pass...")
            print(f"{INFO_COLOR}Closing database after first pass...{COLOR_RESET}")
            return True

        except json.JSONDecodeError as e:
            logger.error(f"JSON Decode Error during first pass processing: {e}. Raw response from LLM: {response_text}")
            print(
                f"{ERROR_COLOR}JSON Decode Error during first pass processing: {e}. Raw response from LLM: {response_text}{COLOR_RESET}")
            return False
        except Exception as e:
            logger.exception(f"An unexpected error occurred during first pass renaming application:")
            print(f"{ERROR_COLOR}An unexpected error occurred during first pass renaming application:{COLOR_RESET}")
            return False
    else:
        logger.error("No response received from the LLM during first pass renaming.")
        print(f"{ERROR_COLOR}No response received from the LLM during first pass renaming.{COLOR_RESET}")
        return False



def refine_sub_functions(idb_path, sub_functions: set[str], sha256_hash_value,
                         ida_rename_prefix_selection: str,
                         logger: logging.Logger, user_input: str,
                         model_selection: str, prompt_selection: str,
                         output_base_dir: str,
                         llm_analyzer_instance: LLMAnalyzer,
                         sub_functions_remaining: set[str],
                         extracted_functions_flag: bool):
    """Refines the names of "sub_" functions until they are all renamed or max iterations are reached."""
    max_iterations = 5
    initial_total_sub_functions = len(sub_functions)

    if not sub_functions:
        logger.info("No 'sub_' functions found to refine.")
        print("[+] - No 'sub_' functions found to refine.")
        return True

    proceed_with_analysis = questionary.confirm(
        f"[!] - Do you want to proceed with refining the IDB and processing '{len(sub_functions_remaining)}' sub_ functions?",
        default=True).ask()

    if not proceed_with_analysis:
        logger.info("Refinement skipped by user.")
        print("[+] - Refinement skipped by user. Proceeding to summarizing malware (if applicable).")
        return True

    try:
        max_iterations_input = questionary.text(
            f"[!] - Enter the maximum number of refinement iterations (default is {max_iterations}). Each iteration involves LLM calls:",
            default=str(max_iterations)
        ).ask()
        if max_iterations_input is None:
            logger.info("Max iterations selection cancelled by user. Aborting refinement.")
            print("[-] Refinement aborted by user.")
            return False
        max_iterations = int(max_iterations_input)
        if max_iterations <= 0:
            logger.warning("Max iterations must be a positive integer. Using default value of 5.")
            print(f"{WARNING_COLOR}Max iterations must be a positive integer. Using default value of 5.{COLOR_RESET}")
            max_iterations = 5
    except ValueError:
        logger.warning("Invalid input for max iterations. Using default value of 5.")
        print(f"{WARNING_COLOR}Invalid input for max iterations. Using default value of 5.{COLOR_RESET}")
        max_iterations = 5
    except Exception as e:
        logger.error(f"Error getting max iterations: {e}. Using default 5.")
        print(f"{ERROR_COLOR}Error getting max iterations: {e}. Using default 5.{COLOR_RESET}")
        max_iterations = 5

    current_iteration = 0
    current_sub_functions_in_idb = sub_functions_remaining  # This is the set of 'sub_' functions entering the loop

    while current_iteration < max_iterations and len(current_sub_functions_in_idb) > 0:
        current_renamed_count = initial_total_sub_functions - len(current_sub_functions_in_idb)
        percentage_renamed = (
                                         current_renamed_count / initial_total_sub_functions) * 100 if initial_total_sub_functions > 0 else 0

        logger.info(f"\n Refinement Iteration {current_iteration + 1}/{max_iterations} ")
        print(f"\n Refinement Iteration {HIGHLIGHT_COLOR}{current_iteration + 1}/{max_iterations}{COLOR_RESET} ")

        logger.info(f"[+] - Percentage of original 'sub_' functions renamed so far: {percentage_renamed:.2f}%")
        print(
            f"[+] - Percentage of original 'sub_' functions renamed so far: {HIGHLIGHT_COLOR}{percentage_renamed:.2f}%{COLOR_RESET}")

        logger.info(
            f"[+] - Remaining 'sub_' functions to attempt renaming in this pass: {len(current_sub_functions_in_idb)}")
        print(
            f"[+] - Remaining 'sub_' functions to attempt renaming in this pass: {HIGHLIGHT_COLOR}{len(current_sub_functions_in_idb)}{COLOR_RESET}")

        logger.info(f"Percentage renamed: {percentage_renamed:.2f}%, Remaining: {len(current_sub_functions_in_idb)}")
        print(
            f"{INFO_COLOR}Percentage renamed: {percentage_renamed:.2f}%, Remaining: {len(current_sub_functions_in_idb)}{COLOR_RESET}")

        # -- Generate new C code based on current IDB state --
        logger.info(f"Running IDA in headless mode to regenerate C file for Iteration {current_iteration + 1}...")
        print(
            f"{INFO_COLOR}Running IDA in headless mode to regenerate C file for Iteration {current_iteration + 1}...{COLOR_RESET}")

        buffer_after_rename = run_ida_read_file(user_input, logger,
                                                sha256_hash_value,
                                                output_base_dir)

        if not buffer_after_rename:
            logger.error(
                f"Failed to get updated code buffer during refinement iteration {current_iteration + 1} after running IDA. Aborting refinement.")
            print(
                f"{ERROR_COLOR}[-] Error: Could not get the updated C file after running IDA for refinement iteration {current_iteration + 1}.{COLOR_RESET}")
            return False










        current_sub_functions_to_process = enumerate_functions(idb_path, "name")




        current_sub_functions_in_idb_filtered = {
            name for name in current_sub_functions_to_process
            if name.startswith('sub_') or name.lower().startswith('main') or '::' in name

        }



        remaining_function_names = sorted(list(current_sub_functions_in_idb_filtered))

        if not remaining_function_names:
            logger.info(
                f"No more 'sub_' functions remaining for processing in iteration {current_iteration + 1}. All relevant functions seem to be renamed. Terminating refinement.")
            print(
                f"{INFO_COLOR}No more 'sub_' functions remaining for processing in iteration {current_iteration + 1}. All relevant functions seem to be renamed. Terminating refinement.{COLOR_RESET}")
            return True


        combined_prompt_data = (
            f"Decompiled Code (after previous renames):\n{buffer_after_rename}\n\n"
            f"The following functions still have generic names and require renaming. "
            f"Please focus your analysis on these functions and provide refined "
            f"DescriptiveNames and Descriptions for them in the JSON format. "
            f"Prioritize renaming 'sub_' functions and any 'main'-like functions:\n"
            f"Functions to focus on: {', '.join(remaining_function_names)}\n"
        )


        logger.info(f"Calling LLM for refinement iteration {current_iteration + 1}...")
        print(f"{INFO_COLOR}Calling LLM for refinement iteration {current_iteration + 1}...{COLOR_RESET}")

        response_text_refine = llm_analyzer_instance._generate_response(
            prompt_key=prompt_selection,
            documents=combined_prompt_data,
            specific_model=model_selection
        )
        logger.info(f"LLM Refine Response Raw (Iteration {current_iteration + 1}):\n{response_text_refine}")
        print(
            f"{INFO_COLOR}LLM Refine Response Raw (Iteration {current_iteration + 1}):\n{response_text_refine}{COLOR_RESET}")

        if response_text_refine:
            parsed_response_data = None
            try:
                parsed_response_data = json.loads(response_text_refine)
                if not isinstance(parsed_response_data, dict):
                    logger.error(
                        f"Parsed response is not a dictionary (Type: {type(parsed_response_data)}) in iteration {current_iteration + 1}. Skipping update. Problematic parsed data: {parsed_response_data}")
                    print(
                        f"{ERROR_COLOR}Parsed response is not a dictionary (Type: {type(parsed_response_data)}) in iteration {current_iteration + 1}. Skipping update. Problematic parsed data: {parsed_response_data}{COLOR_RESET}")
                    current_iteration += 1
                    continue

                logger.info(f"Opening database {idb_path} for updates (Iteration {current_iteration + 1}).")
                print(
                    f"{INFO_COLOR}Opening database {idb_path} for updates (Iteration {current_iteration + 1}).{COLOR_RESET}")

                idapro.open_database(idb_path, False)
                apply_success = rename_and_comment_functions(parsed_response_data, ida_rename_prefix_selection, logger)
                idapro.close_database()
                logger.info(f"Closed database {idb_path} after updates (Iteration {current_iteration + 1}).")
                print(
                    f"{INFO_COLOR}Closed database {idb_path} after updates (Iteration {current_iteration + 1}).{COLOR_RESET}")

                if apply_success:
                    # Re-scrape the C file *after* applying changes to get the most current state
                    buffer_after_apply = run_ida_read_file(user_input, logger,
                                                           sha256_hash_value,
                                                           output_base_dir)
                    if buffer_after_apply:
                        # Update the set of remaining 'sub_' functions based on the *new* IDA DB state
                        # This should reflect if renames actually stuck in IDA
                        current_sub_functions_in_idb_new = enumerate_functions(idb_path, "name")

                        # Filter for actual 'sub_' or 'main'-like patterns (as defined in enumerate_functions)
                        current_sub_functions_in_idb_new_filtered = {
                            name for name in current_sub_functions_in_idb_new
                            if name.startswith('sub_') or name.lower().startswith('main') or '::' in name
                        }

                        successfully_renamed_in_this_pass = current_sub_functions_in_idb - current_sub_functions_in_idb_new_filtered
                        current_sub_functions_in_idb = current_sub_functions_in_idb_new_filtered  # Update the set for the next iteration

                        if successfully_renamed_in_this_pass:
                            logger.info(
                                f"Successfully renamed away from 'sub_' in iteration {current_iteration + 1}: {successfully_renamed_in_this_pass}. {len(current_sub_functions_in_idb)} 'sub_' functions remaining.")
                            print(
                                f"{INFO_COLOR}Successfully renamed away from 'sub_' in iteration {current_iteration + 1}: {successfully_renamed_in_this_pass}. {len(current_sub_functions_in_idb)} 'sub_' functions remaining.{COLOR_RESET}")
                        else:
                            logger.info(
                                f"No functions successfully renamed away from 'sub_' in iteration {current_iteration + 1}.")
                            print(
                                f"{WARNING_COLOR}No functions successfully renamed away from 'sub_' in iteration {current_iteration + 1}.{COLOR_RESET}")
                            if len(current_sub_functions_in_idb) > 0:
                                logger.warning(
                                    f"Refinement stagnant: {len(current_sub_functions_in_idb)} 'sub_' functions remaining, but none were renamed successfully in this iteration.")
                                print(
                                    f"{WARNING_COLOR}Refinement stagnant: {len(current_sub_functions_in_idb)} 'sub_' functions remaining, but none were renamed successfully in this iteration.{COLOR_RESET}")
                    else:
                        logger.error(
                            f"Failed to get updated code buffer after applying renames in iteration {current_iteration + 1}. Cannot accurately track remaining 'sub_' functions.")
                        print(
                            f"{ERROR_COLOR}Failed to get updated code buffer after applying renames in iteration {current_iteration + 1}. Cannot accurately track remaining 'sub_' functions.{COLOR_RESET}")
                        return False  # Cannot determine remaining sub_ functions, best to stop refinement.
                else:
                    logger.error(
                        f"Applying LLM suggestions failed in refinement iteration {current_iteration + 1}. Aborting refinement.")
                    print(
                        f"{ERROR_COLOR}Applying LLM suggestions failed in refinement iteration {current_iteration + 1}. Aborting refinement.{COLOR_RESET}")
                    return False
            except json.JSONDecodeError as e:
                logger.error(
                    f"JSON Decode Error during refinement processing (Iteration {current_iteration + 1}): {e}. Problematic response text: {response_text_refine}")
                print(
                    f"{ERROR_COLOR}[-] Warning: Failed to parse LLM response in iteration {current_iteration + 1}. Skipping.{COLOR_RESET}")
            except Exception as e:
                logger.exception(f"Unexpected Error during refinement processing (Iteration {current_iteration + 1}):")
                print(
                    f"{ERROR_COLOR}[-] An unexpected error occurred during refinement iteration {current_iteration + 1}. See log for details.{COLOR_RESET}")
                return False
        else:
            logger.warning(f"No LLM response received in refinement (Iteration {current_iteration + 1}).")
            print(
                f"{WARNING_COLOR}[*] Warning: No response from LLM for iteration {current_iteration + 1}.{COLOR_RESET}")

        current_iteration += 1

        if len(current_sub_functions_in_idb) == 0:
            logger.info("All identified 'sub_' functions have been processed during refinement.")
            print("[+] All identified 'sub_' functions processed during refinement.")
            break

        if current_iteration < max_iterations:
            current_renamed_count_disp = initial_total_sub_functions - len(current_sub_functions_in_idb)
            percentage_renamed_next_disp = (
                                                       current_renamed_count_disp / initial_total_sub_functions) * 100 if initial_total_sub_functions > 0 else 0

            continue_refinement = questionary.confirm(
                f"[!] - Continue to refinement iteration {current_iteration + 1}/{max_iterations}? ({percentage_renamed_next_disp:.2f}% renamed, {len(current_sub_functions_in_idb)} remaining)",
                default=True
            ).ask()
            if not continue_refinement:
                logger.info(f"Refinement stopped by user before iteration {current_iteration + 1}.")
                print("[+] Refinement stopped by user.")
                break

    final_renamed_count = initial_total_sub_functions - len(current_sub_functions_in_idb)
    final_percentage_renamed = (
                                           final_renamed_count / initial_total_sub_functions) * 100 if initial_total_sub_functions > 0 else 0

    if current_iteration >= max_iterations:
        logger.warning(f"{WARNING_COLOR}Reached maximum refinement iterations ({max_iterations}).{COLOR_RESET}")
        print(f"{WARNING_COLOR}[!] Reached maximum refinement iterations ({max_iterations}).{COLOR_RESET}")
    elif len(current_sub_functions_in_idb) == 0:
        logger.info("Successfully processed all identified 'sub_' functions.")
    else:
        logger.info("Refinement loop finished (likely stopped by user or due to stagnation).")
        print("Refinement loop finished (likely stopped by user or due to stagnation).")

    logger.info(
        f"Refinement finished. Final percentage of original 'sub_' functions renamed: {final_percentage_renamed:.2f}%. {len(current_sub_functions_in_idb)} remaining unprocessed (still named 'sub_...').")
    print(
        f"[+] Refinement finished. Final percentage: {HIGHLIGHT_COLOR}{final_percentage_renamed:.2f}%{COLOR_RESET}. {HIGHLIGHT_COLOR}{len(current_sub_functions_in_idb)}{COLOR_RESET} remaining unprocessed.")

    return True
