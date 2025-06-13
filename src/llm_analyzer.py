import json
import logging
import re
import time
# IMPORTANT: Corrected imports here from config to reflect the separated prompt templates
from config import (
    GENERATION_CONFIG, SAFETY_SETTINGS, BINARY_PROMPT_TEMPLATES, SUMMARY_PROMPT_TEMPLATES,
    SYSTEM_INSTRUCTION_RENAME, USER_MODELS, VERTEX_AI_INITIALIZED,
    SYSTEM_INSTRUCTION_SUMMARY_PERSONAS # Keep this for retrieving the system instruction string
)
from vertexai.generative_models import GenerativeModel, Part
import google.generativeai as genai
import questionary
from utils import extract_json_from_llm_response
from typing import Any

from colors import *

COLOR_RESET = "\033[0m"

logger = logging.getLogger(__name__)

class LLMAnalyzer:

    def __init__(self, model_name: str = list(USER_MODELS.keys())[0], prompt_selection: str = list(BINARY_PROMPT_TEMPLATES.keys())[0], logger: logging.Logger = logger):
        """
        Initializes the LLMAnalyzer.
        Args:
            model_name: The default LLM model name to use for requests.
            prompt_selection: The default prompt key for binary analysis/renaming.
            logger: A logger instance.
        """
        self.logger = logger
        self.model_name = model_name
        self.prompt_selection = prompt_selection

        if not VERTEX_AI_INITIALIZED:
            self.logger.error("Vertex AI not initialized. LLMAnalyzer cannot be used.")
            print(f"{WARNING_COLOR}[-] Warning: Vertex AI not initialized. LLM features will likely fail.{COLOR_RESET}")

        self.base_model = None
        if VERTEX_AI_INITIALIZED:
            try:
                # Initialize with the RENAME system instruction by default
                self.base_model = GenerativeModel(self.model_name,
                                                system_instruction=SYSTEM_INSTRUCTION_RENAME)
            except Exception as e:
                self.logger.error(f"Failed to initialize LLM model '{model_name}': {e}")
                print(f"{ERROR_COLOR}[-] Error: Failed to initialize LLM model '{model_name}'. Check model name or config.{COLOR_RESET}")

    def _generate_response(self, prompt_key: str, documents: str, stream: bool = True, specific_model: str = None, system_instruction_content: str = None) -> str | None:
        """
        Internal method to generate a response from the LLM, with consistent streaming.

        Args:
            prompt_key (str): Key for the desired prompt template (e.g., "Windows (PE)", "Summary - SOC Analyst / Incident Responder").
            documents (str): The content to send to the LLM (e.g., decompiled code).
            stream (bool): Whether to stream the response. Defaults to True.
            specific_model (str, optional): Overrides the default model for this call.
            system_instruction_content (str, optional): The explicit system instruction string to use for this call.
                                                        This is crucial for persona-based summaries.

        Returns:
            str | None: The LLM's response text (e.g., JSON string, summary text), or None on failure.
        """
        if not VERTEX_AI_INITIALIZED:
            self.logger.error("Vertex AI not initialized. Cannot generate response.")
            print(f"{ERROR_COLOR}Vertex AI not initialized. Cannot generate response.{COLOR_RESET}")
            return None

        if not documents:
            self.logger.warning("_generate_response called with empty documents. Returning None.")
            print(f"{ERROR_COLOR}_generate_response called with empty documents. Returning None.{COLOR_RESET}")
            return None

        current_model_name = specific_model if specific_model else self.model_name

        # Determine if it's a summary prompt based on the prompt_key's presence in SUMMARY_PROMPT_TEMPLATES
        is_summary_prompt = prompt_key in SUMMARY_PROMPT_TEMPLATES

        # Get the prompt text from the correct dictionary
        prompt_text = None
        if is_summary_prompt:
            prompt_text = SUMMARY_PROMPT_TEMPLATES.get(prompt_key)
        else:
            prompt_text = BINARY_PROMPT_TEMPLATES.get(prompt_key)

        if not prompt_text:
            self.logger.error(f"Prompt template '{prompt_key}' not found in either binary or summary templates. Cannot generate response.")
            print(f"Prompt template '{ERROR_COLOR}{prompt_key}{COLOR_RESET}' not found. Cannot generate response.")
            return None

        # Use the provided system_instruction_content if available, otherwise default to RENAME for non-summary calls
        current_system_instruction = system_instruction_content if system_instruction_content is not None else SYSTEM_INSTRUCTION_RENAME

        self.logger.debug(f"Calling LLM with model: '{current_model_name}', prompt_key: '{prompt_key}', system_instruction_len: {len(current_system_instruction) if current_system_instruction else 'None'}, stream: {stream}")
        print(f"Calling LLM with model: '{HIGHLIGHT_COLOR}{current_model_name}{COLOR_RESET}', prompt key: '{HIGHLIGHT_COLOR}{prompt_key}{COLOR_RESET}'")


        try:
            model = GenerativeModel(current_model_name,
                                    system_instruction=current_system_instruction)

            prompt_part = Part.from_text(prompt_text)
            document_part = Part.from_data(mime_type="text/plain", data=documents.encode('utf-8'))
            content_parts_list = [prompt_part, document_part]

            responses = model.generate_content(
                content_parts_list,
                generation_config=GENERATION_CONFIG,
                safety_settings=SAFETY_SETTINGS,
                stream=stream,
            )

            response_text = ""

            if stream and not is_summary_prompt:
                self.logger.info(f"\n---LLM ({current_model_name}) Response Streaming from Vertex AI:---")
                print(f"{INFO_COLOR}\n---LLM ({current_model_name}) Response Streaming from Vertex AI:---{COLOR_RESET}")

            for chunk in responses:
                if chunk.candidates and chunk.candidates[0].finish_reason == 'SAFETY':
                    self.logger.warning(f"LLM response potentially blocked due to safety reasons: {chunk.candidates[0].safety_ratings}.")
                    if not is_summary_prompt:
                        print(f"{WARNING_COLOR}LLM response potentially blocked due to safety reasons: {chunk.candidates[0].safety_ratings}.{COLOR_RESET}")
                        self.logger.warning(f"\n[!] Warning: LLM response blocked due to safety policy.")
                        print(f"{WARNING_COLOR}\n[!] Warning: LLM response blocked due to safety policy.{COLOR_RESET}")
                    return None

                if hasattr(chunk, 'text') and chunk.text:
                    if stream and not is_summary_prompt:
                        self.logger.info(f"{chunk.text}")
                        print(f"{STREAM_COLOR}{chunk.text}{COLOR_RESET}", end="", flush=True)
                    response_text += chunk.text
                elif not hasattr(chunk, 'text'):
                    self.logger.debug(f"Chunk has no 'text' attribute (e.g., just metadata): {chunk}")
                    print(f"{WARNING_COLOR}Chunk has no 'text' attribute (e.g., just metadata): {chunk}{COLOR_RESET}")
                elif not chunk.text:
                    self.logger.debug(f"Chunk has empty 'text' attribute: {chunk}")
                    print(f"{WARNING_COLOR}Chunk has empty 'text' attribute: {chunk}{COLOR_RESET}")

            if stream and not is_summary_prompt:
                self.logger.info(f"\n--- End LLM Response ---")
                print(f"{INFO_COLOR}\n--- End LLM Response ---{COLOR_RESET}")

            if not response_text.strip():
                self.logger.warning("Received empty response text from Vertex AI.")
                print(f"{WARNING_COLOR}Received empty response text from Vertex AI.{COLOR_RESET}")
                return None

            if not is_summary_prompt:
                self.logger.info("Attempting to parse LLM response for JSON.")
                print("Attempting to parse LLM response for JSON.")
                parsed_json = extract_json_from_llm_response(response_text)

                if parsed_json is None:
                    self.logger.warning("extract_json_from_llm_response failed, attempting direct json.loads as fallback.")
                    print(f"{WARNING_COLOR}extract_json_from_llm_response failed, attempting direct json.loads as fallback.{COLOR_RESET}")

                    try:
                        parsed_json = json.loads(response_text)
                        self.logger.info("Successfully parsed direct JSON text as fallback.")
                        print(f"{INFO_COLOR}Successfully parsed direct JSON text as fallback.{COLOR_RESET}")

                    except json.JSONDecodeError as json_e:
                        self.logger.error(f"Failed to parse direct JSON text as fallback: {json_e}")
                        print(f"{ERROR_COLOR}Failed to parse direct JSON text as fallback: {json_e}{COLOR_RESET}")

                        if len(response_text) < 2000:
                            self.logger.error(f"Raw response leading to JSON error: {response_text}")
                            print(f"{ERROR_COLOR}Raw response leading to JSON error: {response_text}{COLOR_RESET}")
                        else:
                            self.logger.error("Raw response leading to JSON error is too long to log.")
                            print(f"{ERROR_COLOR}Raw response leading to JSON error is too long to log.{COLOR_RESET}")
                        return None

                if not isinstance(parsed_json, dict):
                    self.logger.error(f"Extracted JSON is not a dictionary (Type: {type(parsed_json)}).")
                    print(f"{ERROR_COLOR}Extracted JSON is not a dictionary (Type: {type(parsed_json)}).{COLOR_RESET}")

                    if len(response_text) < 2000:
                        self.logger.error(f"Raw response: {response_text}")
                        print(f"{ERROR_COLOR}Raw response: {response_text}{COLOR_RESET}")
                    else:
                        self.logger.error(f"Raw response too long to log.")
                        print(f"{ERROR_COLOR}Raw response too long to log.{COLOR_RESET}")
                    return None

                return json.dumps(parsed_json)
            else:
                return response_text

        except Exception as e:
            self.logger.exception(f"Error during LLM response generation:")
            print(f"{ERROR_COLOR}[-] Error generating LLM response: {e}{COLOR_RESET}")
            return None

    def analyze_functions(self, decompiled_buffer: str) -> dict | None:
        """
        Analyzes decompiled code using the LLM and returns a dictionary
        mapping original names (as found in the text) to new names/descriptions.
        It uses the model and prompt type set during LLMAnalyzer initialization.
        """
        if not VERTEX_AI_INITIALIZED:
            self.logger.warning("Skipping function analysis due to LLM initialization failure.")
            print(f"{WARNING_COLOR}[-] Skipping function analysis due to LLM issues.{COLOR_RESET}")
            return None

        if not decompiled_buffer:
            self.logger.warning("No decompiled buffer provided for function analysis.")
            print(f"{WARNING_COLOR}No decompiled buffer provided for function analysis.{COLOR_RESET}")
            return None

        analysis_prompt_key = self.prompt_selection


        if analysis_prompt_key not in BINARY_PROMPT_TEMPLATES:
            self.logger.error(f"Invalid prompt selection '{analysis_prompt_key}' for function analysis. Please choose a binary-specific prompt.")
            print(f"{ERROR_COLOR}Invalid prompt selection '{analysis_prompt_key}' for function analysis. Cannot proceed.{COLOR_RESET}")
            return None

        self.logger.info(f"Calling LLM for function analysis (Prompt Type: {analysis_prompt_key})...")
        print(f"Calling LLM for function analysis (Prompt Type: {HIGHLIGHT_COLOR}{analysis_prompt_key})...{COLOR_RESET}")


        raw_response_json_string = self._generate_response(
            prompt_key=analysis_prompt_key,
            documents=decompiled_buffer,
            specific_model=self.model_name,
            stream=True,
            system_instruction_content=SYSTEM_INSTRUCTION_RENAME
        )

        if raw_response_json_string:
            self.logger.info("Successfully received and parsed JSON response from LLM for function analysis.")
            print("Successfully received and parsed JSON response from LLM for function analysis.")

            try:
                parsed_json = json.loads(raw_response_json_string)
                return parsed_json
            except json.JSONDecodeError as e:
                self.logger.error(f"Internal JSON decode error after _generate_response succeeded: {e}. Raw string: {raw_response_json_string}")
                print(f"{ERROR_COLOR}Internal JSON decode error after _generate_response succeeded: {e}. Raw string: {raw_response_json_string}{COLOR_RESET}")
                return None
        else:
            self.logger.error("No raw JSON string received from LLM for function analysis or an error occurred.")
            print(f"{ERROR_COLOR}No raw JSON string received from LLM for function analysis or an error occurred.{COLOR_RESET}")
            return None

    def summarize_malware_report(self, decompiled_buffer: str, system_persona_key: str, summary_prompt_key: str = "Summary - General Purpose") -> str | None:
        """
        Generates a summary report of the malware based on the decompiled code.
        Uses the specified system_persona_key and summary_prompt_key.

        Args:
            decompiled_buffer: The decompiled code for analysis.
            system_persona_key: The key for the desired system instruction persona (e.g., "SOC Analyst").
            summary_prompt_key: The key for the specific summary prompt template (e.g., "Summary - SOC Analyst / Incident Responder").
        """
        if not VERTEX_AI_INITIALIZED:
            self.logger.warning("Skipping summary generation due to LLM initialization failure.")
            print(f"{WARNING_COLOR}Skipping summary generation due to LLM initialization failure.{COLOR_RESET}")
            return None

        if not decompiled_buffer:
            self.logger.warning("No decompiled buffer provided for summarization.")
            print(f"{WARNING_COLOR}No decompiled buffer provided for summarization.{COLOR_RESET}")
            return None


        actual_system_instruction_content = SYSTEM_INSTRUCTION_SUMMARY_PERSONAS.get(system_persona_key)
        if not actual_system_instruction_content:
            self.logger.error(f"System instruction persona '{system_persona_key}' not found. Cannot generate summary.")
            print(f"{ERROR_COLOR}System instruction persona '{system_persona_key}' not found. Cannot generate summary.{COLOR_RESET}")
            return None


        if summary_prompt_key not in SUMMARY_PROMPT_TEMPLATES:
            self.logger.error(f"Summary prompt key '{summary_prompt_key}' not found in SUMMARY_PROMPT_TEMPLATES. Cannot generate summary.")
            print(f"{ERROR_COLOR}Summary prompt key '{summary_prompt_key}' not found. Cannot generate summary.{COLOR_RESET}")
            return None

        self.logger.info("Calling LLM for malware summary...")
        print("Calling LLM for malware summary...")


        summary_text = self._generate_response(
            prompt_key=summary_prompt_key,
            documents=decompiled_buffer,
            stream=True,
            specific_model=self.model_name,
            system_instruction_content=actual_system_instruction_content
        )

        if summary_text:
            self.logger.info("Malware summary response received.")
            print("Malware summary response received.")
            return summary_text
        else:
            self.logger.error("No response or an error occurred while generating LLM malware summary.")
            print(f"{ERROR_COLOR}No response or an error occurred while generating LLM malware summary.{COLOR_RESET}")
            return None

    def count_tokens(self, text: str) -> int:
        """Counts tokens using the currently selected analysis model."""
        if not VERTEX_AI_INITIALIZED or not text:
            return 0
        try:
            model_to_count_with = self.model_name if self.base_model else list(
                USER_MODELS.keys())[0]
            model = genai.GenerativeModel(model_to_count_with)
            token_count = model.count_tokens(text).total_tokens
            return token_count
        except Exception as e:
            self.logger.error(f"Error counting tokens for model '{self.model_name}': {e}")
            print(f"{ERROR_COLOR}[-] Warning: Could not count tokens for model '{self.model_name}'.{COLOR_RESET}")
            return 0