# r.n.Bin:  Binary Analysis & Annotation Tool

## Overview

<p align="center">
  <img src="https://img.shields.io/badge/Powered%20by-Google%20Vertex%20AI-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white" alt="Powered by Google Cloud Vertex AI"/>
  <img src="https://img.shields.io/badge/Language-Python%203.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"/>
  <img src="https://img.shields.io/badge/IDA%20Pro-Required-ff69b4?style=for-the-badge&logo=ida&logoColor=white" alt="IDA Pro Required"/>
  <img src="https://img.shields.io/badge/Licence-MIT-green?style=for-the-badge" alt="License: MIT"/>
</p>

`r.n.Bin` is an IDA Pro Python script designed to assist reverse engineers, malware analysts, and threat hunters in annotating and understanding complex binary code. It leverages Google's Vertex AI (Gemini models) to rename and comment functions within IDA Pro databases, streamlining the analysis process.

By providing a range of binary-specific analysis templates (prompts) and an iterative refinement process, `r.n.Bin` automates the time-consuming task of deciphering obfuscated or compiler-generated function names, allowing analysts to quickly grasp the core functionality and potential impact of compiled software, especially in malware reverse engineering.

### Disclaimers: The tool should be run inside a safe Virtual Machine.

## Features

-   **AI-Powered Function Renaming & Commenting**: Integrates with Google Vertex AI's Gemini models to analyze decompiled C code from IDA Pro and suggest highly descriptive function names and comments.
-   **Binary-Specific Prompts**: Offers tailored analysis prompts for various binary types, ensuring highly accurate and context-aware renaming:
    -   Windows Portable Executables (PE)
    -   ELF (Linux/Unix Executable and Linkable Format)
    -   Go (Golang) Binaries
    -   Rust Binaries
    -   Nim Binaries
    -   Objective-C (Mach-O) Binaries
    -   Swift (Mach-O) Binaries
-   **Iterative Refinement**: Implements a multi-pass process to continuously refine function names and comments, improving accuracy as more context is gathered from the IDB.
-   **IDA Pro Orchestration**:
    -   Automatically runs IDA Pro in batch mode to generate initial decompiled C code if an existing `.c` file or IDB is not found.
    -   Directly applies renaming and commenting changes to the active IDA Pro database (IDB) using IDA's Python API.
-   **Comprehensive Malware Summary**: Generates a high-level summary report of the malware's characteristics, capabilities, and potential impact based on the full decompiled code.
-   **Decompiled Code Pre-processing**: Includes optional function boundary extraction to reduce LLM token usage for large binaries.
-   **Session Persistence**: Detects and utilizes existing IDA Pro databases (`.i64` files) and previously generated `.c` files to resume analysis, saving time.
-   **Token & Cost Estimation**: Provides approximate token usage to help manage Vertex AI costs.
-   **Detailed Logging**: Generates a comprehensive log file for auditing and troubleshooting analysis steps.

## Requirements

### Software
-   **Python 3.10+**: The scripting language.
-   **IDA Pro 9.1+**: A full license with the **Hex-Rays Decompiler** is mandatory.
    -   Ensure IDA Pro's Python environment is correctly set up.
    -   Ensure the installation folder for IDA must is in your system's PATH environment variable.
-   **IDALIB**: Should have IDALIB for Python installed.
    - Navigate to the idalib/python folder within the IDA Pro installation directory
    - Run the command: pip install .
-   **py-activate-idalib.py**: Execute this script that is bundled in the IDALIB folder.
-   **PATH Variable**: Make sure IDA directory is in your environment variables PATH.

### Google Cloud Configuration
1.  **Enable Vertex AI API**: Ensure the Vertex AI API is enabled in your Google Cloud Project.
    -   Go to [Google Cloud Console](https://console.cloud.google.com/).
    -   Navigate to `APIs & Services` > `Enabled APIs & Services`.
    -   Search for "Vertex AI API" and enable it.
2.  **Authentication**: `r.n.Bin` uses Application Default Credentials (ADC) to authenticate with Vertex AI.
    -   **Recommended for Local Development**: Use the `gcloud CLI`.
        ```bash
        gcloud auth application-default login
        ```
        This command will open a browser window for you to log in with your Google account.
    -   **For Production/CI/CD**: Use a Service Account key file. Set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of your service account JSON key file.
        ```bash
        export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/keyfile.json"
        ```
3.  **Project ID and Region**: Update the `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` variables in `.env` to match your Google Cloud Project ID and preferred Vertex AI region.


## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://gitlab.com/your-username/r.n.Bin.git
    cd r.n.Bin
    ```

2.  **Create a Virtual Environment (Recommended for development/linting)**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Python Dependencies**:
    Create a `requirements.txt` file (if not already present) with the following:

    ```text
    # requirements.txt
    vertexai==1.71.1
    google-generativeai==0.8.4
    pyfiglet==1.0.2
    questionary==2.1.0
    uvicorn
    python-dotenv
    pydantic
    ```
    Then, install:
    ```bash
    pip install -r requirements.txt
    ```

    Install IDALIB for IDA API:
    - Navigate to the idalib/python folder within the IDA Pro installation directory
    - In your Python interperter you plan on using run the command: pip install .


## Usage

1.  **Navigate to the `r.n.Bin` folder**:

2. **Run Main.py**
    -   Navigate to where you copied r.n.Bin `src`.
    -   Run "python main.py"

3.  **Follow the Interactive Prompts**:
    The script will guide you through the process:

    -   **Enter the path to the binary file**: Provide the full path to the binary. This is used for generating the `.c` file and for logging purposes.
    -   `r.n.Bin` will first check if an existing IDA Pro database (`.i64` file) and a corresponding decompiled `.c` file exist for the binary. If not, it will automatically run IDA Pro to create them.
    -   **Initial `sub_` Function Count**: The script will display the number of `sub_` functions (or similar compiler-generated names) found in the decompiled code.
    -   **Proceed with Gemini processing?**: Confirm to proceed with LLM analysis.
    -   **Extract function boundaries?**: For binaries with input token size to large you'll be asked if you want to extract just the function bodies. This can significantly reduce token costs for large binaries.
    -   **Choose a Gemini Model**: Select the Vertex AI Gemini model for analysis (e.g., `gemini-1.5-pro-002`). Different models have varying capabilities and costs.
    -   **Choose a prompt based on the binaries features**: Select the specific binary type (e.g., `Windows (PE)`, `ELF`, `GOlang`) based on the target binary's architecture and language. This is crucial for targeted analysis.
    -   **Choose a prefix for the functions**: Provide a prefix (e.g., `llm_`) that will be prepended to the new LLM-generated function names in IDA Pro.
    -   **Iterative Refinement**: The script will then enter a loop, iteratively calling the LLM to rename and comment functions. After each pass, it will ask:
        -   **Continue to refinement iteration?**: You can choose to continue or stop the refinement process. This is useful for budget control or if you're satisfied with the current renaming.

Upon completion, `r.n.Bin` will apply the suggested renamings and comments directly into your open IDA Pro database, and a final summary report will be logged.

## Configuration

The `config.py`, `prompts.json`, `.env` file allows customization of parameters and analysis settings:

-   `vertexai.init`: **Crucially, update `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`  to match your Google Cloud setup.
-   `GENERATION_CONFIG`: Adjusts LLM generation parameters like `max_output_tokens`, `temperature`, and `top_p`.
-   `SAFETY_SETTINGS`: Controls content safety filters for LLM responses. `r.n.Bin` defaults to `BLOCK_NONE` for harmful content categories to ensure comprehensive malware analysis (though you might adjust this for stricter environments).
-   `USER_MODELS`: Defines the available Gemini models that can be selected.
-   `SYSTEM_INSTRUCTIONS.RENAME_FUNCTIONS`: A general system instruction for the LLM when providing renaming suggestions.
-   `SYSTEM_INSTRUCTIONS.SUMMARY_PERSONAS`: Contains system instruction personas for different operational roles.
-   `SUMMARY_PROMPT_TEMPLATES`: Contains the detail prompt instruction for different operational roles.
-   `BINARY_PROMPT_TEMPLATES`: Contains the detailed system instructions for each binary-specific analysis prompt (PE, ELF, Go, etc.). This is where the core intelligence for binary-specific renaming is defined. **Review and customize these prompts to fine-tune `r.n.Bin`'s renaming logic.**

## Output

`r.n.Bin` generates several outputs:

-   **Modified IDA Pro Database**: The primary output. Function names and comments within your opened `.idb`/`.i64` file are updated directly by `r.n.Bin`.
-   `<SHA256_HASH>_ida_analysis.log`: A main log file recording all steps, LLM interactions, errors, and the final malware summary report. Stored in the same directory as the analyzed binary.
-   `<SHA256_HASH>.c`: The decompiled C code generated by IDA Pro. This file is used by `r.n.Bin` as input for the LLM. Stored in the same directory as the analyzed binary.
-   `<SHA256_HASH>_extracted_functions.txt`: If the "extract function boundaries" option is chosen, this file contains only the extracted function bodies that were sent to the LLM. Stored in the same directory as the analyzed binary.
