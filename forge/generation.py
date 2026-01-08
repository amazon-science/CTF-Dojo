# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

"""
Generation helpers for Dockerfile, docker-compose.yml, and challenge.json.
These functions wrap LLM prompting, validation, and post-processing.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from forge.prompts import (
    SERVER_DETECTION_PROMPT,
    DOCKERFILE_GENERATION_PROMPT,
    WRAPPER_32BIT,
    WRAPPER_64BIT,
    DOCKER_COMPOSE_GENERATION_PROMPT,
    CHALLENGE_JSON_PROMPT,
)
from forge.validators import (
    validate_dockerfile,
    fix_dockerfile_trailing_backslashes,
    remove_duplicate_docker_setup,
    check_dockerfile_file_existence,
)

# Import analysis and file helpers the module depends on
from forge.analysis import (
    analyze_executable_content,
    detect_elf_architecture,
    get_binary_architecture,
)
from forge.files import (
    get_task_files,
    get_task_files_with_info,
    read_init_content,
    read_rehost_content,
    read_description,
    find_sha256_file,
    find_check_file,
)

from forge.ctf_forge import (
    RED, GREEN, YELLOW, BLUE, RESET,
    call_by_litllm,
    detect_provided_libraries,
    select_compatible_base_image,
    test_binary_library_configurations,
    generate_library_fix_commands,
    detect_custom_interpreter_paths,
    generate_interpreter_fix_commands,
    detect_problematic_shebangs,
    generate_shebang_fix_command,
    detect_python_files,
    detect_node_files,
    get_category_specific_guidelines,
    get_enhanced_file_analysis,
    generate_adaptive_docker_setup,
    generate_fallback_dockerfile,
)

# The following functions are thin re-exports; the full logic remains in ctf_forge.py for now.
# This module is introduced to centralize generation-related symbols and enable incremental migration.

def parse_flag_from_dockerfile(dockerfile_content: str) -> Optional[str]:
    import re
    patterns = [
        r"pwn\.college\{[^}]+\}",
        r"'pwn\.college\{[^}]+\}'",
        r'"pwn\.college\{[^}]+\}"',
        r"echo\s+['\"]?(pwn\.college\{[^}]+\})['\"]?",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, dockerfile_content, re.IGNORECASE)
        for match in matches:
            flag = match.strip('\'\"')
            if flag != "pwn.college{...}" and "..." not in flag:
                return flag
    return None


def call_model_for_dockerfile(task_data: Dict, available_files: List[str], has_sha256_file: bool = True, server_needed: bool = False, model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> tuple[str, Optional[str]]:
    """Use model to generate Dockerfile content. Returns (dockerfile_content, parsed_flag)."""
    
    task_name = task_data.get("task_name", "")
    task_tags = task_data.get("task_tags", [])
    task_path = task_data.get("task_path", "")
    description = task_data.get("description", "")
    rehost_content = task_data.get("rehost_content", "")
    category = task_data.get("category", "")
    
    # Determine architecture
    architecture, relevant_binary_files = get_binary_architecture(task_path, available_files)
    if verbose:
        print(f"{BLUE}Detected architecture: {architecture}-bit{RESET}")
        if relevant_binary_files:
            print(f"{BLUE}Relevant binary files: {relevant_binary_files}{RESET}")
    
    # Detect provided libraries
    provided_libs = detect_provided_libraries(task_path, available_files)
    if verbose and provided_libs:
        print(f"{BLUE}Detected provided libraries: {provided_libs}{RESET}")
    
    # Select compatible base image based on library analysis
    base_image = select_compatible_base_image(provided_libs, task_path)
    if verbose:
        print(f"{BLUE}Selected base image: {base_image}{RESET}")
    
    # Use only the architecture-relevant binary files for library testing
    binary_files = relevant_binary_files
    
    # Test library configurations to get detailed analysis
    test_results = {}
    if provided_libs and binary_files:
        test_results = test_binary_library_configurations(task_path, binary_files, provided_libs, verbose)
    
    # Generate library fix commands based on test results
    if test_results and test_results.get("working_config") != "system_libs":
        library_fix_commands = test_results.get("commands", [])
        if test_results.get("working_config") == "unknown":
            # Fallback to heuristic approach
            library_fix_commands = generate_library_fix_commands(provided_libs, binary_files, task_path, verbose)
    else:
        library_fix_commands = generate_library_fix_commands(provided_libs, binary_files, task_path, verbose)
    
    # Select appropriate wrapper template
    architecture_specific_wrapper = WRAPPER_32BIT if architecture == '32' else WRAPPER_64BIT
    
    # Add library-specific instructions to wrapper if needed
    if provided_libs and binary_files:
        library_instructions = f"""

# LIBRARY DEPENDENCY HANDLING:
- **CRITICAL**: Custom libraries detected in task folder: {list(provided_libs.keys())}
- **MANDATORY**: Use patchelf to set correct interpreter and library paths
- **PROVIDED LIBRARIES**: {provided_libs}"""
        
        # Add test results information if available
        if test_results:
            library_instructions += f"""
- **COMPATIBILITY ANALYSIS**: {test_results.get('reason', 'Unknown')}"""
            
            if test_results.get("detected_issues"):
                library_instructions += f"""
- **DETECTED ISSUES**: {'; '.join(test_results['detected_issues'])}"""
            
            if test_results.get("recommended_base_image") != "ubuntu:20.04":
                library_instructions += f"""
- **RECOMMENDED BASE IMAGE**: {test_results['recommended_base_image']} (for better compatibility)"""
        
        library_instructions += f"""
- For binaries with provided libraries, the following approach MUST be used:
  1. Copy all library files to /challenge/ directory
  2. Use patchelf to set interpreter to provided dynamic linker (if available)
  3. Use patchelf to set rpath to current directory (.)
  4. This ensures binaries use provided libraries instead of system ones
- Example commands will be automatically generated based on detected libraries
- **CRITICAL**: Without proper library setup, binaries may segfault due to library incompatibility"""
        
        architecture_specific_wrapper += library_instructions
    
    # Prepare flag instruction based on whether sha256 file exists
    if has_sha256_file:
        flag_instruction = "\n\nNote that the challenge should be hosted on a server inside the docker container, so you need to consider making some CTF files part of the server (e.g., containing the server binary, or the server script, the server configuration file, or web files, etc.)"
    else:
        flag_instruction = '''

IMPORTANT: This challenge does not have a flag.sha256 file, so you MUST generate a flag and place it in `/flag`.

**CRITICAL FLAG GENERATION RULES:**
1.  **Inspect Script Logic:** If the file analysis provides the full content of a script (like a Python script), you MUST carefully inspect its code for any constraints on the flag's length, format, or content (e.g., `assert len(flag) % 16 == 1`).
2.  **Satisfy Constraints:** The flag you generate MUST satisfy all such constraints to prevent the script from crashing.
3.  **Format:** The flag must be in the format `pwn.college{...}`.
4.  **Command:** Use a command like `echo 'pwn.college{YOUR_VALID_FLAG_CONTENT}' > /flag`.
5.  **Uniqueness:** Ensure the flag content is unique and relevant to the challenge. Do not use placeholders like `...`.

Note that the challenge should be hosted on a server inside the docker container, so you need to consider making some CTF files part of the server (e.g., containing the server binary, or the server script, the server configuration file, or web files, etc.)'''
    
    # Get category-specific guidelines
    category_guidelines = get_category_specific_guidelines(category, task_tags)
    
    # Get enhanced file analysis
    file_analysis = get_enhanced_file_analysis(task_path, available_files)
    
    # Add architecture-specific setup to category guidelines
    if architecture == '32':
        category_guidelines += """

32-BIT SPECIFIC REQUIREMENTS:
**CRITICAL**: i386 architecture and 32-bit packages are ALREADY configured in the comprehensive setup.
- DO NOT add 'dpkg --add-architecture i386' commands - this is already done
- DO NOT install duplicate packages: socat, libc6:i386, libstdc++6:i386, lib32gcc-s1 - these are already installed
- DO NOT install coreutils:i386 as it conflicts with essential coreutils package
- Use linux32 command prefix for all binary executions in CMD/ENTRYPOINT
- The following packages are ALREADY available: libc6:i386, libstdc++6:i386, lib32gcc-s1, lib32stdc++6, libgcc1:i386, libpam0g:i386, libc6-dev-i386, libncurses5:i386, socat
- Use linux32 stdbuf for proper buffering control (or custom stdbuf32 wrapper)
- Focus on challenge-specific setup only, not system package installation"""
    
    # Update comprehensive Docker setup block to use dynamic base image
    has_python_files = detect_python_files(task_path, available_files)
    has_node_files = detect_node_files(task_path, available_files)
    comprehensive_setup = generate_adaptive_docker_setup(base_image, architecture, has_python_files, has_node_files)
    
    prompt = DOCKERFILE_GENERATION_PROMPT.format(
        task_name=task_name,
        category=category,
        available_files=[f for f in available_files if f not in ["Dockerfile", "docker-compose.yml", ".init"]],
        file_analysis=file_analysis,
        description=description,
        rehost_content=rehost_content,
        init_content=read_init_content(task_path),
        flag_instruction=flag_instruction,
        category_guidelines=category_guidelines,
        architecture_specific_wrapper=architecture_specific_wrapper
    )
    
    # Add library compatibility information to the prompt
    if test_results and test_results.get("detected_issues"):
        prompt += f"""

# LIBRARY COMPATIBILITY ANALYSIS:
The following compatibility issues were detected during library testing:
{chr(10).join(f"- {issue}" for issue in test_results['detected_issues'])}

Working configuration: {test_results.get('working_config', 'unknown')}
Recommended base image: {test_results.get('recommended_base_image', base_image)}

CRITICAL: Use the recommended base image and patchelf commands to ensure proper library compatibility."""
    
    if verbose:
        print(f"{BLUE}=== Dockerfile Generation Prompt ==={RESET}")
        print(prompt)
        print(f"{BLUE}=== End Dockerfile Generation Prompt ==={RESET}")

    messages = [
        {"role": "system", "content": f"You are an expert at creating Dockerfiles for CTF challenges. Generate only the Dockerfile content, no explanations. Use {base_image} as the base image for better compatibility. Follow the guidelines and validation checklist carefully."},
        {"role": "user", "content": prompt}
    ]
    
    attempt = 0
    while attempt < max_retries:
        try:
            response = call_by_litllm(messages, model=model, max_retries=1)
            # Clean up the response to extract just the Dockerfile content
            dockerfile_content = response.strip()
            # Remove markdown code blocks if present
            if dockerfile_content.startswith("```"):
                lines = dockerfile_content.split('\n')
                dockerfile_content = '\n'.join(lines[1:-1]) if len(lines) > 2 else dockerfile_content
            
            if dockerfile_content.strip():
                # Replace the FROM instruction with our selected base image
                lines = dockerfile_content.split('\n')
                modified_lines = []
                from_found = False
                
                for line in lines:
                    if line.strip().upper().startswith('FROM') and not from_found:
                        # Replace with our selected base image
                        modified_lines.append(f"FROM {base_image}")
                        modified_lines.append("ENV DEBIAN_FRONTEND=noninteractive")
                        modified_lines.append("ENV LC_CTYPE=C.UTF-8")
                        # Add comprehensive setup after the FROM instruction
                        modified_lines.append(comprehensive_setup.strip())
                        from_found = True
                    else:
                        modified_lines.append(line)
                
                dockerfile_content = '\n'.join(modified_lines)
                
                # Continue with the existing processing logic...
                # (rest of the function remains the same)
                
                # After injecting comprehensive setup, add library fix commands if needed
                if library_fix_commands:
                    lines = dockerfile_content.split('\n')
                    
                    # Find the last COPY command and add library fixes after it
                    last_copy_index = -1
                    for i, line in enumerate(lines):
                        line_stripped = line.strip()
                        if line_stripped.upper().startswith(('COPY', 'ADD')) and '/challenge' in line:
                            last_copy_index = i
                    
                    if last_copy_index >= 0:
                        # Insert library fix commands after the last COPY command
                        lines.insert(last_copy_index + 1, "")  # Add blank line
                        
                        # Add the library fix commands as a single RUN instruction
                        if len(library_fix_commands) > 1:
                            run_command = "RUN " + " && \\\n".join(library_fix_commands)
                        else:
                            run_command = "RUN " + library_fix_commands[0]
                        
                        lines.insert(last_copy_index + 2, run_command)
                        dockerfile_content = '\n'.join(lines)
                        
                        if verbose:
                            print(f"{GREEN}Added library fixing commands to Dockerfile{RESET}")
                    elif verbose:
                        print(f"{YELLOW}Could not find COPY command to add library fixes after{RESET}")
                
                # After library fixes, check for custom interpreter paths and fix them
                custom_interpreters = detect_custom_interpreter_paths(task_path, binary_files or available_files, verbose)
                if custom_interpreters:
                    if verbose:
                        print(f"{YELLOW}Detected custom interpreter paths: {custom_interpreters}{RESET}")
                    
                    interpreter_fix_commands = generate_interpreter_fix_commands(custom_interpreters, architecture)
                    
                    if interpreter_fix_commands:
                        lines = dockerfile_content.split('\n')
                        
                        # Find the last COPY command or library fix command and add interpreter fixes after it
                        last_relevant_index = -1
                        for i, line in enumerate(lines):
                            line_stripped = line.strip()
                            if (line_stripped.upper().startswith(('COPY', 'ADD', 'RUN')) and 
                                ('/challenge' in line or 'patchelf' in line)):
                                last_relevant_index = i
                        
                        if last_relevant_index >= 0:
                            # Insert interpreter fix commands after the last relevant command
                            lines.insert(last_relevant_index + 1, "")  # Add blank line
                            
                            # Add the interpreter fix commands as a single RUN instruction
                            if len(interpreter_fix_commands) > 1:
                                run_command = "RUN " + " && \\\n".join(interpreter_fix_commands)
                            else:
                                run_command = "RUN " + interpreter_fix_commands[0]
                            
                            lines.insert(last_relevant_index + 2, run_command)
                            dockerfile_content = '\n'.join(lines)
                            
                            if verbose:
                                print(f"{GREEN}Added interpreter fixing commands to Dockerfile{RESET}")
                        elif verbose:
                            print(f"{YELLOW}Could not find appropriate location to add interpreter fixes{RESET}")
                
                # After injecting interpreter fixes, detect and fix problematic shebangs
                problematic_shebangs = detect_problematic_shebangs(task_path, available_files)
                if problematic_shebangs and verbose:
                    print(f"{YELLOW}Detected problematic shebangs: {problematic_shebangs}{RESET}")
                
                shebang_fix_command = generate_shebang_fix_command(problematic_shebangs)
                if shebang_fix_command:
                    # Find the last COPY command and add the shebang fix after it
                    lines = dockerfile_content.split('\n')
                    last_copy_index = -1
                    insert_index = -1
                    
                    for i, line in enumerate(lines):
                        line_stripped = line.strip()
                        if line_stripped.upper().startswith(('COPY', 'ADD')) and '/challenge' in line:
                            last_copy_index = i
                            
                            # Check if this COPY command uses heredoc syntax
                            if '<<' in line:
                                # Extract the heredoc marker (EOF, EOL, etc.)
                                heredoc_marker = line.split('<<')[-1].strip().strip("'\"")
                                # Find the closing marker to insert after the complete heredoc block
                                for j in range(i + 1, len(lines)):
                                    if lines[j].strip() == heredoc_marker:
                                        insert_index = j
                                        break
                            else:
                                # Regular COPY command, insert right after it
                                insert_index = i
                        elif line_stripped.upper().startswith('RUN') and '<<' in line and '/challenge' in line:
                            # Handle RUN commands with heredoc (like RUN cat > file << 'EOL')
                            # NOTE: This should no longer occur with updated prompts that use printf instead
                            last_copy_index = i  # Treat this as a relevant command for insertion point
                            
                            # Extract the heredoc marker (EOF, EOL, etc.)
                            heredoc_marker = line.split('<<')[-1].strip().strip("'\"")
                            # Find the closing marker to insert after the complete heredoc block
                            for j in range(i + 1, len(lines)):
                                if lines[j].strip() == heredoc_marker:
                                    insert_index = j
                                    break
                    
                    if insert_index >= 0:
                        # Insert shebang fix command after the determined position
                        lines.insert(insert_index + 1, "")  # Add blank line
                        lines.insert(insert_index + 2, shebang_fix_command)
                        dockerfile_content = '\n'.join(lines)
                        
                        if verbose:
                            print(f"{GREEN}Added shebang fixing command to Dockerfile{RESET}")
                    elif verbose:
                        print(f"{YELLOW}Could not find appropriate location to add shebang fixes{RESET}")
                
                # Remove duplicate Docker setup commands to prevent conflicts
                dockerfile_content = remove_duplicate_docker_setup(dockerfile_content, verbose)
                
                # Check specifically for non-existing files being copied
                non_existing_files = check_dockerfile_file_existence(dockerfile_content, available_files)
                
                if non_existing_files:
                    if verbose:
                        print(f"{YELLOW}Dockerfile tries to copy non-existing files (attempt {attempt + 1}): {non_existing_files}{RESET}")
                    
                    # Add specific feedback about non-existing files
                    feedback_prompt = f"""
The previous Dockerfile tried to copy files that don't exist in the task folder:
Non-existing files: {non_existing_files}

Available files in the task folder are ONLY:
{available_files}

Please generate a corrected Dockerfile that ONLY copies files from the available files list above. Do not reference any files not in this list.
Use {base_image} as the base image for compatibility.

Original prompt:
{prompt}"""
                    
                    messages = [
                        {"role": "system", "content": f"You are an expert at creating Dockerfiles for CTF challenges. The previous attempt tried to copy files that don't exist. ONLY use files from the provided available files list. Use {base_image} as the base image."},
                        {"role": "user", "content": feedback_prompt}
                    ]
                    attempt += 1
                    continue
                
                # If no non-existing files, proceed with other validations
                is_valid, validation_issues = validate_dockerfile(dockerfile_content, available_files, verbose)
                
                # If no sha256 file, try to parse flag from dockerfile
                parsed_flag = None
                if not has_sha256_file:
                    parsed_flag = parse_flag_from_dockerfile(dockerfile_content)
                    # If we got a placeholder flag, retry
                    if parsed_flag is None or parsed_flag == "pwn.college{...}" or "..." in parsed_flag:
                        if verbose:
                            print(f"{YELLOW}Got placeholder flag, retrying dockerfile generation (attempt {attempt + 1}){RESET}")
                        attempt += 1
                        continue
                
                if verbose:
                    if is_valid:
                        print(f"{GREEN}Generated valid Dockerfile with {base_image} and comprehensive setup (attempt {attempt + 1}){RESET}")
                    else:
                        print(f"{YELLOW}Generated Dockerfile with {base_image} and validation issues (attempt {attempt + 1}): {validation_issues}{RESET}")
                
                # Break the loop - all files exist and we have a valid Dockerfile
                return dockerfile_content, parsed_flag
            else:
                if verbose:
                    print(f"{YELLOW}Empty Dockerfile content generated, retrying (attempt {attempt + 1}){RESET}")
                attempt += 1
                continue
                
        except Exception as e:
            if verbose:
                print(f"{RED}Error in attempt {attempt + 1}: {e}{RESET}")
            attempt += 1
            
            # Don't retry on BadRequestError (e.g., wrong provider) - it won't fix itself
            error_str = str(e)
            if "BadRequestError" in error_str or "LLM Provider NOT provided" in error_str:
                if verbose:
                    print(f"{RED}Fatal error: {e}. Stopping retries.{RESET}")
                raise
            
            if attempt >= max_retries:
                if verbose:
                    print(f"{RED}Max retries ({max_retries}) reached. Giving up.{RESET}")
                raise
            
            # Wait before retry with exponential backoff (but cap at 10 seconds)
            import time
            wait_time = min(2 ** min(attempt - 1, 5), 10)
            time.sleep(wait_time)


def call_model_for_dockerfile_with_fallback(task_data: Dict, available_files: List[str], has_sha256_file: bool = True, server_needed: bool = False, model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> tuple[str, Optional[str]]:
    """
    Enhanced version of call_model_for_dockerfile with fallback strategies.
    """
    # First try the main approach
    try:
        return call_model_for_dockerfile(task_data, available_files, has_sha256_file, server_needed, model, max_retries, verbose)
    except Exception as e:
        if verbose:
            print(f"{YELLOW}Main Dockerfile generation failed: {e}{RESET}")
            print(f"{BLUE}Attempting fallback strategies...{RESET}")
    
    # Fallback approach 1: Try with library compatibility analysis
    task_path = task_data.get("task_path", "")
    provided_libs = detect_provided_libraries(task_path, available_files)
    
    if provided_libs:
        # Get binary files for testing
        task_dir = Path(task_path)
        binary_files = []
        for file_path in available_files:
            full_path = task_dir / file_path
            if analyze_executable_content(full_path) == 'binary':
                binary_files.append(file_path)
        
        if binary_files:
            # Run library compatibility tests
            test_results = test_binary_library_configurations(task_path, binary_files, provided_libs, verbose)
            
            if test_results.get("working_config") == "unknown":
                if verbose:
                    print(f"{YELLOW}Library tests failed, generating fallback Dockerfile...{RESET}")
                
                # Generate fallback dockerfile
                fallback_dockerfile = generate_fallback_dockerfile(task_data, available_files, provided_libs, test_results, verbose)
                
                # Try to parse flag if needed
                parsed_flag = None
                if not has_sha256_file:
                    # Generate a simple flag for fallback
                    task_name = task_data.get("task_name", "challenge")
                    parsed_flag = f"pwn.college{{{task_name}_fallback_flag}}"
                
                if verbose:
                    print(f"{GREEN}Generated fallback Dockerfile{RESET}")
                
                return fallback_dockerfile, parsed_flag
    
    # Fallback approach 2: Generate minimal Dockerfile
    if verbose:
        print(f"{YELLOW}Generating minimal fallback Dockerfile...{RESET}")
    
    minimal_dockerfile = f"""FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \\
    socat \\
    python3 \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

COPY . /challenge/

RUN chmod +x /challenge/* 2>/dev/null || true

RUN printf '#!/bin/bash\\ncd /challenge\\necho "Challenge is ready for interaction"\\ncat\\n' > /challenge/run.sh && chmod +x /challenge/run.sh

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/challenge/run.sh,stderr"]"""
    
    parsed_flag = None
    if not has_sha256_file:
        task_name = task_data.get("task_name", "challenge")
        parsed_flag = f"pwn.college{{{task_name}_minimal_flag}}"
    
    if verbose:
        print(f"{GREEN}Generated minimal fallback Dockerfile{RESET}")
    
    return minimal_dockerfile, parsed_flag

def get_ubuntu_version_from_base_image(base_image: str) -> str:
    """
    Extract Ubuntu version from base image string.
    Returns version like "16.04", "18.04", "20.04", etc.
    """
    import re
    
    # Extract version from strings like "ubuntu:20.04", "ubuntu:16.04"
    match = re.search(r'ubuntu:(\d+\.\d+)', base_image.lower())
    if match:
        return match.group(1)
    
    # Default to 20.04 if no version found
    return "20.04"

def get_adaptive_package_lists(ubuntu_version: str, architecture: str = "64") -> Dict[str, List[str]]:
    """
    Get package lists adapted for specific Ubuntu versions and architecture.
    Returns dict with different package categories.
    """
    version_parts = ubuntu_version.split('.')
    major_version = int(version_parts[0])
    minor_version = int(version_parts[1]) if len(version_parts) > 1 else 0
    
    # Base packages available in all versions
    base_packages = [
        "build-essential",
        "ca-certificates", 
        "curl",
        "sudo",
        "wget",
        "unzip"
    ]
    
    # Development packages with version-specific alternatives
    dev_packages = [
        "autoconf",
        "bc", 
        "bison",
        "clang",
        "cmake",
        "cpio",
        "flex",
        "g++-multilib",
        "gcc-multilib", 
        "git",
        "libedit-dev",
        "libelf-dev",
        "libffi-dev",
        "libglib2.0-dev",
        "libgmp-dev",
        "libpcap-dev",
        "libseccomp-dev",
        "libssl-dev",
        "libtool-bin",
        "llvm",
        "man-db",
        "manpages-dev",
        "nasm",
        "python3-dev",
        "python3-pip",
        "squashfs-tools"
    ]
    
    # Add i386 packages only if 32-bit architecture is needed
    if architecture == '32':
        dev_packages.extend([
            "libc6-dev-i386",
            "libc6:i386", 
            "libncurses5:i386",
            "libstdc++6:i386"
        ])
    
    # Tools packages with version-specific alternatives  
    tools_packages = [
        "binutils",
        "binwalk",
        "bsdmainutils",
        "bsdutils", 
        "debianutils",
        "diffutils",
        "ed",
        "elfutils",
        "ethtool",
        "exiftool",
        "expect",
        "figlet",
        "findutils",
        "gdb",
        "gdb-multiarch",
        "hexedit",
        "iproute2",
        "iptables",
        "iputils-ping",
        "john",
        "jq",
        "keyutils",
        "kmod",
        "less",
        "ltrace",
        "nano",
        "net-tools",
        "netcat-openbsd",
        "nmap",
        "openssh-server",
        "p7zip-full",
        "parallel",
        "patchelf",
        "pcaputils",
        "pcre2-utils", 
        "strace",
        "tmux",
        "valgrind",
        "vim",
        "wireshark",
        "zip",
        "zsh",
        "xz-utils",
        "libxml2-dev",
        "libxslt-dev",
        "socat",
        "sqlite3"
    ]
    
    # Version-specific packages
    version_specific_packages = []
    python_packages = []
    java_packages = []
    
    if major_version >= 20:  # Ubuntu 20.04+
        version_specific_packages.extend([
            "python-is-python3",  # Only available in 20.04+
            "ipython3",
            "python3-ipdb",
            "python3-magic"
        ])
        python_packages = ["python-is-python3"]
        java_packages = ["openjdk-17-jdk"]  # Java 17 available in 20.04+
        
    elif major_version >= 18:  # Ubuntu 18.04-19.x
        version_specific_packages.extend([
            "ipython3", 
            "python3-ipdb",
            "python3-magic"
        ])
        # Create python symlink manually for older versions
        python_packages = []  # Will handle manually
        java_packages = ["openjdk-11-jdk"]  # Java 11 for 18.04
        
    else:  # Ubuntu 16.04 and older
        version_specific_packages.extend([
            "ipython",  # Different package name in 16.04
            "python3-magic"
        ])
        python_packages = []  # Will handle manually
        java_packages = ["openjdk-8-jdk"]  # Java 8 for 16.04
    
    # Packages that might not be available in older versions
    # optional_packages = []
    # if major_version >= 18:
    #     optional_packages.extend([
    #         "cargo", 
    #         "dwarves",
    #         "rust-src"
    #     ])
    
    # if major_version >= 20:
    #     optional_packages.extend([
    #         # nodejs and npm removed - these should only be installed when Node.js files are detected
    #     ])
    
    return {
        "base": base_packages,
        "development": dev_packages,
        "tools": tools_packages,
        "version_specific": version_specific_packages,
        "python": python_packages,
        "java": java_packages,
        # "optional": optional_packages
    }


def _call_model(messages: List[Dict[str, str]], model: str, max_retries: int) -> Optional[str]:
    # Avoid circular import by importing function at runtime from main module
    try:
        from ctf_forge import call_by_litllm  # type: ignore
    except Exception:
        # Fallback if module layout differs
        from . import ctf_forge  # type: ignore
        call_by_litllm = ctf_forge.call_by_litllm
    return call_by_litllm(messages, model, max_retries)


def call_model_for_docker_compose(task_data: Dict, dockerfile_content: str, available_files: List[str], model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> str:
    task_name = task_data.get("task_name", "")
    task_tags = task_data.get("task_tags", [])
    ctf_name = task_data.get("ctf_name", "chal")
    description = task_data.get("description", "")
    prompt = DOCKER_COMPOSE_GENERATION_PROMPT.format(
        task_name=task_name,
        ctf_name=ctf_name,
        available_files=available_files,
        description=description,
        dockerfile_content=dockerfile_content
    )
    messages = [
        {"role": "system", "content": "You are an expert at creating docker-compose.yml files for CTF challenges. Generate only the docker-compose.yml content with meaningful aliases, no explanations."},
        {"role": "user", "content": prompt}
    ]
    for attempt in range(max_retries):
        try:
            response = _call_model(messages, model, 1)
            if response is None:
                raise ValueError("Empty docker-compose content generated")
            compose_content = response.strip()
            if compose_content.startswith("```"):
                lines = compose_content.split('\n')
                start_idx = 1
                end_idx = len(lines) - 1
                for i, line in enumerate(lines):
                    if line.strip() and not line.strip().startswith('```') and ('services:' in line or 'version:' in line):
                        start_idx = i
                        break
                for i in range(len(lines) - 1, -1, -1):
                    if lines[i].strip() and not lines[i].strip().startswith('```'):
                        end_idx = i + 1
                        break
                compose_content = '\n'.join(lines[start_idx:end_idx])
            if compose_content.strip():
                return compose_content
            else:
                raise ValueError("Empty docker-compose content generated")
        except Exception as e:
            # Don't retry on BadRequestError (e.g., wrong provider) - it won't fix itself
            error_str = str(e)
            if "BadRequestError" in error_str or "LLM Provider NOT provided" in error_str:
                if verbose:
                    print(f"Fatal error: {e}. Stopping retries.")
                return ""
            
            if attempt == max_retries - 1:
                if verbose:
                    print(f"Error: Model call failed for docker-compose generation after {max_retries} attempts: {e}")
                return ""
            import time
            wait_time = 2 ** attempt
            time.sleep(wait_time)


def call_model_for_challenge_json(task_data: Dict, task_files: List[str], server_needed: bool, docker_compose_content: str = "", model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> Dict:
    task_name = task_data.get("task_name", "")
    task_tags = task_data.get("task_tags", [])
    task_path = task_data.get("task_path", "")
    description = task_data.get("description", "")
    rehost_content = task_data.get("rehost_content", "")

    docker_compose_section = ""
    if server_needed and docker_compose_content.strip():
        docker_compose_section = f"""
# Generated docker-compose.yml:
{docker_compose_content}

Use the docker-compose.yml information above to understand the server configuration and port mapping for this challenge."""

    prompt = CHALLENGE_JSON_PROMPT.format(
        task_name=task_name,
        category=task_data.get("category", ""),
        task_files=task_files,
        description=description,
        rehost_content=rehost_content,
        docker_compose_section=docker_compose_section
    )
    if server_needed:
        prompt += "\n\nNote that the challenge should be hosted on a server inside the docker container, you must specify `box` and `internal_port` in the challenge.json file."
    messages = [
        {"role": "system", "content": "You are an expert at creating challenge.json files for CTF challenges. Generate only valid JSON, no explanations."},
        {"role": "user", "content": prompt}
    ]

    for attempt in range(max_retries):
        try:
            while True:
                response = _call_model(messages, model, 1)
                if response is None:
                    raise ValueError("Model returned None response")

                json_content = response.strip()
                if json_content.startswith("```"):
                    lines = json_content.split('\n')
                    start_idx = 1
                    end_idx = len(lines) - 1
                    for i, line in enumerate(lines):
                        if line.strip().startswith('{'):
                            start_idx = i
                            break
                    for i in range(len(lines) - 1, -1, -1):
                        if lines[i].strip().endswith('}'):
                            end_idx = i + 1
                            break
                    json_content = '\n'.join(lines[start_idx:end_idx])

                if not json_content.strip().startswith('{'):
                    import re as _re
                    json_match = _re.search(r'\{.*\}', json_content, _re.DOTALL)
                    if json_match:
                        json_content = json_match.group(0)
                    else:
                        raise ValueError("No valid JSON found in model response")

                import json as _json
                try:
                    try:
                        challenge_json = _json.loads(json_content)
                    except _json.JSONDecodeError:
                        import re as _re2
                        name_match = _re2.search(r'"name"\s*:\s*"([^"]*)"', json_content)
                        desc_match = _re2.search(r'"description"\s*:\s*"(.*?)"(?=\s*,\s*")', json_content, _re2.DOTALL)
                        files_match = _re2.search(r'"files"\s*:\s*(\[[^\]]*\])', json_content)
                        box_match = _re2.search(r'"box"\s*:\s*"([^"]*)"', json_content)
                        port_match = _re2.search(r'"internal_port"\s*:\s*"([^\"]*)"', json_content)
                        compose_match = _re2.search(r'"compose"\s*:\s*(true|false)', json_content)
                        flag_match = _re2.search(r'"flag"\s*:\s*"([^\"]*)"', json_content)
                        if not desc_match:
                            desc_match = _re2.search(r'"description"\s*:\s*"(.*?)",\s*"files"', json_content, _re2.DOTALL)
                        challenge_json = {}
                        if name_match:
                            challenge_json["name"] = name_match.group(1)
                        if desc_match:
                            challenge_json["description"] = desc_match.group(1)
                        if files_match:
                            challenge_json["files"] = _json.loads(files_match.group(1))
                        if box_match:
                            challenge_json["box"] = box_match.group(1)
                        if port_match:
                            challenge_json["internal_port"] = port_match.group(1)
                        if compose_match:
                            challenge_json["compose"] = compose_match.group(1) == "true"
                        if flag_match:
                            challenge_json["flag"] = flag_match.group(1)

                    required_fields: List[str] = ["name", "description", "files"]
                    if not server_needed:
                        challenge_json.pop("box", None)
                        challenge_json.pop("internal_port", None)
                        challenge_json.pop("compose", None)
                    else:
                        required_fields.extend(["box", "internal_port", "compose"])
                        challenge_json["internal_port"] = int(challenge_json["internal_port"])

                    if "flagCheck" in challenge_json.get("description", ""):
                        continue

                    for field in required_fields:
                        if field not in challenge_json:
                            raise ValueError(f"Missing required field '{field}' in generated JSON")

                    return challenge_json

                except _json.JSONDecodeError as e:
                    if verbose:
                        print(f"Invalid JSON generated by model: {e}")
                    raise ValueError(f"Invalid JSON generated by model: {e}")

        except Exception as e:
            if verbose:
                print(f"Error: {e}")
            
            # Don't retry on BadRequestError (e.g., wrong provider) - it won't fix itself
            error_str = str(e)
            if "BadRequestError" in error_str or "LLM Provider NOT provided" in error_str:
                if verbose:
                    print(f"Fatal error: {e}. Stopping retries.")
                return {}
            
            if attempt == max_retries - 1:
                if verbose:
                    print(f"Error: Model call failed for challenge.json generation after {max_retries} attempts: {e}")
                return {}
            import time
            wait_time = 2 ** attempt
            time.sleep(wait_time)


def generate_challenge_json(task_data: Dict, task_files: List[str], server_needed: bool, docker_compose_content: str = "", parsed_flag: Optional[str] = None, model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> Dict:
    """Generate challenge.json content using the model and post-process it."""
    challenge_json = call_model_for_challenge_json(task_data, task_files, server_needed, docker_compose_content, model, max_retries, verbose)
    if not challenge_json:
        if verbose:
            print(f"Failed to generate challenge.json for {task_data.get('task_name', 'unknown')}")
        return {}

    # Always set category from task_data mapping
    category = task_data.get("category")
    if category and category in ["web", "pwn", "crypto", "rev", "forensics", "misc"]:
        challenge_json["category"] = category
    else:
        challenge_json["category"] = "misc"
        if verbose:
            print(f"Warning: No valid category found for {task_data.get('task_name', 'unknown')}, using 'misc'")

    # Post-process to add sha256_flag, flag_check, and flag fields
    task_path = task_data.get("task_path", "")
    if task_path:
        challenge_json = post_process_challenge_json(challenge_json, task_path, parsed_flag)

    return challenge_json


def post_process_challenge_json(challenge_json: Dict, task_path: str, parsed_flag: Optional[str] = None) -> Dict:
    """Post-process challenge.json to add sha256_flag, flag_check, and flag fields."""
    sha256_content = find_sha256_file(task_path)
    if sha256_content:
        challenge_json["sha256_flag"] = sha256_content

    check_file_path = find_check_file(task_path)
    if check_file_path:
        challenge_json["flag_check"] = check_file_path

    # Add flag field - use parsed flag if available and no sha256 file
    if parsed_flag and not sha256_content:
        challenge_json["flag"] = parsed_flag

    if sha256_content:
        if "accessdeniedctf" in task_path:
            challenge_json["flag"] = "accessdenied{...}"
        elif any(ctf_name in task_path for ctf_name in ["hsctf2020/mountains", "hsctf2021/multidimensional"]):
            challenge_json["flag"] = "flag{...}"
        else:
            challenge_json["flag"] = "..."

    return challenge_json


def validate_and_fix_dockerfile(dockerfile_content: str, available_files: List[str], task_data: Dict, verbose: bool = False) -> tuple[str, bool]:
    """
    Validate and attempt to fix common Dockerfile issues.
    Returns (fixed_dockerfile_content, is_valid).
    """
    # First fix trailing backslash issues
    fixed_dockerfile, backslash_fixes = fix_dockerfile_trailing_backslashes(dockerfile_content)
    
    lines = fixed_dockerfile.split('\n')
    fixed_lines = []
    issues_fixed = []
    
    # Add the backslash fixes to our issues_fixed list
    issues_fixed.extend(backslash_fixes)
    
    for line in lines:
        fixed_line = line
        
        # Fix incorrect file paths in COPY commands
        if line.strip().startswith(('COPY', 'ADD')):
            parts = line.split()
            if len(parts) >= 3:
                source = parts[1].strip('\'"')
                if source not in available_files and not source.startswith('.') and not source.endswith('*'):
                    # Check if this looks like a directory by seeing if there are files with this prefix
                    directory_files = [f for f in available_files if f.startswith(source + '/') or f.startswith(source + '\\')]
                    
                    if directory_files:
                        # This looks like a directory that exists as individual files in available_files
                        # Don't replace it, as the directory itself should be copied
                        if verbose:
                            print(f"{GREEN}Detected directory pattern '{source}' with {len(directory_files)} files, keeping as-is{RESET}")
                    else:
                        # Try to find a matching individual file
                        matches = [f for f in available_files if f.endswith(source) or source in f]
                        if matches:
                            # Additional check: make sure we're not replacing a directory name with a file
                            # If the source has no extension and the match has one, it might be a directory->file issue
                            best_match = matches[0]
                            source_has_ext = '.' in source.split('/')[-1]
                            match_has_ext = '.' in best_match.split('/')[-1]
                            
                            # If source has no extension but match does, and match is inside a directory 
                            # that matches source name, don't replace
                            if not source_has_ext and match_has_ext and source in best_match:
                                if verbose:
                                    print(f"{YELLOW}Skipping replacement of '{source}' with '{best_match}' - likely directory vs file{RESET}")
                            else:
                                fixed_line = line.replace(source, best_match)
                                issues_fixed.append(f"Fixed file path: {source} -> {best_match}")
        
        fixed_lines.append(fixed_line)
    
    final_dockerfile = '\n'.join(fixed_lines)
    
    # Validate the fixed dockerfile
    is_valid, remaining_issues = validate_dockerfile(final_dockerfile, available_files, verbose)
    
    if verbose and issues_fixed:
        print(f"{GREEN}Fixed Dockerfile issues: {issues_fixed}{RESET}")
    
    if verbose and remaining_issues:
        print(f"{YELLOW}Remaining validation issues: {remaining_issues}{RESET}")
    
    return final_dockerfile, is_valid