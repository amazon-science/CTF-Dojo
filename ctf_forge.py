#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

"""
Generate challenge.json and optional docker-compose.yml files for CTF challenges
directly from ctf-archive repository structure.

This script processes CTF challenge directories from ctf-archive that contain
required files (flag.sha256 or flagcheck files) and generates the required files
for EnIGMA directly in each task folder.
"""

import json
import argparse
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import re
import threading
import concurrent.futures
from tqdm import tqdm
import yaml
import stat
import mimetypes
import fnmatch
import zipfile
import tarfile
import tempfile
import litellm
import sys
from forge.analysis import (
    analyze_executable_content,
    detect_elf_architecture,
    get_binary_architecture,
    analyze_python_server_script,
)
from forge.files import (
    has_required_files,
    find_task_directories,
    extract_task_info,
    filter_out_patched_files,
    get_task_files,
    read_description,
    get_category_from_module_yml,
    read_rehost_content,
    read_init_content,
    get_file_type_info,
    get_task_files_with_info,
)
from forge.validators import (
    validate_dockerfile,
    fix_dockerfile_trailing_backslashes,
    remove_duplicate_docker_setup,
    check_dockerfile_file_existence,
    fix_dockerfile_in_place,
)
from forge.generation import (
    generate_challenge_json,
    call_model_for_docker_compose,
    validate_and_fix_dockerfile,
    call_model_for_dockerfile_with_fallback,
    call_model_for_challenge_json,
)
from forge.prompts import (
    SERVER_DETECTION_PROMPT,
    DOCKERFILE_GENERATION_PROMPT,
    WRAPPER_32BIT,
    WRAPPER_64BIT,
    DOCKER_COMPOSE_GENERATION_PROMPT,
    CHALLENGE_JSON_PROMPT,
)

from forge.ctf_forge import (
    generate_adaptive_docker_setup,
    generate_fallback_dockerfile,
    generate_interpreter_fix_commands,
    generate_library_fix_commands,
    generate_shebang_fix_command,
    get_binary_architecture,
    get_category_specific_guidelines,
    get_enhanced_file_analysis,
    select_compatible_base_image,
    detect_custom_interpreter_paths,
    detect_node_files,
    detect_problematic_shebangs,
    detect_provided_libraries,
    detect_python_files,
    test_binary_library_configurations,
    call_by_litllm
)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def call_model_for_server_detection(task_data: Dict, model: str = "deepseek-v3-0324", max_retries: int = 10, verbose: bool = False) -> bool:
    """Use model to determine if a server is needed."""
    
    task_name = task_data.get("task_name", "")
    task_path = task_data.get("task_path", "")
    description = task_data.get("description", "")
    
    # Get Python scripts context
    python_context = get_python_scripts_context(task_path, get_task_files(task_path))
    
    prompt = SERVER_DETECTION_PROMPT.format(
        task_name=task_name,
        category=task_data.get("category", ""),
        description=description,
        rehost_content=task_data.get("rehost_content", ""),
        available_files_info=get_task_files_with_info(task_path),
        has_sha256_file=bool(find_sha256_file(task_path)),
        file_analysis=get_enhanced_file_analysis(task_path, get_task_files(task_path))
    )
    
    # Add Python scripts context to the prompt
    enhanced_prompt = f"""{prompt}

# Python Scripts Analysis:
{python_context}

Consider the Python scripts analysis above when making your server detection decision. Python server scripts that listen on ports are strong indicators that the challenge needs server hosting."""
    
    if verbose:
        print(f"{BLUE}=== Prompt for server detection ==={RESET}")
        print(enhanced_prompt)
        print(f"{BLUE}=== End Prompt for server detection ==={RESET}")
    
    messages = [
        {"role": "system", "content": "You are an expert at analyzing CTF challenges to determine if they require network services."},
        {"role": "user", "content": enhanced_prompt}
    ]
    
    for attempt in range(max_retries):
        try:
            response = call_by_litllm(messages, model=model, max_retries=1)
            result = "YES" in  response.strip().upper()
            return result   
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"{RED}Error: Model call failed for server detection after {max_retries} attempts: {e}{RESET}")
                return False
            # Wait before retry with exponential backoff
            import time
            wait_time = 2 ** attempt
            time.sleep(wait_time)

def parse_flag_from_dockerfile(dockerfile_content: str) -> Optional[str]:
    """Parse flag from dockerfile content, looking for pwn.college{...} patterns."""
    import re
    
    # Look for various patterns where flags might be defined
    patterns = [
        r"pwn\.college\{[^}]+\}",  # Direct flag pattern
        r"'pwn\.college\{[^}]+\}'",  # Quoted flag pattern
        r'"pwn\.college\{[^}]+\}"',  # Double quoted flag pattern
        r"echo\s+['\"]?(pwn\.college\{[^}]+\})['\"]?",  # Echo commands
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, dockerfile_content, re.IGNORECASE)
        for match in matches:
            flag = match.strip('\'"')
            # Make sure it's not just a placeholder
            if flag != "pwn.college{...}" and "..." not in flag:
                return flag
    
    return None

def find_sha256_file(task_path: str) -> Optional[str]:
    from forge.files import find_sha256_file as _f
    return _f(task_path)

def find_check_file(task_path: str) -> Optional[str]:
    from forge.files import find_check_file as _f
    return _f(task_path)

def cleanup_docker_files(task_output_dir: Path, verbose: bool = False) -> None:
    """Remove existing challenge.json, Dockerfile, and docker-compose.yml files from task directory."""
    docker_files = ["challenge.json", "Dockerfile", "docker-compose.yml"]
    
    for docker_file in docker_files:
        file_path = task_output_dir / docker_file
        if file_path.exists():
            try:
                file_path.unlink()
                if verbose:
                    print(f"{YELLOW}Removed existing {docker_file}{RESET}")
            except Exception as e:
                if verbose:
                    print(f"{RED}Warning: Could not remove {docker_file}: {e}{RESET}")
    
    # also remove any files having docker-compose- in the name
    for file_path in task_output_dir.rglob("*"):
        if file_path.is_file() and "docker-compose" in file_path.name:
            try:
                file_path.unlink()
                if verbose:
                    print(f"{YELLOW}Removed existing {file_path}{RESET}")
            except Exception as e:
                if verbose:
                    print(f"{RED}Warning: Could not remove {file_path}: {e}{RESET}")

def process_task(task_data: Dict, create_docker_compose: bool = True, model: str = "deepseek-v3-0324", max_retries: int = 10, overwrite: bool = False, verbose: bool = False) -> bool:
    """Process a single task and generate challenge.json and optional docker-compose.yml directly in the task folder."""
    
    task_path = task_data.get("task_path", "")
    task_name = task_data.get("task_name", "unknown")
    task_tags = task_data.get("task_tags", [])
    ctf_name = task_data.get("ctf_name", "unknown")
    
    if not task_path or not os.path.exists(task_path):
        if verbose:
            print(f"{RED}Task path does not exist: {task_path}{RESET}")
        return False
    
    task_output_dir = Path(task_path)  # Write directly to task folder
    
    # Check existing files
    dockerfile_exists = (task_output_dir / "Dockerfile").exists()
    docker_compose_exists = (task_output_dir / "docker-compose.yml").exists()
    challenge_json_exists = (task_output_dir / "challenge.json").exists()
    
    # If not overwriting, check what needs to be generated
    if not overwrite:
        if challenge_json_exists and docker_compose_exists and dockerfile_exists:
            if verbose:
                print(f"{YELLOW}Skipping existing task (all files present): {task_name}{RESET}")
            return True
        elif challenge_json_exists and not dockerfile_exists and not docker_compose_exists:
            if verbose:
                print(f"{YELLOW}Skipping existing task (challenge.json exists, no server files needed): {task_name}{RESET}")
            return True
        
        # Determine what needs to be generated
        need_dockerfile = not dockerfile_exists
        need_docker_compose = not docker_compose_exists  
        need_challenge_json = not challenge_json_exists
        
        if verbose:
            files_to_generate = []
            if need_dockerfile:
                files_to_generate.append("Dockerfile")
            if need_docker_compose:
                files_to_generate.append("docker-compose.yml")
            if need_challenge_json:
                files_to_generate.append("challenge.json")
            
            if files_to_generate:
                print(f"{BLUE}Generating missing files for {task_name}: {', '.join(files_to_generate)}{RESET}")
            else:
                print(f"{YELLOW}All files already exist for {task_name}{RESET}")
                return True
    else:
        # If overwriting, generate all files
        need_dockerfile = True
        need_docker_compose = True
        need_challenge_json = True
        
        if verbose:
            print(f"{BLUE}Overwriting existing task: {task_name}{RESET}")
        cleanup_docker_files(task_output_dir, verbose)

    try:
        # Step 1: Check if task has sha256 file
        has_sha256_file = find_sha256_file(task_path) is not None
        if verbose:
            print(f"{BLUE}=== Has SHA256 file: {has_sha256_file} ==={RESET}")
        
        # Step 2: Get task files (excluding generated files)
        task_files = get_task_files(task_path)
        
        if verbose:
            print(f"{BLUE}=== Task files ==={RESET}")
            print(task_files)
            print(f"{BLUE}=== End task files ==={RESET}")
        
        # Step 3: Check if server is needed
        rehost_content = task_data.get("rehost_content", "")
        has_own_custom_flag = "own custom flag" in rehost_content.lower()
        has_check_file = find_check_file(task_path) is not None
        
        category = task_data.get("category", "").lower() if task_data.get("category") else "misc"
        

        # Check for own custom flag - if detected, server is never needed
        if has_own_custom_flag:
            server_needed = False
            if verbose:
                print(f"{BLUE}=== Server not needed (has own custom flag) ==={RESET}")
        # Skip server detection if we have sha256 file or check file
        elif has_sha256_file or has_check_file:
            server_needed = False
            if verbose:
                if has_sha256_file:
                    print(f"{BLUE}=== Server not needed (has sha256 file) ==={RESET}")
                elif has_check_file:
                    print(f"{BLUE}=== Server not needed (has check file) ==={RESET}")
        # If both flag check and sha256 are not existing, server will be needed
        elif not has_sha256_file and not has_check_file:
            server_needed = True
            if verbose:
                print(f"{BLUE}=== Server needed (no sha256 file and no check file) ==={RESET}")
        else:
            # if task_data.get("category") in ["web", "pwn"]:
            server_needed = True
            # else:
            #     # Use model detection as fallback
            #     server_needed = call_model_for_server_detection(task_data, model, max_retries, verbose)
        
        if verbose:
            print(f"{BLUE}=== Server needed: {server_needed} ==={RESET}")
        
        # Step 4: Handle Dockerfile generation/reading
        parsed_flag = None
        dockerfile_content = ""
        used_files = set()  # Track files used in Dockerfile
        
        if server_needed and need_dockerfile:
            # Generate dockerfile for server setup using enhanced method with fallback strategies
            if verbose:
                print(f"{BLUE}=== Generating dockerfile (server_needed: {server_needed}) ==={RESET}")
            
            # Get available files (excluding flag and check files)
            available_files = [file for file in task_files if "flagcheck" not in file.lower() and file not in ["Dockerfile", "docker-compose.yml"]]
            
            # Try enhanced generation with fallback strategies, retrying until valid
            dockerfile_content, parsed_flag, success = generate_dockerfile_with_retries(
                task_data, available_files, has_sha256_file, server_needed, model, max_retries, verbose
            )
            
            if not success:
                return False

            if dockerfile_content.strip():
                # Write dockerfile
                dockerfile_path = task_output_dir / "Dockerfile"
                with open(dockerfile_path, 'w') as f:
                    f.write(dockerfile_content)
                if verbose:
                    if parsed_flag:
                        print(f"{GREEN}Generated Dockerfile with flag: {parsed_flag}{RESET}")
                    else:
                        print(f"{GREEN}Generated Dockerfile{RESET}")
                
                # Parse used files from Dockerfile
                used_files = parse_dockerfile_used_files(dockerfile_content, task_files)
                if verbose:
                    print(f"{BLUE}=== Files used in Dockerfile ==={RESET}")
                    print(used_files)
                    print(f"{BLUE}=== End files used in Dockerfile ==={RESET}")
                
            else:
                if verbose:
                    print(f"{RED}Failed to generate dockerfile for {task_name}{RESET}")
                return False
        else:
            # Read existing Dockerfile content if it exists (needed for docker-compose and challenge.json generation)
            if dockerfile_exists:
                try:
                    with open(task_output_dir / "Dockerfile", 'r', encoding='utf-8') as f:
                        dockerfile_content = f.read()
                        # Parse used files from existing Dockerfile
                        used_files = parse_dockerfile_used_files(dockerfile_content, task_files)
                        if verbose:
                            print(f"{BLUE}=== Files used in existing Dockerfile ==={RESET}")
                            print(used_files)
                            print(f"{BLUE}=== End files used in existing Dockerfile ==={RESET}")
                        # If no sha256 file, try to parse flag from existing dockerfile
                        if not has_sha256_file:
                            parsed_flag = parse_flag_from_dockerfile(dockerfile_content)
                except Exception as e:
                    if verbose:
                        print(f"{YELLOW}Warning: Could not read existing Dockerfile: {e}{RESET}")
        
        # Step 5: Handle docker-compose.yml generation/reading
        docker_compose_content = ""
        if server_needed:
            if need_docker_compose:
                # Generate docker-compose.yml using dockerfile content
                if dockerfile_content.strip():
                    docker_compose_content = call_model_for_docker_compose(task_data, dockerfile_content, task_files, model, max_retries, verbose)

                    if docker_compose_content.strip():
                        compose_path = task_output_dir / "docker-compose.yml"
                        with open(compose_path, 'w') as f:
                            f.write(docker_compose_content)
                        if verbose:
                            print(f"{GREEN}Generated docker-compose.yml for {task_name}{RESET}")
                    else:
                        if verbose:
                            print(f"{RED}Failed to generate docker-compose.yml for {task_name}{RESET}")
                else:
                    if verbose:
                        print(f"{RED}No Dockerfile content available for docker-compose generation{RESET}")
            else:
                # Read existing docker-compose.yml content for challenge.json generation
                if docker_compose_exists:
                    try:
                        with open(task_output_dir / "docker-compose.yml", 'r', encoding='utf-8') as f:
                            docker_compose_content = f.read()
                        if verbose:
                            print(f"{BLUE}Using existing docker-compose.yml for {task_name}{RESET}")
                    except Exception as e:
                        if verbose:
                            print(f"{YELLOW}Warning: Could not read existing docker-compose.yml: {e}{RESET}")
        
        # Step 6: Generate challenge.json if needed
        if need_challenge_json:
            # Get remaining files that weren't used in Dockerfile
            # used_files = [f for f in used_files if not f.endswith(".txt")]
            used_files = []
            remaining_files = [f for f in task_files if  "flagcheck" not in f.lower() 
                               and ".sha256" not in f.lower() and f not in ["Dockerfile", "docker-compose.yml", ".init"]
                            ]
                            #    and ".zip" not in f.lower() and ".tar" not in f.lower() and ".gz" not in f.lower()]
            
            if verbose:
                print(f"{BLUE}=== Remaining files for challenge.json ==={RESET}")
                print(remaining_files)
                print(f"{BLUE}=== End remaining files ==={RESET}")
            
            challenge_json = generate_challenge_json(task_data, remaining_files, server_needed, docker_compose_content, parsed_flag, model, max_retries, verbose)
            if not challenge_json:
                return False
            
            # Write challenge.json
            challenge_json_path = task_output_dir / "challenge.json"
            with open(challenge_json_path, 'w', encoding='utf-8') as f:
                json.dump(challenge_json, f, indent=2, ensure_ascii=False)
            
            if verbose:
                print(f"{GREEN}Generated challenge.json for {task_name}{RESET}")
        else:
            if verbose:
                print(f"{BLUE}Using existing challenge.json for {task_name}{RESET}")
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"{RED}Error processing task {task_name}: {e}{RESET}")
        return False


def analyze_executable_content(file_path: Path) -> str:  # re-export for backward compatibility
    from forge.analysis import analyze_executable_content as _aec
    return _aec(file_path)

def detect_elf_architecture(file_path: Path) -> str:  # re-export
    from forge.analysis import detect_elf_architecture as _dea
    return _dea(file_path)

def get_binary_architecture(task_path: str, task_files: List[str]) -> tuple[str, List[str]]:  # re-export
    from forge.analysis import get_binary_architecture as _gba
    return _gba(task_path, task_files)

def analyze_python_server_script(file_path: Path) -> tuple[bool, Optional[int], str]:  # re-export
    from forge.analysis import analyze_python_server_script as _apss
    return _apss(file_path)

# Add new function after the existing helper functions, around line 1200
def filter_binaries_by_architecture(task_path: str, binary_files: List[str], target_architecture: str) -> List[str]:
    """
    Filter binary files to only include those matching the target architecture.
    This ensures we focus on the correct binaries when both 32-bit and 64-bit exist.
    
    Args:
        task_path: Path to the task directory
        binary_files: List of binary file paths to filter  
        target_architecture: Target architecture ('32' or '64')
        
    Returns:
        List of binary files matching the target architecture
    """
    if not binary_files or target_architecture not in ['32', '64']:
        return binary_files
        
    task_dir = Path(task_path)
    filtered_files = []
    
    for file_path in binary_files:
        full_path = task_dir / file_path
        try:
            arch = detect_elf_architecture(full_path)
            if arch == target_architecture:
                filtered_files.append(file_path)
        except Exception:
            # If we can't detect architecture, include the file
            filtered_files.append(file_path)
    
    return filtered_files

def get_python_scripts_context(task_path: str, available_files: List[str]) -> str:
    """
    Analyze Python scripts to provide context for server detection.
    Returns detailed information about Python scripts and their server capabilities.
    """
    if not available_files:
        return "No files available for Python analysis."
    
    python_analysis = []
    task_dir = Path(task_path)
    
    python_files = [f for f in available_files if f.lower().endswith('.py')]
    
    if not python_files:
        return "No Python files detected."
    
    python_analysis.append(f"PYTHON SCRIPTS ANALYSIS ({len(python_files)} files):")
    
    server_scripts = []
    regular_scripts = []
    
    for py_file in python_files:
        py_path = task_dir / py_file
        is_server, port, content = analyze_python_server_script(py_path)
        
        if is_server:
            port_info = f"port {port}" if port else "unknown port"
            server_scripts.append({
                'file': py_file,
                'port': port,
                'content_snippet': content[:500] + "..." if len(content) > 500 else content
            })
            python_analysis.append(f"  🌐 SERVER SCRIPT: {py_file} (listens on {port_info})")
        else:
            try:
                with open(py_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    content_snippet = content[:300] + "..." if len(content) > 300 else content
                    regular_scripts.append({
                        'file': py_file,
                        'content_snippet': content_snippet
                    })
                    python_analysis.append(f"  📄 SCRIPT: {py_file}")
            except Exception as e:
                python_analysis.append(f"  ❌ ERROR: {py_file} - {e}")
    
    # Add detailed analysis
    if server_scripts:
        python_analysis.append(f"\n🔍 SERVER SCRIPTS DETAILS:")
        for script in server_scripts:
            python_analysis.append(f"  File: {script['file']}")
            python_analysis.append(f"  Port: {script['port'] or 'Not specified'}")
            python_analysis.append(f"  Content preview:")
            for line in script['content_snippet'].split('\n')[:10]:
                python_analysis.append(f"    {line}")
            python_analysis.append("")
    
    if regular_scripts:
        python_analysis.append(f"🔍 REGULAR SCRIPTS DETAILS:")
        for script in regular_scripts:
            python_analysis.append(f"  File: {script['file']}")
            python_analysis.append(f"  Content preview:")
            for line in script['content_snippet'].split('\n')[:5]:
                python_analysis.append(f"    {line}")
            python_analysis.append("")
    
    # Add server detection recommendation
    if server_scripts:
        python_analysis.append("🚀 SERVER DETECTION RECOMMENDATION:")
        python_analysis.append("  → Python server scripts detected - this challenge LIKELY NEEDS server hosting")
        python_analysis.append("  → Server scripts suggest network-based interaction required")
        python_analysis.append("  → Consider containerizing with Docker for proper server environment")
    else:
        python_analysis.append("📋 SERVER DETECTION RECOMMENDATION:")
        python_analysis.append("  → No Python server scripts detected")
        python_analysis.append("  → Regular Python scripts may be utility/helper scripts")
        python_analysis.append("  → Server hosting may not be required unless other indicators suggest otherwise")
    
    return "\n".join(python_analysis)


def generate_dockerfile_with_retries(task_data: Dict, available_files: List[str], has_sha256_file: bool, server_needed: bool, model: str, max_retries: int, verbose: bool = False) -> tuple[str, Optional[str], bool]:
    """
    Generate Dockerfile with retries until valid (no non-existing files).
    Returns (dockerfile_content, parsed_flag, success).
    """
    max_dockerfile_retries = 5  # Limit retries to prevent infinite loops
    dockerfile_retry_count = 0
    dockerfile_generated = False
    dockerfile_content = ""
    parsed_flag = None
    
    while not dockerfile_generated and dockerfile_retry_count < max_dockerfile_retries:
        dockerfile_retry_count += 1
        if verbose and dockerfile_retry_count > 1:
            print(f"{YELLOW}Retrying Dockerfile generation (attempt {dockerfile_retry_count}/{max_dockerfile_retries})...{RESET}")
        
        try:
            dockerfile_content, parsed_flag = call_model_for_dockerfile_with_fallback(
                task_data, available_files, has_sha256_file, server_needed, model, max_retries, verbose
            )
            
            if dockerfile_content.strip():
                # Validate and potentially fix the generated Dockerfile
                dockerfile_content, is_valid = validate_and_fix_dockerfile(dockerfile_content, available_files, task_data, verbose)
                
                # Check specifically for non-existing file issues
                if is_valid:
                    dockerfile_generated = True
                    if verbose:
                        print(f"{GREEN}✓ Generated valid Dockerfile on attempt {dockerfile_retry_count}{RESET}")
                else:
                    # Check if the validation issues include non-existing files
                    _, validation_issues = validate_dockerfile(dockerfile_content, available_files, verbose)
                    has_file_issues = any("does not match any available files" in issue for issue in validation_issues)
                    
                    if has_file_issues:
                        if verbose:
                            print(f"{YELLOW}✗ Dockerfile contains non-existing files, retrying...{RESET}")
                            for issue in validation_issues:
                                if "does not match any available files" in issue:
                                    print(f"    - {issue}")
                        # Continue loop to retry generation
                    else:
                        # If issues are not file-related, accept the Dockerfile
                        dockerfile_generated = True
                        if verbose:
                            print(f"{YELLOW}Generated Dockerfile with non-file validation issues (acceptable){RESET}")
            else:
                if verbose:
                    print(f"{RED}Empty Dockerfile generated on attempt {dockerfile_retry_count}{RESET}")
                    
        except Exception as e:
            if verbose:
                print(f"{RED}Dockerfile generation failed on attempt {dockerfile_retry_count}: {e}{RESET}")
            
            # If this was the last attempt, break
            if dockerfile_retry_count >= max_dockerfile_retries:
                break
    
    # Check if we successfully generated a Dockerfile
    if not dockerfile_generated:
        if verbose:
            print(f"{RED}Failed to generate valid Dockerfile after {max_dockerfile_retries} attempts{RESET}")
        return "", None, False
    
    return dockerfile_content, parsed_flag, True


def main():
    parser = argparse.ArgumentParser(description="Generate challenge.json and docker-compose.yml files directly in CTF challenge folders from ctf-archive.")
    parser.add_argument('--path', default='ctf-archive', 
                       help='Path to template directory that will be copied to ctf-archive')
    parser.add_argument('--max_tasks', type=int, default=None, 
                       help='Maximum number of tasks to process (for testing)')
    parser.add_argument('--filter_ctf', type=str, default=None, 
                       help='Filter tasks by CTF name (partial match)')
    parser.add_argument('--filter_category', type=str, default=None, 
                       help='Filter tasks by category/tag')
    parser.add_argument('--no_docker_compose', action='store_true', 
                       help='Skip generating docker-compose.yml files')
    parser.add_argument('--verbose', action='store_true', 
                       help='Verbose output with detailed processing information')
    parser.add_argument('--model', default='deepseek-v3-0324', 
                       help='Model ID for LLM calls')
    parser.add_argument('--max_retries', type=int, default=10, 
                       help='Max retries for LLM calls')
    parser.add_argument('--workers', type=int, default=32, 
                       help='Number of parallel workers')
    parser.add_argument('--skip_existing', action='store_true', default=True,
                       help='Skip tasks that already have challenge.json (default: True)')
    parser.add_argument('--overwrite', action='store_true', 
                       help='Overwrite existing challenge.json and docker files, and recopy template to ctf-archive')
    parser.add_argument('--demo', action='store_true', 
                       help='Process only one random task with verbose output for demonstration')
    
    args = parser.parse_args()
    
    # Define the working directory
    ctf_archive_path = 'ctf-archive'
    
    # Handle template copying and overwrite logic
    if args.overwrite:
        # Remove existing ctf-archive directory if it exists
        if os.path.exists(ctf_archive_path):
            if args.verbose:
                print(f"{YELLOW}Removing existing {ctf_archive_path} directory...{RESET}")
            shutil.rmtree(ctf_archive_path)
    
    # Copy template to ctf-archive if it doesn't exist or if overwrite is specified
    if not os.path.exists(ctf_archive_path) or args.overwrite:
        if not os.path.exists(args.path):
            print(f"{RED}Template directory not found: {args.path}{RESET}")
            return
        
        if args.verbose:
            print(f"{BLUE}Copying {args.path} to {ctf_archive_path}...{RESET}")
        
        try:
            shutil.copytree(args.path, ctf_archive_path)
            if args.verbose:
                print(f"{GREEN}Successfully copied template to {ctf_archive_path}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to copy template: {e}{RESET}")
            return
    
    # Check if ctf-archive directory exists
    if not os.path.exists(ctf_archive_path):
        print(f"{RED}CTF archive directory not found: {ctf_archive_path}{RESET}")
        return
    
    # Find all task directories with required files
    if args.verbose:
        print(f"{BLUE}Scanning {ctf_archive_path} for task directories with required files...{RESET}")
    task_directories = find_task_directories(ctf_archive_path)
    
    if not task_directories:
        print(f"{RED}No task directories with required files found in {ctf_archive_path}{RESET}")
        return
    
    if args.verbose:
        print(f"{GREEN}Found {len(task_directories)} task directories with required files{RESET}")
    
    # Convert directories to task data
    tasks = []
    for task_dir in task_directories:
        task_data = extract_task_info(task_dir)
        if task_data:
            tasks.append(task_data)
        else:
            if args.verbose:
                print(f"{YELLOW}Skipping directory (invalid structure): {task_dir}{RESET}")
    
    if args.verbose:
        print(f"{GREEN}Successfully parsed {len(tasks)} tasks{RESET}")
    
    # Demo mode: select one random task
    if args.demo:
        import random

        tasks = [random.choice(tasks)]  # Select one random task for demo
        args.workers = 1
        args.verbose = True
        # args.overwrite = True  # Always overwrite in demo mode
        print(f"{BLUE}Demo mode: Processing 1 random task with verbose output{RESET}")
        print(f"{BLUE}Selected task: {tasks[0]['ctf_name']}/{tasks[0]['task_name']}{RESET}")
    
    # Apply filters (only if not in demo mode)
    if not args.demo:
        filtered_tasks = tasks
        
        if args.filter_ctf:
            filtered_tasks = [t for t in filtered_tasks if args.filter_ctf.lower() in t.get("ctf_name", "").lower()]
            if args.verbose:
                print(f"{YELLOW}Filtered to {len(filtered_tasks)} tasks matching CTF: {args.filter_ctf}{RESET}")
        
        if args.filter_category:
            filtered_tasks = [t for t in filtered_tasks 
                             if any(args.filter_category.lower() in tag.lower() 
                                   for tag in t.get("task_tags", []))]
            if args.verbose:
                print(f"{YELLOW}Filtered to {len(filtered_tasks)} tasks matching category: {args.filter_category}{RESET}")
        
        if args.max_tasks:
            filtered_tasks = filtered_tasks[:args.max_tasks]
            if args.verbose:
                print(f"{YELLOW}Limited to {len(filtered_tasks)} tasks{RESET}")
        
        tasks = filtered_tasks
    
    # Filter out existing tasks if skip_existing is enabled (skip in demo mode)
    if not args.demo and args.skip_existing and not args.overwrite:
        original_count = len(tasks)
        existing_tasks = []
        remaining_tasks = []
        
        for task in tasks:
            task_path = task.get("task_path", "")
            if task_path:
                task_dir = Path(task_path)
                if (task_dir / "challenge.json").exists():
                    existing_tasks.append(task)
                else:
                    remaining_tasks.append(task)
            else:
                remaining_tasks.append(task)
        
        tasks = remaining_tasks
        
        if existing_tasks and args.verbose:
            print(f"{YELLOW}Skipping {len(existing_tasks)} existing tasks{RESET}")
            print(f"{GREEN}Processing {len(tasks)} remaining tasks{RESET}")
        
        if len(tasks) == 0:
            if args.verbose:
                print(f"{GREEN}All tasks already processed! Use --overwrite to reprocess.{RESET}")
            return
    
    # Process tasks
    successful = 0
    failed = 0
    
    def process_single_task(task):
        """Process a single task and return success status."""
        task_name = task.get("task_name", "unknown")
        ctf_name = task.get("ctf_name", "unknown")
        
        try:
            success = process_task(task, not args.no_docker_compose, args.model, args.max_retries, args.overwrite, args.verbose)
            if args.verbose and success:
                print(f"{GREEN}✓ Completed: {ctf_name}/{task_name}{RESET}")
            elif args.verbose and not success:
                print(f"{RED}✗ Failed: {ctf_name}/{task_name}{RESET}")
            return success
        except Exception as e:
            if args.verbose:
                print(f"{RED}✗ Error processing {ctf_name}/{task_name}: {e}{RESET}")
            return False
    
    if args.workers == 1 or args.demo:
        # Sequential processing (always used in demo mode)
        for i, task in enumerate(tasks, 1):
            task_name = task.get("task_name", "unknown")
            ctf_name = task.get("ctf_name", "unknown")
            
            if args.verbose or args.demo:
                print(f"\n{BLUE}[{i}/{len(tasks)}] Processing: {ctf_name}/{task_name}{RESET}")
                print(f"{BLUE}Task path: {task.get('task_path', 'unknown')}{RESET}")
            
            if process_single_task(task):
                successful += 1
            else:
                failed += 1
    else:
        # Parallel processing
        if args.verbose:
            print(f"{BLUE}Processing {len(tasks)} tasks with {args.workers} workers...{RESET}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            with tqdm(total=len(tasks), desc="Processing tasks") as pbar:
                futures = []
                for task in tasks:
                    futures.append(executor.submit(process_single_task, task))
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        successful += 1
                    else:
                        failed += 1
                    pbar.update(1)
    
    # Summary
    if args.verbose:
        print(f"\n{GREEN}Summary:{RESET}")
        print(f"  {GREEN}Successfully processed: {successful}{RESET}")
        print(f"  {RED}Failed: {failed}{RESET}")
        print(f"  {BLUE}Files generated directly in task directories{RESET}")
    
    if args.demo and successful > 0:
        # Show demo results
        task = tasks[0]
        task_path = Path(task.get("task_path", ""))
        print(f"\n{BLUE}Demo Results for {task['ctf_name']}/{task['task_name']}:{RESET}")
        
        if (task_path / "challenge.json").exists():
            print(f"{GREEN}✓ challenge.json generated{RESET}")
            if args.verbose:
                with open(task_path / "challenge.json", 'r') as f:
                    challenge_data = json.load(f)
                    print(f"  - Name: {challenge_data.get('name', 'N/A')}")
                    print(f"  - Category: {challenge_data.get('category', 'N/A')}")
                    print(f"  - Files: {challenge_data.get('files', [])}")
                    print(f"  - Compose: {challenge_data.get('compose', False)}")
                    if 'sha256_flag' in challenge_data:
                        print(f"  - SHA256 flag: {challenge_data['sha256_flag'][:20]}...")
        
        if (task_path / "Dockerfile").exists():
            print(f"{GREEN}✓ Dockerfile generated{RESET}")
        
        if (task_path / "docker-compose.yml").exists():
            print(f"{GREEN}✓ docker-compose.yml generated{RESET}")

def parse_dockerfile_used_files(dockerfile_content: str, available_files: List[str]) -> Set[str]:
    """Parse Dockerfile content to find which files from available_files have been used."""
    used_files = set()
    
    # Common Dockerfile commands that might reference files
    file_commands = ['COPY', 'ADD']
    
    # Split into lines and process each line
    lines = dockerfile_content.split('\n')
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
            
        # Check if line starts with a file command
        parts = line.split()
        if parts and parts[0] in file_commands:
            # Skip multi-stage build references (--from=)
            if '--from=' in line:
                continue
                
            # Remove quotes if present
            args = [arg.strip('"\'') for arg in parts[1:]]
            
            # Check each argument against available files (exclude destination - last arg)
            for arg in args[:-1]:  # Last arg is destination
                # Expand the pattern to find matching files
                matched_files = _expand_dockerfile_source_pattern(arg, available_files)
                used_files.update(matched_files)
    
    return used_files


if __name__ == "__main__":
    # Add a command-line option to fix existing Dockerfiles
    if len(sys.argv) > 1 and sys.argv[1] == "--fix-dockerfile":
        if len(sys.argv) > 2:
            dockerfile_path = sys.argv[2]
            fix_dockerfile_in_place(dockerfile_path, verbose=True)
        else:
            print("Usage: python set_ctf_environment.py --fix-dockerfile <dockerfile_path>")
        sys.exit(0)
    
    # Continue with normal execution
    main() 