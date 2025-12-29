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


def call_by_litllm(messages, model, max_retries=50, backoff_base=2):
    """
    Calls litellm completion with retries and exponential backoff.
    """
    attempt = 0
    while attempt < max_retries:
        try:
            response = completion(
                model=model,
                messages=messages,
                temperature=0.6,
                top_p=0.95,
            )
            if not response['choices'][0]['message']['content']:
                raise Exception("No response from model")
            return response['choices'][0]['message']['content']
        except Exception as e:
            if "long" in str(e):
                return None
            print(f"Error: {e}")
            attempt += 1
            if attempt == max_retries:
                raise
            wait_time = 10
            time.sleep(wait_time)


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

def detect_provided_libraries(task_path: str, available_files: List[str]) -> Dict[str, str]:
    """
    Detect if custom libraries are provided in the task folder.
    Returns dict with library types and their paths.
    """
    provided_libs = {}
    
    for file_path in available_files:
        file_name = file_path.lower()
        
        # Check for dynamic linker
        if file_name.endswith('.so.2'):
            provided_libs['dynamic_linker'] = file_path
        
        # Check for libc
        if file_name == 'libc.so.6':
            provided_libs['libc'] = file_path
            
        # Check for other common libraries
        if file_name.startswith('lib') and file_name.endswith('.so'):
            lib_type = file_name.split('.')[0]  # e.g., 'libssl' from 'libssl.so'
            provided_libs[lib_type] = file_path
    
    return provided_libs

def test_binary_library_configurations(task_path: str, binary_files: List[str], provided_libs: Dict[str, str], verbose: bool = False) -> Dict[str, Any]:
    """
    Test different library configurations to determine which one works.
    Returns dict with working configuration and commands needed.
    """
    if not binary_files:
        return {"working_config": "none", "commands": [], "reason": "No binary files to test"}
    
    task_dir = Path(task_path)
    test_results = {
        "system_libs": False,
        "custom_libc_only": False,
        "custom_dynamic_linker": False,
        "working_config": "unknown",
        "commands": [],
        "reason": "No working configuration found",
        "detected_issues": [],
        "recommended_base_image": "ubuntu:20.04"
    }
    
    # Test with the first binary file (usually the main executable)
    test_binary = binary_files[0]
    test_binary_path = task_dir / test_binary
    
    if not test_binary_path.exists():
        test_results["reason"] = f"Test binary {test_binary} not found"
        return test_results
    
    if verbose:
        print(f"{BLUE}Testing library configurations for {test_binary}...{RESET}")
    
    # Detect GLIBC version mismatch issues
    if 'libc' in provided_libs:
        libc_path = task_dir / provided_libs['libc']
        custom_glibc_version = detect_glibc_version(libc_path)
        
        if custom_glibc_version:
            # Get system GLIBC version for comparison
            try:
                result = subprocess.run(['/lib/x86_64-linux-gnu/libc.so.6'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    system_glibc_match = re.search(r'version\s+(\d+\.\d+)', result.stdout)
                    if system_glibc_match:
                        system_glibc_version = system_glibc_match.group(1)
                        
                        if custom_glibc_version != system_glibc_version:
                            issue = f"GLIBC version mismatch: custom={custom_glibc_version}, system={system_glibc_version}"
                            test_results["detected_issues"].append(issue)
                            test_results["recommended_base_image"] = select_compatible_base_image(provided_libs, task_path)
                            
                            if verbose:
                                print(f"{YELLOW}⚠️  {issue}{RESET}")
                                print(f"{BLUE}Recommended base image: {test_results['recommended_base_image']}{RESET}")
            except Exception:
                pass
    
    # Test 1: System libraries (no custom libs) - with better error detection
    try:
        if verbose:
            print(f"{BLUE}  Testing system libraries...{RESET}")
        
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_binary = Path(temp_dir) / test_binary
            shutil.copy2(test_binary_path, temp_binary)
            
            # Test if binary runs with system libraries
            result = subprocess.run(
                [str(temp_binary)], 
                cwd=temp_dir,
                capture_output=True, 
                text=True, 
                timeout=3,
                input="\n"
            )
            
            # Analyze the result more carefully
            exit_code = result.returncode
            stderr_output = result.stderr.lower()
            
            # Check for specific error patterns
            segfault_indicators = [
                exit_code == -11,  # SIGSEGV
                'segmentation fault' in stderr_output,
                'core dumped' in stderr_output
            ]
            
            library_error_indicators = [
                'cannot execute binary file' in stderr_output,
                'no such file or directory' in stderr_output and 'ld-linux' in stderr_output,
                'wrong elf class' in stderr_output,
                'incompatible' in stderr_output
            ]
            
            if any(segfault_indicators):
                test_results["detected_issues"].append("Binary segfaults with system libraries")
                if verbose:
                    print(f"{RED}    ✗ System libraries cause segfault (exit code: {exit_code}){RESET}")
            elif any(library_error_indicators):
                test_results["detected_issues"].append("Binary has library compatibility issues")
                if verbose:
                    print(f"{RED}    ✗ System libraries have compatibility issues{RESET}")
            else:
                test_results["system_libs"] = True
                if verbose:
                    print(f"{GREEN}    ✓ System libraries work (exit code: {exit_code}){RESET}")
                    
    except subprocess.TimeoutExpired:
        # Timeout might indicate the binary is waiting for input (which is good)
        test_results["system_libs"] = True
        if verbose:
            print(f"{GREEN}    ✓ System libraries work (timed out waiting for input){RESET}")
    except Exception as e:
        if verbose:
            print(f"{YELLOW}    ? System libraries test failed: {str(e)[:50]}{RESET}")
    
    # Test 2: Custom libc only (enhanced)
    if 'libc' in provided_libs and not test_results["system_libs"]:
        try:
            if verbose:
                print(f"{BLUE}  Testing custom libc with system dynamic linker...{RESET}")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_binary = Path(temp_dir) / test_binary
                temp_libc = Path(temp_dir) / provided_libs['libc']
                
                shutil.copy2(test_binary_path, temp_binary)
                shutil.copy2(task_dir / provided_libs['libc'], temp_libc)
                
                # Try to patch the binary to use custom libc
                patchelf_result = subprocess.run(
                    ['patchelf', '--set-rpath', '.', str(temp_binary)], 
                    capture_output=True, text=True, timeout=10
                )
                
                if patchelf_result.returncode != 0:
                    test_results["detected_issues"].append("patchelf failed to set rpath")
                    if verbose:
                        print(f"{RED}    ✗ patchelf failed: {patchelf_result.stderr}{RESET}")
                else:
                    # Test the patched binary
                    result = subprocess.run(
                        [str(temp_binary)], 
                        cwd=temp_dir,
                        capture_output=True, 
                        text=True, 
                        timeout=3,
                        input="\n"
                    )
                    
                    if result.returncode != -11:  # Not a segfault
                        test_results["custom_libc_only"] = True
                        if verbose:
                            print(f"{GREEN}    ✓ Custom libc with system dynamic linker works{RESET}")
                    else:
                        test_results["detected_issues"].append("Custom libc with system linker still segfaults")
                        if verbose:
                            print(f"{RED}    ✗ Custom libc with system dynamic linker causes segfault{RESET}")
                        
        except subprocess.TimeoutExpired:
            test_results["custom_libc_only"] = True
            if verbose:
                print(f"{GREEN}    ✓ Custom libc works (timed out waiting for input){RESET}")
        except Exception as e:
            test_results["detected_issues"].append(f"Custom libc test failed: {str(e)}")
            if verbose:
                print(f"{YELLOW}    ? Custom libc test failed: {str(e)[:50]}{RESET}")
    
    # Test 3: Custom dynamic linker + custom libc (enhanced)
    if 'dynamic_linker' in provided_libs and 'libc' in provided_libs and not test_results["custom_libc_only"]:
        try:
            if verbose:
                print(f"{BLUE}  Testing custom dynamic linker + custom libc...{RESET}")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_binary = Path(temp_dir) / test_binary
                temp_libc = Path(temp_dir) / provided_libs['libc']
                temp_linker = Path(temp_dir) / provided_libs['dynamic_linker']
                
                shutil.copy2(test_binary_path, temp_binary)
                shutil.copy2(task_dir / provided_libs['libc'], temp_libc)
                shutil.copy2(task_dir / provided_libs['dynamic_linker'], temp_linker)
                
                # Patch binary to use custom interpreter and rpath
                interpreter_result = subprocess.run(
                    ['patchelf', '--set-interpreter', f'./{provided_libs["dynamic_linker"]}', str(temp_binary)], 
                    capture_output=True, text=True, timeout=10
                )
                
                rpath_result = subprocess.run(
                    ['patchelf', '--set-rpath', '.', str(temp_binary)], 
                    capture_output=True, text=True, timeout=10
                )
                
                if interpreter_result.returncode != 0 or rpath_result.returncode != 0:
                    test_results["detected_issues"].append("patchelf failed to set interpreter or rpath")
                    if verbose:
                        print(f"{RED}    ✗ patchelf failed to set interpreter or rpath{RESET}")
                else:
                    # Test the patched binary
                    result = subprocess.run(
                        [str(temp_binary)], 
                        cwd=temp_dir,
                        capture_output=True, 
                        text=True, 
                        timeout=3,
                        input="\n"
                    )
                    
                    if result.returncode != -11:  # Not a segfault
                        test_results["custom_dynamic_linker"] = True
                        if verbose:
                            print(f"{GREEN}    ✓ Custom dynamic linker + custom libc works{RESET}")
                    else:
                        test_results["detected_issues"].append("Custom dynamic linker + custom libc still segfaults")
                        if verbose:
                            print(f"{RED}    ✗ Custom dynamic linker + custom libc causes segfault{RESET}")
                        
        except subprocess.TimeoutExpired:
            test_results["custom_dynamic_linker"] = True
            if verbose:
                print(f"{GREEN}    ✓ Custom dynamic linker + custom libc works (timed out waiting for input){RESET}")
        except Exception as e:
            test_results["detected_issues"].append(f"Custom dynamic linker test failed: {str(e)}")
            if verbose:
                print(f"{YELLOW}    ? Custom dynamic linker test failed: {str(e)[:50]}{RESET}")
    
    # Determine the working configuration and generate appropriate commands
    if test_results["system_libs"]:
        test_results["working_config"] = "system_libs"
        test_results["commands"] = []
        test_results["reason"] = "Binary works with system libraries, no patchelf needed"
        
    elif test_results["custom_libc_only"]:
        test_results["working_config"] = "custom_libc_only"
        test_results["commands"] = [
            "# Set library path for custom libc",
            f"    patchelf --set-rpath . /challenge/{test_binary}"
        ]
        test_results["reason"] = "Binary works with custom libc and system dynamic linker"
        
    elif test_results["custom_dynamic_linker"]:
        test_results["working_config"] = "custom_dynamic_linker"
        test_results["commands"] = [
            "# Set custom interpreter and library path",
            f"    patchelf --set-interpreter ./{provided_libs['dynamic_linker']} /challenge/{test_binary}",
            f"    patchelf --set-rpath . /challenge/{test_binary}"
        ]
        test_results["reason"] = "Binary requires both custom dynamic linker and custom libc"
        
    else:
        test_results["working_config"] = "unknown"
        test_results["commands"] = []
        test_results["reason"] = "No working library configuration found - all tests failed"
        
        # Suggest fallback strategies
        if provided_libs:
            test_results["detected_issues"].append("Consider using compatible base image")
            test_results["detected_issues"].append("Consider using system dynamic linker with LD_LIBRARY_PATH")
    
    if verbose:
        print(f"{BLUE}  Result: {test_results['working_config']} - {test_results['reason']}{RESET}")
        if test_results["detected_issues"]:
            print(f"{YELLOW}  Issues detected: {test_results['detected_issues']}{RESET}")
    
    return test_results

def generate_library_fix_commands(provided_libs: Dict[str, str], binary_files: List[str], task_path: str = "", verbose: bool = False) -> List[str]:
    """
    Generate commands to fix library dependencies and interpreter paths.
    Now includes testing to determine the correct approach.
    """
    commands = []
    
    if not provided_libs or not binary_files:
        return commands
    
    # Test different configurations to see what actually works
    if task_path:
        test_results = test_binary_library_configurations(task_path, binary_files, provided_libs, verbose)
        
        if test_results["working_config"] == "system_libs":
            # No patchelf needed - system libraries work
            return []
        elif test_results["working_config"] in ["custom_libc_only", "custom_dynamic_linker"]:
            # Use the tested commands that actually work
            return test_results["commands"]
        else:
            if verbose:
                print(f"{YELLOW}Warning: No working library configuration found, falling back to heuristic approach{RESET}")
    
    # Fallback to original heuristic approach if testing fails or no task_path provided
    if 'dynamic_linker' in provided_libs:
        dynamic_linker = provided_libs['dynamic_linker']
        
        commands.append("# Fix interpreter and library paths for provided libraries")
        
        for binary_file in binary_files:
            # Set the correct interpreter
            commands.append(f"    patchelf --set-interpreter ./{dynamic_linker} /challenge/{binary_file}")
            
            # Set the rpath to current directory so it finds provided libraries
            commands.append(f"    patchelf --set-rpath . /challenge/{binary_file}")
    
    # If we have custom libc but no custom dynamic linker, just set rpath
    elif 'libc' in provided_libs:
        commands.append("# Set library path for provided libraries")
        
        for binary_file in binary_files:
            commands.append(f"    patchelf --set-rpath . /challenge/{binary_file}")
    
    return commands


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


def get_category_specific_guidelines(category: str, task_tags: List[str]) -> str:
    """Generate category-specific guidelines for Dockerfile creation."""
    
    category_lower = category.lower() if category else ""
    tags_lower = [tag.lower() for tag in task_tags]
    
    # Determine category from various sources
    if category_lower == "web" or any("web" in tag for tag in tags_lower):
        return """
WEB CHALLENGES:
- Install web server (apache2, nginx, or built-in server for frameworks)
- Install appropriate language runtime (php, python3, node.js, etc.)
- If using Python, install python3 and python-is-python3 packages
- Copy web files to appropriate directory (/var/www/html for Apache)
- Configure web server to serve files properly
- Expose port 80 or 8080 for HTTP access
- Use COPY for static files, ensure proper permissions
- Example: COPY *.php /var/www/html/ && chmod 644 /var/www/html/*.php
- Start web server with CMD ["apache2ctl", "-D", "FOREGROUND"] or similar"""
        
    elif category_lower == "pwn" or any("pwn" in tag for tag in tags_lower):
        return """
PWN CHALLENGES:
- Install socat for network service hosting.
- Follow the general guidelines for hosting executables using a `run.sh` wrapper for maximum stability.
- Expose port 1337 (standard for pwn challenges).
- May need additional libraries for binary execution, such as libc6:i386 for 32-bit binaries."""
        
    elif category_lower == "crypto" or any("crypto" in tag for tag in tags_lower):
    
        return """
CRYPTO CHALLENGES:
- Copy Python scripts to /challenge/ directory
- Install socat if hosting a crypto service
- Expose appropriate port (often 1337)
- Use CMD to run the crypto service
- Example: CMD ["python3", "/challenge/crypto_server.py"]
- Consider installing specific versions of crypto libraries if needed"""
        
    elif category_lower == "rev" or any("rev" in tag for tag in tags_lower):
        return """
REVERSE ENGINEERING CHALLENGES:
- Copy binary files to /challenge/ directory
- Set executable permissions for binaries
- May need specific libraries or runtime environments
- If hosting a service, use socat with appropriate port
- Example: COPY binary /challenge/ && chmod +x /challenge/binary
- Consider if challenge needs to run as service or just provide downloadable binary"""
        
    elif category_lower == "forensics" or any("forensics" in tag for tag in tags_lower):
        return """
FORENSICS CHALLENGES:
- Copy evidence files to appropriate directory
- Install analysis tools if challenge provides online analysis
- May not need network service - could be file download only
- If hosting service, use appropriate web server
- Example: COPY evidence.* /challenge/
- Consider file integrity and proper permissions"""
        
    else:  # misc or unknown
        return """
MISCELLANEOUS CHALLENGES:
- Analyze available files to determine service type
- Install appropriate runtime (python3 with python-is-python3, node.js, etc.) based on file types
- Copy all necessary files to /challenge/ directory
- Set appropriate permissions for executable files
- Choose port based on service type (1337 for general services)
- Use socat for simple TCP services or appropriate server for web-based challenges"""

def get_enhanced_file_analysis(task_path: str, available_files: List[str]) -> str:
    """Generate enhanced file analysis to help with Dockerfile creation."""
    
    if not available_files:
        return "No files available for analysis."
    
    analysis = []
    analysis.append(f"Total files: {len(available_files)}")
    
    # Categorize files by type
    executables = []
    scripts = []
    web_files = []
    config_files = []
    data_files = []
    libraries = []
    archives = []
    
    task_dir = Path(task_path)
    
    # Store file contents for analysis
    file_contents = {}
    
    # Track library dependencies found
    library_dependencies = []
    
    # Detect provided libraries first
    provided_libs = detect_provided_libraries(task_path, available_files)
    
    # Get binary architecture information for the overall task
    detected_arch, binary_files = get_binary_architecture(task_path, available_files)
    
    for file_path in available_files:
        file_full_path = task_dir / file_path
        file_info = get_file_type_info(file_full_path)
        file_name = file_path.lower()
        
        # First, try content analysis for all files to determine if they're scripts
        content_type = analyze_executable_content(file_full_path)
        
        # Special handling for Python scripts to detect servers
        if content_type == 'python':
            is_server, internal_port, script_content = analyze_python_server_script(file_full_path)
            if is_server:
                port_info = f" on port {internal_port}" if internal_port else ""
                server_note = f" - detected as PYTHON SERVER{port_info}"
                scripts.append(f"{file_path} ({file_info}){server_note}")
                executables.append(f"{file_path} ({file_info}){server_note}")
                
                # Add full script content to file_contents for model analysis
                header = f"--- PYTHON SERVER SCRIPT (listens on port {internal_port or 'UNKNOWN'}) ---"
                file_contents[file_path] = f"{header}\n{script_content}"
                continue # Skip to next file

        # Read file content for other scripts and small text files
        if content_type in ['node', 'php', 'shell', 'ruby', 'perl', 'lua']:
            try:
                with open(file_full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Limit content size to avoid overly long prompts
                    if len(content) > 2000:
                        file_contents[file_path] = content[:2000] + "\n... [truncated]"
                    else:
                        file_contents[file_path] = content
            except Exception as e:
                file_contents[file_path] = f"Error reading file: {e}"
        
        # Classify based on content analysis first, then fall back to extension/type analysis
        if content_type in ['python', 'node', 'php', 'shell', 'ruby', 'perl', 'lua']:
            # It's a script - add to both scripts and executables for proper handling
            scripts.append(f"{file_path} ({file_info}) - detected as {content_type} script")
            executables.append(f"{file_path} ({file_info}) - detected as {content_type} script")
        elif content_type == 'binary' and ("executable" in file_info.lower() or file_name.endswith(('.bin', '.out'))):
            # Get architecture information for this specific binary
            arch = detect_elf_architecture(file_full_path)
            arch_info = f" - {arch}-bit binary" if arch in ['32', '64'] else " - binary executable"
            executables.append(f"{file_path} ({file_info}){arch_info}")
        elif file_name.endswith(('.py', '.js', '.php', '.rb', '.pl', '.sh')):
            # Fallback for script files that content analysis missed
            scripts.append(f"{file_path} ({file_info}) - script file")
            executables.append(f"{file_path} ({file_info}) - script file")
            # Also try to read content for fallback scripts
            try:
                with open(file_full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if len(content) > 2000:
                        file_contents[file_path] = content[:2000] + "\n... [truncated]"
                    else:
                        file_contents[file_path] = content
            except Exception as e:
                file_contents[file_path] = f"Error reading file: {e}"
        elif file_name.endswith(('.html', '.htm', '.css', '.js', '.php')):
            web_files.append(f"{file_path} ({file_info})")
        elif file_name.endswith(('.conf', '.cfg', '.ini', '.yml', '.yaml', '.json')):
            config_files.append(f"{file_path} ({file_info})")
        elif file_name.endswith(('.so', '.dll', '.a')) or 'ld-linux' in file_name:
            # Enhanced library detection including dynamic linkers
            library_note = ""
            if 'ld-linux' in file_name:
                library_note = " - DYNAMIC LINKER"
            elif file_name == 'libc.so.6':
                library_note = " - LIBC LIBRARY"
            elif file_name.startswith('lib'):
                library_note = f" - SHARED LIBRARY ({file_name.split('.')[0]})"
            
            libraries.append(f"{file_path} ({file_info}){library_note}")
            
            # Analyze library names for common dependencies
            lib_name = Path(file_path).name.lower()
            if 'pam' in lib_name:
                library_dependencies.append(f"PAM library detected: {file_path} - may need libpam0g:i386 for 32-bit or libpam0g for 64-bit")
            elif 'ssl' in lib_name or 'crypto' in lib_name:
                library_dependencies.append(f"SSL/Crypto library detected: {file_path} - may need libssl-dev")
            elif 'mysql' in lib_name:
                library_dependencies.append(f"MySQL library detected: {file_path} - may need libmysqlclient-dev")
            elif 'sqlite' in lib_name:
                library_dependencies.append(f"SQLite library detected: {file_path} - may need libsqlite3-dev")
            elif 'ld-linux' in lib_name:
                library_dependencies.append(f"Custom dynamic linker detected: {file_path} - MUST use patchelf to set interpreter path")
            elif lib_name == 'libc.so.6':
                library_dependencies.append(f"Custom libc detected: {file_path} - MUST use patchelf to set library path")
        elif file_name.endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.rar', '.7z')):
            # Analyze archive contents
            archive_contents = get_archive_contents(file_full_path)
            archives.append(f"{file_path} ({file_info}) - Contents: {archive_contents}")
        else:
            data_files.append(f"{file_path} ({file_info})")
    
    # Add overall binary architecture analysis
    if binary_files:
        analysis.append(f"\n🏗️  BINARY ARCHITECTURE ANALYSIS:")
        analysis.append(f"  - Detected architecture: {detected_arch}-bit")
        analysis.append(f"  - Binary files analyzed: {len(binary_files)}")
        for binary_file in binary_files:
            binary_path = task_dir / binary_file
            arch = detect_elf_architecture(binary_path)
            analysis.append(f"    * {binary_file}: {arch}-bit")
        
        if detected_arch == '32':
            analysis.append("  - 🔧 32-bit binaries detected - requires i386 compatibility packages")
            analysis.append("  - Use RUN dpkg --add-architecture i386 && apt-get update")
            analysis.append("  - Install 32-bit versions of required libraries (package:i386)")
        elif detected_arch == '64':
            analysis.append("  - ✅ 64-bit binaries detected - standard amd64 packages should work")
    
    # Add provided libraries analysis at the top
    if provided_libs:
        analysis.append(f"\n🔧 CUSTOM LIBRARIES DETECTED ({len(provided_libs)}):")
        for lib_type, lib_path in provided_libs.items():
            analysis.append(f"  - {lib_type.upper()}: {lib_path}")
        analysis.append("  → These libraries require special handling with patchelf to avoid segmentation faults")
        analysis.append("  → Binaries MUST be patched to use these libraries instead of system ones")
    
    if executables:
        analysis.append(f"\nEXECUTABLE FILES ({len(executables)}):")
        for exe in executables[:5]:  # Limit to first 5
            analysis.append(f"  - {exe}")
        if len(executables) > 5:
            analysis.append(f"  ... and {len(executables) - 5} more")
        
        # Analyze executable types and provide specific recommendations
        analysis.append("\n  RECOMMENDATIONS FOR EXECUTABLES:")
        
        # Categorize executables by type based on content analysis already done
        binary_executables = []
        python_scripts = []
        node_scripts = []
        php_scripts = []
        shell_scripts = []
        other_scripts = []
        
        for exe_info in executables:
            exe_path = exe_info.split(' ')[0]
            full_file_path = task_dir / exe_path
            
            # Extract the detected type from the exe_info string
            if "detected as python script" in exe_info:
                python_scripts.append(exe_path)
            elif "detected as node script" in exe_info:
                node_scripts.append(exe_path)
            elif "detected as php script" in exe_info:
                php_scripts.append(exe_path)
            elif "detected as shell script" in exe_info:
                shell_scripts.append(exe_path)
            elif "detected as ruby script" in exe_info:
                other_scripts.append((exe_path, 'ruby'))
            elif "detected as perl script" in exe_info:
                other_scripts.append((exe_path, 'perl'))
            elif "detected as lua script" in exe_info:
                other_scripts.append((exe_path, 'lua'))
            elif "binary executable" in exe_info or "-bit binary" in exe_info:
                binary_executables.append(exe_path)
            else:
                # Fallback: re-analyze content for files without clear detection info
                file_type = analyze_executable_content(full_file_path)
                
                if file_type == 'python':
                    python_scripts.append(exe_path)
                elif file_type == 'node':
                    node_scripts.append(exe_path)
                elif file_type == 'php':
                    php_scripts.append(exe_path)
                elif file_type == 'shell':
                    shell_scripts.append(exe_path)
                elif file_type in ['ruby', 'perl', 'lua']:
                    other_scripts.append((exe_path, file_type))
                else:
                    binary_executables.append(exe_path)
        
        # Provide specific recommendations for each type
        if binary_executables:
            analysis.append("  - BINARY EXECUTABLES:")
            if detected_arch == '32':
                analysis.append("    * 🔧 32-bit binaries require special Docker setup with i386 architecture support")
                analysis.append("    * Add RUN dpkg --add-architecture i386 && apt-get update to Dockerfile")
                analysis.append("    * Install 32-bit libraries: libc6:i386, libstdc++6:i386, etc.")
            elif detected_arch == '64':
                analysis.append("    * ✅ 64-bit binaries use standard amd64 architecture")
            
            analysis.append("    * Use run.sh wrapper script for better stability and crash reporting")
            example_binary = Path(binary_executables[0]).name
            analysis.append(f"    * Create wrapper: RUN echo '#!/bin/sh\\n/challenge/{example_binary}' > /challenge/run.sh && chmod +x /challenge/run.sh")
            analysis.append("    * Execute with: CMD [\"socat\", \"TCP-LISTEN:1337,reuseaddr,fork\", \"EXEC:/challenge/run.sh,stderr\"]")
            analysis.append("    * Remember to chmod +x both the binary and run.sh")
            
            # Add specific library handling recommendations for binaries
            if provided_libs:
                analysis.append("    * ⚠️  CRITICAL: Custom libraries detected - MUST use patchelf to fix library paths")
                if 'dynamic_linker' in provided_libs:
                    analysis.append(f"    * MANDATORY: Set interpreter: patchelf --set-interpreter ./{provided_libs['dynamic_linker']} /challenge/{example_binary}")
                analysis.append(f"    * MANDATORY: Set library path: patchelf --set-rpath . /challenge/{example_binary}")
                analysis.append("    * Without proper patchelf setup, binaries will segfault due to library incompatibility")
    
    if scripts:
        analysis.append(f"\nSCRIPT FILES ({len(scripts)}):")
        for script in scripts[:5]:
            analysis.append(f"  - {script}")
        if len(scripts) > 5:
            analysis.append(f"  ... and {len(scripts) - 5} more")
        analysis.append("  → Install appropriate runtime (python3, node, php, etc.)")
    
    if web_files:
        analysis.append(f"\nWEB FILES ({len(web_files)}):")
        for web in web_files[:5]:
            analysis.append(f"  - {web}")
        if len(web_files) > 5:
            analysis.append(f"  ... and {len(web_files) - 5} more")
        analysis.append("  → Install web server (apache2, nginx) and copy to /var/www/html/")
    
    if archives:
        analysis.append(f"\nARCHIVE FILES ({len(archives)}):")
        for archive in archives:
            analysis.append(f"  - {archive}")
        analysis.append("  → Archive contents shown above - analyze contents to determine if server hosting is needed")
    
    if config_files:
        analysis.append(f"\nCONFIG FILES ({len(config_files)}):")
        for config in config_files[:3]:
            analysis.append(f"  - {config}")
        if len(config_files) > 3:
            analysis.append(f"  ... and {len(config_files) - 3} more")
        analysis.append("  → May need special placement or environment setup")
    
    if libraries:
        analysis.append(f"\nLIBRARY FILES ({len(libraries)}):")
        for lib in libraries[:5]:
            analysis.append(f"  - {lib}")
        if len(libraries) > 5:
            analysis.append(f"  ... and {len(libraries) - 5} more")
        analysis.append("  → CRITICAL: Custom libraries require patchelf setup for proper binary execution")
        analysis.append("  → Copy to /challenge/ and patch binary interpreter/rpath settings")
    
    if data_files:
        analysis.append(f"\nDATA/OTHER FILES ({len(data_files)}):")
        for data in data_files[:3]:
            analysis.append(f"  - {data}")
        if len(data_files) > 3:
            analysis.append(f"  ... and {len(data_files) - 3} more")
    
    # Add recommendations
    analysis.append(f"\nRECOMMENDATIONS:")
    if executables:
        analysis.append("  - Use socat to host executable binaries on port 1337")
        analysis.append("  - Set executable permissions with chmod +x")
        if provided_libs:
            analysis.append("  - 🔧 CRITICAL: Custom libraries detected - use patchelf to fix library paths")
            analysis.append("  - Without proper library setup, binaries will segfault")
    if scripts:
        analysis.append("  - Install appropriate runtime environment")
        analysis.append("  - Copy scripts to /challenge/ directory")
    if web_files:
        analysis.append("  - Set up web server and copy files to document root")
        analysis.append("  - Expose port 80 or 8080")
    if archives:
        analysis.append("  - Consider archive contents when deciding server hosting needs")
        analysis.append("  - Archives with source code + data files often indicate file-based challenges")
        analysis.append("  - Archives with web files or executables may need server hosting")
    
    # Enhanced library dependencies section
    if library_dependencies:
        analysis.append(f"\nLIBRARY DEPENDENCIES DETECTED:")
        for dep in library_dependencies:
            analysis.append(f"  - {dep}")
        analysis.append("  → Ensure proper library packages are installed in Dockerfile")
        analysis.append("  → Use patchelf commands to set correct interpreter and library paths")
        analysis.append("  → 🚨 CRITICAL: Custom libraries (especially ld-linux and libc) require special handling")
    
    # Add file contents section for scripts
    if file_contents:
        analysis.append(f"\nFILE CONTENTS ANALYSIS:")
        for file_path, content in file_contents.items():
            analysis.append(f"\n=== {file_path} ===")
            analysis.append(content)
            analysis.append(f"=== End of {file_path} ===")
    
    return "\n".join(analysis)


def get_archive_contents(archive_path: Path) -> str:
    """Get contents of archive files (zip, tar, etc.) for analysis."""
    try:
        if not archive_path.exists():
            return "archive file not found"
        
        archive_name = archive_path.name.lower()
        contents = []
        
        # Handle ZIP files
        if archive_name.endswith('.zip'):
            try:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    contents = [f for f in file_list if not f.endswith('/')]  # Exclude directories
            except zipfile.BadZipFile:
                return "corrupted zip file"
        
        # Handle TAR files (tar, tar.gz, tar.bz2, tar.xz, etc.)
        elif any(archive_name.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz']):
            try:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    file_list = tar_ref.getnames()
                    contents = [f for f in file_list if tar_ref.getmember(f).isfile()]  # Only files, not directories
            except tarfile.TarError:
                return "corrupted tar file"
        
        # Handle other formats using system tools (7z, rar)
        elif archive_name.endswith(('.7z', '.rar')):
            try:
                # Try using 7z command if available
                result = subprocess.run(['7z', 'l', str(archive_path)], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse 7z output - this is a simplified parser
                    lines = result.stdout.split('\n')
                    in_file_list = False
                    for line in lines:
                        if '---' in line and 'Name' in lines[lines.index(line)-1]:
                            in_file_list = True
                            continue
                        elif '---' in line and in_file_list:
                            break
                        elif in_file_list and line.strip():
                            # Extract filename from 7z output format
                            parts = line.split()
                            if len(parts) >= 6:
                                filename = ' '.join(parts[5:])
                                if filename and not filename.endswith('/'):
                                    contents.append(filename)
                else:
                    return "unsupported archive format"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return "cannot analyze archive (7z tool not available)"
        
        else:
            return "unsupported archive format"
        
        if not contents:
            return "empty archive"
        
        # Limit the number of files shown and categorize them
        file_types = {}
        for file_path in contents[:20]:  # Limit to first 20 files
            file_name = file_path.lower()
            
            # Categorize files
            if file_name.endswith(('.py', '.js', '.php', '.rb', '.pl', '.sh', '.c', '.cpp', '.java')):
                file_types.setdefault('source_code', []).append(file_path)
            elif file_name.endswith(('.html', '.htm', '.css', '.js')):
                file_types.setdefault('web_files', []).append(file_path)
            elif file_name.endswith(('.exe', '.bin', '.elf')):
                file_types.setdefault('executables', []).append(file_path)
            elif file_name.endswith(('.txt', '.md', '.pdf', '.doc')):
                file_types.setdefault('documents', []).append(file_path)
            elif file_name.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                file_types.setdefault('images', []).append(file_path)
            elif file_name.endswith(('.zip', '.tar', '.gz')):
                file_types.setdefault('nested_archives', []).append(file_path)
            else:
                file_types.setdefault('other', []).append(file_path)
        
        # Format the output
        result_parts = []
        for category, files in file_types.items():
            if files:
                result_parts.append(f"{category}: {', '.join(files[:5])}")
                if len(files) > 5:
                    result_parts.append(f" (+{len(files)-5} more)")
        
        total_files = len(contents)
        result = f"{total_files} files - " + "; ".join(result_parts)
        
        if total_files > 20:
            result += f" (showing first 20 of {total_files})"
        
        return result
        
    except Exception as e:
        return f"error analyzing archive: {str(e)}"

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

def detect_problematic_shebangs(task_path: str, available_files: List[str]) -> List[tuple[str, str]]:
    """
    Detect files with problematic shebangs that need to be fixed.
    Returns list of (file_path, problematic_shebang) tuples.
    """
    problematic_shebangs = []
    task_dir = Path(task_path)
    
    # Known problematic shebang patterns
    problematic_patterns = [
        '/opt/pwn.college/python',
        '/opt/pwn.college/node',
        '/opt/pwn.college/',
        '/usr/local/bin/python',  # might not exist in some containers
        '/usr/local/bin/node',    # might not exist in some containers
    ]
    
    for file_path in available_files:
        full_path = task_dir / file_path
        try:
            # Only check text files that could have shebangs
            if full_path.is_file() and full_path.stat().st_size < 1024 * 1024:  # Max 1MB
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    
                    if first_line.startswith('#!'):
                        # Check if this shebang is problematic
                        for problematic_pattern in problematic_patterns:
                            if problematic_pattern in first_line:
                                problematic_shebangs.append((file_path, first_line))
                                break
        except Exception:
            # Skip files that can't be read as text
            continue
    
    return problematic_shebangs

def generate_shebang_fix_command(problematic_shebangs: List[tuple[str, str]]) -> str:
    """
    Generate a RUN command to fix problematic shebangs.
    Returns the RUN command string to be added to Dockerfile.
    """
    if not problematic_shebangs:
        return ""
    
    # Create a mapping of common shebang fixes
    shebang_fixes = {
        '/opt/pwn.college/python': '/usr/bin/python3',
        '/opt/pwn.college/node': '/usr/bin/node',
        '/usr/local/bin/python': '/usr/bin/python3',
        '/usr/local/bin/node': '/usr/bin/node',
    }
    
    fix_commands = []
    fix_commands.append("# Fix problematic shebangs in challenge files")
    
    for file_path, original_shebang in problematic_shebangs:
        # Determine the correct replacement
        replacement_shebang = None
        
        for problematic_pattern, standard_replacement in shebang_fixes.items():
            if problematic_pattern in original_shebang:
                replacement_shebang = f"#!/usr/bin/env python3" if 'python' in original_shebang else f"#!/usr/bin/env node"
                # More specific replacements
                if 'python' in original_shebang.lower():
                    replacement_shebang = "#!/usr/bin/env python3"
                elif 'node' in original_shebang.lower():
                    replacement_shebang = "#!/usr/bin/env node"
                break
        
        if replacement_shebang:
            # Use sed to replace the first line (shebang) only
            escaped_original = original_shebang.replace('/', r'\/')
            escaped_replacement = replacement_shebang.replace('/', r'\/')
            fix_commands.append(f"    sed -i '1s|^{escaped_original}|{escaped_replacement}|' /challenge/{file_path}")
    
    if len(fix_commands) > 1:  # More than just the comment
        return "RUN " + " && \\\n".join(fix_commands)
    
    return ""

def detect_glibc_version(libc_path: Path) -> Optional[str]:
    """
    Detect GLIBC version from a libc.so.6 file.
    Returns version string like "2.23" or None if detection fails.
    """
    try:
        if not libc_path.exists():
            return None
            
        # Try to extract version using strings command
        result = subprocess.run(['strings', str(libc_path)], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Look for GNU C Library version string
            for line in result.stdout.split('\n'):
                if 'GNU C Library' in line and 'stable release version' in line:
                    # Extract version number (e.g., "2.23")
                    import re
                    version_match = re.search(r'version\s+(\d+\.\d+)', line)
                    if version_match:
                        return version_match.group(1)
                        
        # Fallback: try readelf to get version information
        result = subprocess.run(['readelf', '-V', str(libc_path)], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Look for GLIBC version in version symbols
            for line in result.stdout.split('\n'):
                if 'GLIBC_' in line:
                    # Extract highest GLIBC version found
                    import re
                    versions = re.findall(r'GLIBC_(\d+\.\d+)', line)
                    if versions:
                        # Return the highest version found
                        return max(versions, key=lambda v: tuple(map(int, v.split('.'))))
                        
    except Exception as e:
        print(f"{YELLOW}Warning: Could not detect GLIBC version from {libc_path}: {e}{RESET}")
        
    return None

def select_compatible_base_image(provided_libs: Dict[str, str], task_path: str = "") -> str:
    """
    Select the most compatible base image based on provided libraries.
    Returns base image string like "ubuntu:16.04" or "ubuntu:20.04".
    """
    
    # Default to Ubuntu 20.04
    default_base = "ubuntu:20.04"
    
    if not provided_libs or 'libc' not in provided_libs:
        return default_base
        
    # Detect GLIBC version from custom libc
    if task_path:
        libc_path = Path(task_path) / provided_libs['libc']
        glibc_version = detect_glibc_version(libc_path)
        
        if glibc_version:
            # Map GLIBC versions to compatible Ubuntu versions
            version_mapping = {
                "2.23": "ubuntu:16.04",  # Ubuntu 16.04 LTS
                "2.24": "ubuntu:16.04",  # Stay with 16.04 for compatibility
                "2.25": "ubuntu:17.04",  # Ubuntu 17.04 (but use 18.04 for LTS)
                "2.26": "ubuntu:18.04",  # Ubuntu 18.04 LTS
                "2.27": "ubuntu:18.04",  # Ubuntu 18.04 LTS
                "2.28": "ubuntu:18.04",  # Ubuntu 18.04 LTS
                "2.29": "ubuntu:19.04",  # Ubuntu 19.04 (but use 20.04 for LTS)
                "2.30": "ubuntu:20.04",  # Ubuntu 20.04 LTS
                "2.31": "ubuntu:20.04",  # Ubuntu 20.04 LTS
                "2.32": "ubuntu:20.04",  # Ubuntu 20.04 LTS
                "2.33": "ubuntu:21.04",  # Ubuntu 21.04 (but use 22.04 for LTS)
                "2.34": "ubuntu:21.10",  # Ubuntu 21.10 (but use 22.04 for LTS)
                "2.35": "ubuntu:22.04",  # Ubuntu 22.04 LTS
                "2.36": "ubuntu:22.04",  # Ubuntu 22.04 LTS
                "2.37": "ubuntu:22.04",  # Ubuntu 22.04 LTS
                "2.38": "ubuntu:23.04",  # Ubuntu 23.04 (but use 22.04 for stability)
            }
            
            # Find the best match
            compatible_base = version_mapping.get(glibc_version)
            if compatible_base:
                return compatible_base
            else:
                # For unknown versions, try to make an educated guess
                version_parts = glibc_version.split('.')
                if len(version_parts) >= 2:
                    major, minor = int(version_parts[0]), int(version_parts[1])
                    
                    if major == 2 and minor <= 23:
                        return "ubuntu:16.04"
                    elif major == 2 and minor <= 27:
                        return "ubuntu:18.04"
                    elif major == 2 and minor <= 31:
                        return "ubuntu:20.04"
                    else:
                        return "ubuntu:22.04"  # For newer versions
                        
        else:
            print(f"{YELLOW}Could not detect GLIBC version, using default base image{RESET}")
    
    return default_base

def generate_fallback_dockerfile(task_data: Dict, available_files: List[str], provided_libs: Dict[str, str], test_results: Dict[str, Any], verbose: bool = False) -> str:
    """
    Generate a fallback Dockerfile when the main approach fails.
    Uses alternative strategies like LD_LIBRARY_PATH and different base images.
    """
    task_name = task_data.get("task_name", "")
    base_image = test_results.get("recommended_base_image", "ubuntu:16.04")  # Default to older base for compatibility
    
    if verbose:
        print(f"{BLUE}Generating fallback Dockerfile with {base_image}...{RESET}")
    
    # Use adaptive package management for fallback too
    ubuntu_version = get_ubuntu_version_from_base_image(base_image)
    packages = get_adaptive_package_lists(ubuntu_version)
    
    # Generate a simpler, more robust Dockerfile
    dockerfile_lines = [
        f"FROM {base_image}",
        "",
        "ENV DEBIAN_FRONTEND=noninteractive",
        "ENV LC_CTYPE=C.UTF-8",
        "",
        "# Minimal package installation with error handling",
    ]
    
    # Install only essential packages that are likely to be available
    essential_packages = packages["base"] + ["socat", "patchelf", "gdb", "strace"]
    
    dockerfile_lines.extend([
        "RUN apt-get update && \\",
        "    ("
    ])
    
    # Install packages with error handling
    for i, pkg in enumerate(essential_packages):
        if i > 0:
            dockerfile_lines.append("     || true) && (")
        dockerfile_lines.append(f"apt-get install --no-install-recommends -yqq {pkg}")
    
    dockerfile_lines.extend([
        "     || true) && \\",
        "    apt-get clean && rm -rf /var/lib/apt/lists/*",
        "",
        "# Create python symlink if needed",
        "RUN ln -sf /usr/bin/python3 /usr/bin/python 2>/dev/null || true",
        "",
        "WORKDIR /challenge",
        "",
        "# Copy all challenge files",
    ])
    
    # Add COPY commands for all files
    for file_path in available_files:
        if not file_path.startswith('.') and file_path not in ['Dockerfile', 'docker-compose.yml']:
            dockerfile_lines.append(f"COPY {file_path} /challenge/")
    
    dockerfile_lines.extend([
        "",
        "# Set executable permissions for all files",
        "RUN chmod +x /challenge/* 2>/dev/null || true",
        "",
    ])
    
    # Find the main executable
    main_executable = None
    task_dir = Path(task_data.get("task_path", ""))
    for file_path in available_files:
        full_path = task_dir / file_path
        if analyze_executable_content(full_path) == 'binary':
            main_executable = file_path
            break
    
    if main_executable:
        dockerfile_lines.extend([
            "# Alternative library handling using LD_LIBRARY_PATH",
            f"ENV LD_LIBRARY_PATH=/challenge",
            "",
            "# Create wrapper script with multiple fallback strategies",
            "RUN echo '#!/bin/bash' > /challenge/run.sh && \\",
            "    echo 'cd /challenge' >> /challenge/run.sh && \\",
            "    echo '# Try different execution strategies' >> /challenge/run.sh && \\",
            f"    echo 'if [ -f \"{main_executable}\" ]; then' >> /challenge/run.sh && \\",
        ])
        
        # Add different execution strategies based on provided libraries
        if 'dynamic_linker' in provided_libs:
            dockerfile_lines.extend([
                f"    echo '  # Strategy 1: Use provided dynamic linker directly' >> /challenge/run.sh && \\",
                f"    echo '  if ./{provided_libs['dynamic_linker']} --list ./{main_executable} >/dev/null 2>&1; then' >> /challenge/run.sh && \\",
                f"    echo '    exec ./{provided_libs['dynamic_linker']} --library-path /challenge ./{main_executable}' >> /challenge/run.sh && \\",
                f"    echo '  fi' >> /challenge/run.sh && \\",
            ])
        
        dockerfile_lines.extend([
            f"    echo '  # Strategy 2: Use system dynamic linker with LD_LIBRARY_PATH' >> /challenge/run.sh && \\",
            f"    echo '  LD_LIBRARY_PATH=/challenge exec ./{main_executable}' >> /challenge/run.sh && \\",
            "    echo 'else' >> /challenge/run.sh && \\",
            "    echo '  echo \"Binary not found\"' >> /challenge/run.sh && \\",
            "    echo '  exit 1' >> /challenge/run.sh && \\",
            "    echo 'fi' >> /challenge/run.sh && \\",
            "    chmod +x /challenge/run.sh",
            "",
            "EXPOSE 1337",
            "",
            'CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/challenge/run.sh,stderr"]'
        ])
    else:
        # Fallback for non-binary executables
        dockerfile_lines.extend([
            "# Create generic wrapper script",
            "RUN echo '#!/bin/bash' > /challenge/run.sh && \\",
            "    echo 'cd /challenge' >> /challenge/run.sh && \\",
            "    echo 'echo \"Challenge ready\"' >> /challenge/run.sh && \\",
            "    echo 'cat' >> /challenge/run.sh && \\",  # Simple cat for interaction
            "    chmod +x /challenge/run.sh",
            "",
            "EXPOSE 1337",
            "",
            'CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/challenge/run.sh,stderr"]'
        ])
    
    return '\n'.join(dockerfile_lines)
 

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

def generate_adaptive_docker_setup(base_image: str, architecture: str = "64", has_python_files: bool = False, has_node_files: bool = False) -> str:
    """
    Generate comprehensive Docker setup commands that adapt to the base image and architecture.
    Only installs runtimes that are actually needed based on detected files.
    """
    ubuntu_version = get_ubuntu_version_from_base_image(base_image)
    
    setup_commands = []
    
    # Configure i386 architecture FIRST if needed for 32-bit builds
    if architecture == '32':
        setup_commands.extend([
            "# Configure i386 architecture for 32-bit support",
            "RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \\",
            "    dpkg --add-architecture i386 && \\",
            "    apt-get update",
            ""
        ])
    
    # Now do the main package installation
    setup_commands.extend([
        "# Comprehensive package installation with error handling",
        "RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \\",
        "    apt-get update && apt-get install --no-install-recommends -yqq \\"
    ])
    
    # Get appropriate package lists (now includes i386 packages if architecture == '32')
    packages = get_adaptive_package_lists(ubuntu_version, architecture)
    
    # Add base system packages
    setup_commands.extend([f"        {pkg} \\" for pkg in packages["base"]])
    
    # Add development tools
    setup_commands.extend([f"        {pkg} \\" for pkg in packages["development"]])
    
    # Add tools packages
    setup_commands.extend([f"        {pkg} \\" for pkg in packages["tools"]])
    
    # Add version-specific packages
    setup_commands.extend([f"        {pkg} \\" for pkg in packages["version_specific"]])
    
    # Conditionally add Python packages only if Python files are detected
    if has_python_files:
        setup_commands.extend([f"        {pkg} \\" for pkg in packages["python"]])
    
    # Add Java packages
    setup_commands.extend([f"        {pkg} \\" for pkg in packages["java"]])
    
    # Add optional packages
    # setup_commands.extend([f"        {pkg} \\" for pkg in packages["optional"]])
    
    # Remove the trailing backslash from the last package and close the command
    if setup_commands[-1].endswith(" \\"):
        setup_commands[-1] = setup_commands[-1][:-2]
    
    # Conditionally install Python packages if Python files are detected
    if has_python_files:
        python_commands = generate_python_installation_commands(ubuntu_version)
        setup_commands.extend(python_commands)
        
        # Add Python symlinks
        setup_commands.extend([
            "# Create Python symlinks for compatibility",
            "RUN ln -sf /usr/bin/python3 /usr/bin/python 2>/dev/null || true",
            "RUN ln -sf /usr/bin/pip3 /usr/bin/pip 2>/dev/null || true",
            ""
        ])
    
    # Conditionally install Node.js only if Node.js files are detected
    if has_node_files:
        major_version = int(ubuntu_version.split('.')[0])
        
        if major_version >= 20:
            setup_commands.extend([
                "# Install Node.js (from system packages)",
                "RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \\",
                "    apt-get update && apt-get install -y nodejs npm && \\",
                "    apt-get clean && rm -rf /var/lib/apt/lists/*",
                ""
            ])
        elif major_version >= 18:
            setup_commands.extend([
                "# Install Node.js (from NodeSource for Ubuntu 18.04+)",
                "RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \\",
                "    apt-get install -y nodejs && \\",
                "    apt-get clean && rm -rf /var/lib/apt/lists/*",
                ""
            ])
        else:
            # For Ubuntu 16.04, use older Node.js version
            setup_commands.extend([
                "# Install Node.js (older version for Ubuntu 16.04)",
                "RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash - && \\",
                "    apt-get install -y nodejs && \\",
                "    apt-get clean && rm -rf /var/lib/apt/lists/* || \\",
                "    (apt-get update && apt-get install -y nodejs npm || true)",
                ""
            ])
    
    # 32-bit specific additional packages if needed
    if architecture == '32':
        setup_commands.extend([
            "# Add additional 32-bit specific packages", 
            "RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \\",
            "    apt-get update && apt-get install --no-install-recommends -yqq \\",
            "        lib32gcc-s1 \\",
            "        lib32stdc++6 \\",
            "        libgcc1:i386 \\",
            "        libpam0g:i386 \\", 
            "    && apt-get clean && rm -rf /var/lib/apt/lists/*",
            "",
            "# Create a custom stdbuf wrapper for 32-bit binaries",
            "RUN echo '#!/bin/bash' > /usr/local/bin/stdbuf32 && \\",
            "    echo '# Custom stdbuf wrapper for 32-bit binaries' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '# This avoids the ELF class mismatch error by using alternative methods' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '' >> /usr/local/bin/stdbuf32 && \\",
            "    echo 'if [[ \"$1\" == \"-i0\" && \"$2\" == \"-o0\" && \"$3\" == \"-e0\" ]]; then' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    shift 3' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    # Use environment variables to achieve unbuffered I/O' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    export GLIBC_TUNABLES=glibc.stdio.unbuffered=1' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    export _POSIX_C_SOURCE=200809L' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    exec \"$@\"' >> /usr/local/bin/stdbuf32 && \\",
            "    echo 'else' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    # Fallback to regular stdbuf for non-standard usage' >> /usr/local/bin/stdbuf32 && \\",
            "    echo '    exec stdbuf \"$@\"' >> /usr/local/bin/stdbuf32 && \\",
            "    echo 'fi' >> /usr/local/bin/stdbuf32 && \\",
            "    chmod +x /usr/local/bin/stdbuf32",
            ""
        ])
    
    return '\n'.join(setup_commands)

def generate_python_installation_commands(ubuntu_version: str) -> List[str]:
    """
    Generate Python package installation commands based on Ubuntu version.
    Returns list of command strings with proper error handling.
    """
    version_parts = ubuntu_version.split('.')
    major_version = int(version_parts[0])
    
    commands = []
    
    if major_version >= 20:
        # Modern Python 3.8+ with recent pip
        commands.extend([
            "# Install Python packages (modern)",
            "RUN python3 -m pip install --upgrade pip && \\",
            "    python3 -m pip install flask requests pycryptodome pycryptodomex argon2-cffi psutil tqdm construct lxml && \\",
            "    (python3 -m pip install 'git+https://github.com/Gallopsled/pwntools#egg=pwntools' || true)",
            ""
        ])
    elif major_version >= 18:
        # Python 3.6-3.7, use compatible pip version
        commands.extend([
            "# Install Python packages (compatible)",
            "RUN python3 -m pip install --upgrade 'pip<21.0' && \\",
            "    python3 -m pip install flask requests pycryptodome pycryptodomex argon2-cffi psutil tqdm construct lxml && \\",
            "    (python3 -m pip install 'git+https://github.com/Gallopsled/pwntools#egg=pwntools' || true)",
            ""
        ])
    else:
        # Python 3.5 (Ubuntu 16.04), use very old pip and minimal packages
        commands.extend([
            "# Install Python packages (legacy - Python 3.5)",
            "RUN (python3 -m pip install --upgrade 'pip<10.0') || \\",
            "    (curl https://bootstrap.pypa.io/pip/3.5/get-pip.py -o get-pip.py && \\",
            "     python3 get-pip.py 'pip<10.0' && \\",
            "     rm get-pip.py) || \\",
            "    (apt-get update && apt-get install -y python3-pip || true) && \\",
            "    (python3 -m pip install flask || apt-get install -y python3-flask || true) && \\",
            "    (python3 -m pip install requests || apt-get install -y python3-requests || true) && \\",
            "    (python3 -m pip install pycryptodome || apt-get install -y python3-crypto || true)",
            ""
        ])
    
    return commands

# Add new function after the existing helper functions, around line 1200
def detect_python_files(task_path: str, available_files: List[str]) -> bool:
    """
    Detect if there are Python files in the task.
    Returns True if Python files are found, False otherwise.
    """
    if not available_files:
        return False
        
    task_dir = Path(task_path)
    
    for file_path in available_files:
        full_path = task_dir / file_path
        
        # Check by file extension first
        if file_path.lower().endswith('.py'):
            return True
            
        # Check by content analysis
        if analyze_executable_content(full_path) == 'python':
            return True
            
        # Check for Python shebang
        try:
            if full_path.exists() and full_path.is_file():
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('#!') and 'python' in first_line.lower():
                        return True
        except Exception:
            continue
            
    return False

def detect_custom_interpreter_paths(task_path: str, available_files: List[str], verbose: bool = False) -> Dict[str, str]:
    """
    Detect binaries with custom interpreter paths that need to be fixed.
    Returns dict mapping binary_path -> custom_interpreter_path.
    """
    custom_interpreters = {}
    task_dir = Path(task_path)
    
    # Standard interpreter paths that should be OK
    standard_interpreters = {
        '/lib/ld-linux.so.2',           # 32-bit
        '/lib32/ld-linux.so.2',         # 32-bit alternative
        '/lib64/ld-linux-x86-64.so.2', # 64-bit
        '/lib/ld-linux-x86-64.so.2',   # 64-bit alternative
    }
    
    for file_path in available_files:
        full_path = task_dir / file_path
        
        # Only check binary files
        try:
            content_type = analyze_executable_content(full_path)
            if content_type != 'binary':
                continue
                
            # Use readelf to check interpreter
            result = subprocess.run(['readelf', '-l', str(full_path)], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Look for INTERP section in readelf output
                for line in result.stdout.split('\n'):
                    if 'INTERP' in line:
                        # Extract interpreter path from the line
                        # Format: "      [Requesting program interpreter: /path/to/interpreter]"
                        if 'Requesting program interpreter:' in line:
                            interpreter_path = line.split('Requesting program interpreter:')[1].strip().rstrip(']')
                            
                            if interpreter_path not in standard_interpreters:
                                # Check if the interpreter contains paths that won't exist in container
                                problematic_patterns = ['/nix/store/', '/opt/pwn.college/', '/usr/local/']
                                if any(pattern in interpreter_path for pattern in problematic_patterns):
                                    custom_interpreters[file_path] = interpreter_path
                                    if verbose:
                                        print(f"{YELLOW}Found custom interpreter: {file_path} -> {interpreter_path}{RESET}")
                        break
                        
        except Exception as e:
            # Skip files that can't be analyzed
            continue
    
    return custom_interpreters

def generate_interpreter_fix_commands(custom_interpreters: Dict[str, str], architecture: str = "64") -> List[str]:
    """
    Generate patchelf commands to fix custom interpreter paths.
    Returns list of commands to be added to Dockerfile.
    """
    if not custom_interpreters:
        return []
    
    commands = []
    commands.append("# Fix custom interpreter paths")
    
    # Map to standard interpreter paths
    standard_interpreter_32 = "/lib/ld-linux.so.2"
    standard_interpreter_64 = "/lib64/ld-linux-x86-64.so.2"
    
    for binary_path, custom_interpreter in custom_interpreters.items():
        # Determine if it's 32-bit or 64-bit based on the custom interpreter
        if 'x86-64' in custom_interpreter or '64' in custom_interpreter:
            target_interpreter = standard_interpreter_64
        else:
            target_interpreter = standard_interpreter_32
            
        commands.append(f"    patchelf --set-interpreter {target_interpreter} /challenge/{binary_path}")
    
    return commands

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

def detect_node_files(task_path: str, available_files: List[str]) -> bool:
    """
    Detect if there are Node.js files in the task.
    Returns True if Node.js files are found, False otherwise.
    """
    if not available_files:
        return False
        
    task_dir = Path(task_path)
    
    for file_path in available_files:
        full_path = task_dir / file_path
        
        # Check by file extension first
        if file_path.lower().endswith(('.js', '.mjs', '.ts')):
            return True
            
        # Check for package.json or other Node.js specific files
        if file_path.lower() in ['package.json', 'package-lock.json', '.nvmrc', 'yarn.lock']:
            return True
            
        # Check by content analysis
        if analyze_executable_content(full_path) == 'node':
            return True
            
        # Check for Node.js shebang
        try:
            if full_path.exists() and full_path.is_file():
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('#!') and ('node' in first_line.lower() or 'nodejs' in first_line.lower()):
                        return True
        except Exception:
            continue
            
    return False

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
        if not os.path.exists(args.template_path):
            print(f"{RED}Template directory not found: {args.template_path}{RESET}")
            return
        
        if args.verbose:
            print(f"{BLUE}Copying {args.template_path} to {ctf_archive_path}...{RESET}")
        
        try:
            shutil.copytree(args.template_path, ctf_archive_path)
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