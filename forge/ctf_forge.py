"""
CTF Forge utility functions for Dockerfile generation and challenge analysis.
"""

import subprocess
import re
import time
import tempfile
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Any

import litellm
from litellm import completion

from forge.analysis import (
    analyze_executable_content,
    detect_elf_architecture,
    get_binary_architecture,
    analyze_python_server_script,
)
from forge.files import get_file_type_info

# Color codes for terminal output
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
            error_str = str(e)
            if "long" in error_str:
                return None
            # Don't retry on BadRequestError (e.g., wrong provider) - it won't fix itself
            if "BadRequestError" in error_str or "LLM Provider NOT provided" in error_str:
                print(f"Error: {e}")
                raise
            print(f"Error: {e}")
            attempt += 1
            if attempt == max_retries:
                raise
            wait_time = 10
            time.sleep(wait_time)


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


def test_binary_library_configurations(task_path: str, binary_files: List[str], provided_libs: Dict[str, str], verbose: bool = False) -> Dict[str, Any]:
    """
    Test different library configurations to determine which one works.
    Returns dict with working configuration and commands needed.
    """
    import tempfile
    import shutil
    
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


# Re-export get_binary_architecture from forge.analysis
def get_binary_architecture(task_path: str, task_files: List[str]) -> tuple[str, List[str]]:
    """Re-export from forge.analysis"""
    from forge.analysis import get_binary_architecture as _gba
    return _gba(task_path, task_files)


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


def get_ubuntu_version_from_base_image(base_image: str) -> str:
    """
    Extract Ubuntu version from base image string.
    Returns version like "16.04", "18.04", "20.04", etc.
    """
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
    
    return {
        "base": base_packages,
        "development": dev_packages,
        "tools": tools_packages,
        "version_specific": version_specific_packages,
        "python": python_packages,
        "java": java_packages,
    }


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
