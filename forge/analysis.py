# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

"""
Analysis helpers extracted from ctf_forge.py to improve modularity.

Functions here are pure utilities without external side effects, intended to be
imported by the main orchestration script.
"""

from pathlib import Path
from typing import List, Tuple

import re


def analyze_executable_content(file_path: Path) -> str:
    """
    Analyze file content to determine executable type (script vs binary).
    Returns one of: 'binary', 'python', 'node', 'php', 'ruby', 'perl', 'lua', 'shell'
    """
    try:
        if not file_path.exists() or not file_path.is_file():
            return 'binary'

        # First, check for binary file signatures before attempting text analysis
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

                # Check for common binary formats first
                if header.startswith(b'\x7fELF'):
                    return 'binary'  # ELF executable
                elif header.startswith(b'MZ'):
                    return 'binary'  # PE executable
                elif header.startswith(b'\xca\xfe\xba\xbe'):
                    return 'binary'  # Mach-O executable
                elif header.startswith(b'\x89PNG'):
                    return 'binary'  # PNG image
                elif header.startswith(b'\xff\xd8\xff'):
                    return 'binary'  # JPEG image
                elif header.startswith(b'PK'):
                    return 'binary'  # ZIP/archive file

                # Check for null bytes (strong indicator of binary file)
                f.seek(0)
                chunk = f.read(1024)  # Read first 1KB
                if b'\x00' in chunk:
                    return 'binary'

                # Check if the content has too many non-printable characters
                printable_chars = sum(1 for b in chunk if 32 <= b <= 126 or b in [9, 10, 13])
                if len(chunk) > 0 and printable_chars / len(chunk) < 0.7:
                    return 'binary'

        except Exception:
            # If binary reading fails, assume binary
            return 'binary'

        # If not clearly binary, try text analysis
        try:
            with open(file_path, 'r', encoding='utf-8') as f:  # Removed errors='ignore'
                # Read first few lines to check for script indicators
                first_lines = []
                for _ in range(10):  # Read up to 10 lines
                    line = f.readline()
                    if not line:
                        break
                    first_lines.append(line.strip())

                content_start = '\n'.join(first_lines).lower()

                # Check for shebang lines first (most reliable)
                if first_lines and first_lines[0].startswith('#!'):
                    shebang = first_lines[0].lower()
                    if 'python' in shebang:
                        return 'python'
                    elif 'node' in shebang or 'js' in shebang:
                        return 'node'
                    elif 'php' in shebang:
                        return 'php'
                    elif 'ruby' in shebang:
                        return 'ruby'
                    elif 'perl' in shebang:
                        return 'perl'
                    elif 'lua' in shebang:
                        return 'lua'
                    elif any(shell in shebang for shell in ['bash', 'sh', 'zsh', 'dash']):
                        return 'shell'

                # Check for script patterns in content
                # Enhanced Python detection patterns
                python_patterns = [
                    'import ', 'from ', 'def ', 'class ', 'if __name__',
                    'print(', 'print ', 'len(', 'str(', 'int(', 'list(',
                    'range(', 'open(', 'with open', 'for ', 'while ',
                    'try:', 'except:', 'finally:', 'else:', 'elif ',
                    '__init__', 'self.', 'return ', 'yield ', 'lambda ',
                    'isinstance(', 'hasattr(', 'getattr(', 'setattr('
                ]

                if any(pattern in content_start for pattern in python_patterns):
                    return 'python'
                elif any(pattern in content_start for pattern in ['require(', 'const ', 'let ', 'var ', 'function(']):
                    return 'node'
                elif any(pattern in content_start for pattern in ['<?php', 'echo ', '$_GET', '$_POST']):
                    return 'php'
                elif any(pattern in content_start for pattern in ['require ', 'class ', 'def ', 'end']):
                    return 'ruby'
                elif any(pattern in content_start for pattern in ['use ', 'my $', 'sub ', 'print ']):
                    return 'perl'
                elif any(pattern in content_start for pattern in ['function ', 'local ', 'require']):
                    return 'lua'
                elif any(pattern in content_start for pattern in ['#!/bin/sh', '#!/bin/bash', 'echo ', 'if [', 'for ']):
                    return 'shell'

                # Check if the content looks like readable text (could be a script without clear indicators)
                # Read more content to make a better decision
                f.seek(0)
                sample = f.read(1024)  # Read first 1KB

                # Check if it's mostly printable ASCII (likely a script)
                printable_chars = sum(1 for c in sample if c.isprintable() or c in '\n\r\t')
                if len(sample) > 0 and printable_chars / len(sample) > 0.8:
                    # It's likely a text file/script, but we couldn't determine the type
                    # Check file extension as fallback
                    name = file_path.name.lower()
                    if name.endswith('.py'):
                        return 'python'
                    elif name.endswith(('.js', '.mjs')):
                        return 'node'
                    elif name.endswith('.php'):
                        return 'php'
                    elif name.endswith(('.sh', '.bash')):
                        return 'shell'
                    elif name.endswith('.rb'):
                        return 'ruby'
                    elif name.endswith('.pl'):
                        return 'perl'
                    elif name.endswith('.lua'):
                        return 'lua'
                    else:
                        # Default to shell script for unknown text files
                        return 'shell'

        except UnicodeDecodeError:
            # File is not readable as UTF-8 text, it's binary
            return 'binary'

        # Default to binary if we can't determine
        return 'binary'

    except Exception:
        # If any error occurs, assume it's binary
        return 'binary'


def detect_elf_architecture(file_path: Path) -> str:
    """
    Detect if an ELF binary is 32-bit or 64-bit.
    Returns: '32', '64', or 'unknown'
    """
    try:
        if not file_path.exists() or not file_path.is_file():
            return 'unknown'

        with open(file_path, 'rb') as f:
            # Read ELF header
            header = f.read(64)  # ELF header is 64 bytes

            # Check if it's an ELF file
            if not header.startswith(b'\x7fELF'):
                return 'unknown'

            # Get architecture class from e_ident[EI_CLASS] (byte 4)
            # ELFCLASS32 = 1, ELFCLASS64 = 2
            elf_class = header[4]

            if elf_class == 1:
                return '32'
            elif elf_class == 2:
                return '64'

        return 'unknown'

    except Exception:
        return 'unknown'


def get_binary_architecture(task_path: str, task_files: List[str]) -> Tuple[str, List[str]]:
    """
    Analyze all binary files in the task to determine if we need 32-bit or 64-bit environment.
    Returns: (architecture, relevant_binary_files)
    - architecture: '32', '64', or 'unknown'
    - relevant_binary_files: list of binary files that should be processed
    """
    task_dir = Path(task_path)
    files_32bit = []
    files_64bit = []

    for file_path in task_files:
        full_path = task_dir / file_path

        # First check if it's a binary
        content_type = analyze_executable_content(full_path)
        if content_type == 'binary':
            arch = detect_elf_architecture(full_path)
            if arch == '32':
                files_32bit.append(file_path)
            elif arch == '64':
                files_64bit.append(file_path)

    # Priority logic: if 32-bit files exist, focus only on them and ignore 64-bit
    if files_32bit:
        return '32', files_32bit
    elif files_64bit:
        return '64', files_64bit
    else:
        # Default to 64-bit if no specific architecture is detected
        return '64', []


def analyze_python_server_script(file_path: Path) -> Tuple[bool, int | None, str]:
    """
    Analyze a Python script to check if it's a network server.
    Returns (is_server, port, content).
    """
    try:
        if not file_path.exists() or not file_path.is_file():
            return False, None, ""

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Check for server-related imports
        is_server = ('socketserver' in content or
                     'socket' in content or
                     'threading' in content or
                     'asyncio' in content)

        if not is_server:
            return False, None, content

        # Try to find the port number
        port = None
        # Common patterns for port definition
        # e.g., port = 8080 or ("0.0.0.0", 8080)
        port_patterns = [
            r'port\s*=\s*(\d+)',
            r'listen\(\s*(\d+)\)',
            r'bind\(\s*\([^,]+,\s*(\d+)\s*\)\s*\)',
            r'host,\s*port\s*=\s*[^,]+,\s*(\d+)',
            r'server_address\s*=\s*\([^,]+,\s*(\d+)\s*\)'
        ]

        for pattern in port_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                break

        return True, port, content

    except Exception:
        return False, None, ""


