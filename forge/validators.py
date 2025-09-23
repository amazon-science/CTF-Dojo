# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

from __future__ import annotations
from typing import List, Tuple
import fnmatch


def fix_dockerfile_trailing_backslashes(dockerfile_content: str) -> tuple[str, List[str]]:
    """
    Fix problematic trailing backslashes in Dockerfiles that cause build failures.
    Returns (fixed_dockerfile, list_of_fixes_made).
    """
    lines = dockerfile_content.split('\n')
    fixed_lines = []
    fixes_made = []

    docker_commands = ['FROM', 'RUN', 'COPY', 'ADD', 'WORKDIR', 'ENV', 'EXPOSE', 'CMD', 'ENTRYPOINT', 'USER', 'VOLUME', 'LABEL', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL']

    for i, line in enumerate(lines):
        current_line = line
        line_stripped = line.strip()

        if line_stripped.endswith('\\'):
            next_line_idx = i + 1
            while next_line_idx < len(lines) and not lines[next_line_idx].strip():
                next_line_idx += 1

            if next_line_idx < len(lines):
                next_line = lines[next_line_idx].strip()
                if any(next_line.upper().startswith(cmd) for cmd in docker_commands):
                    current_line = line.rstrip().rstrip('\\').rstrip()
                    fixes_made.append(f"Line {i+1}: Removed problematic trailing backslash before {next_line.split()[0]} command")

        fixed_lines.append(current_line)

    return '\n'.join(fixed_lines), fixes_made


def _expand_dockerfile_source_pattern(source_pattern: str, available_files: List[str]) -> List[str]:
    """Expand a Dockerfile COPY/ADD source pattern to matching files from available_files."""
    matched_files: List[str] = []

    if source_pattern in ['.', './']:
        return available_files

    if source_pattern.endswith('/'):
        dir_prefix = source_pattern.rstrip('/')
        if dir_prefix == '':
            return available_files
        for file_path in available_files:
            if file_path.startswith(dir_prefix + '/') or file_path == dir_prefix:
                matched_files.append(file_path)
        return matched_files

    if '*' in source_pattern or '?' in source_pattern:
        for file_path in available_files:
            if fnmatch.fnmatch(file_path, source_pattern) or fnmatch.fnmatch(file_path.split('/')[-1], source_pattern):
                matched_files.append(file_path)
        return matched_files

    if source_pattern in available_files:
        matched_files.append(source_pattern)
        return matched_files

    directory_files = [f for f in available_files if f.startswith(source_pattern + '/')]
    if directory_files:
        matched_files.extend(directory_files)
        return matched_files

    for available_file in available_files:
        if available_file.endswith('/' + source_pattern) or available_file == source_pattern:
            matched_files.append(available_file)

    return matched_files


def validate_dockerfile(dockerfile_content: str, available_files: List[str], verbose: bool = False) -> tuple[bool, List[str]]:
    """Validate generated Dockerfile content. Returns (is_valid, issues_list)."""
    issues: List[str] = []
    lines = dockerfile_content.strip().split('\n')

    content_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

    if not content_lines:
        issues.append("Empty Dockerfile generated")
        return False, issues

    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if line_stripped.endswith('\\'):
            next_line_idx = i + 1
            while next_line_idx < len(lines) and not lines[next_line_idx].strip():
                next_line_idx += 1
            if next_line_idx < len(lines):
                next_line = lines[next_line_idx].strip()
                docker_commands = ['FROM', 'RUN', 'COPY', 'ADD', 'WORKDIR', 'ENV', 'EXPOSE', 'CMD', 'ENTRYPOINT', 'USER', 'VOLUME', 'LABEL', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL']
                if any(next_line.upper().startswith(cmd) for cmd in docker_commands):
                    issues.append(f"Line {i+1}: Trailing backslash before new Docker command will cause build failure")

    has_from = any(line.upper().startswith('FROM') for line in content_lines)
    has_expose = any(line.upper().startswith('EXPOSE') for line in content_lines)
    has_cmd_or_entrypoint = any(line.upper().startswith(('CMD', 'ENTRYPOINT')) for line in content_lines)

    if not has_from:
        issues.append("Missing FROM instruction")
    if not has_expose:
        issues.append("Missing EXPOSE instruction - challenge needs to be accessible over network")
    if not has_cmd_or_entrypoint:
        issues.append("Missing CMD or ENTRYPOINT - service won't start automatically")

    from_lines = [line for line in content_lines if line.upper().startswith('FROM')]
    if from_lines:
        from_line = from_lines[0].lower()
        if 'ubuntu:20.04' not in from_line:
            acceptable_bases = ['ubuntu:', 'python:', 'node:', 'php:', 'nginx:', 'apache:']
            if not any(base in from_line for base in acceptable_bases):
                issues.append(f"Unusual base image detected: {from_lines[0]} - prefer ubuntu:20.04")

    copy_lines = [line for line in content_lines if line.upper().startswith(('COPY', 'ADD'))]

    for line in copy_lines:
        parts = line.split()
        if len(parts) >= 3:
            if '--from=' in line:
                continue
            source_parts: List[str] = []
            i = 1
            while i < len(parts):
                part = parts[i]
                if part.startswith('--'):
                    if '=' in part:
                        i += 1
                        continue
                    else:
                        i += 2
                        continue
                else:
                    source_parts.append(part)
                    i += 1
            if source_parts:
                source = source_parts[0].strip('\'"')
                matched_files = _expand_dockerfile_source_pattern(source, available_files)
                if not matched_files and source not in ['.', '..', './']:
                    issues.append(f"File pattern '{source}' does not match any available files")

    for line in content_lines:
        line_upper = line.upper()
        if 'FLAG.SHA256' in line_upper or 'FLAGCHECK' in line_upper:
            issues.append("Security issue: trying to copy flag.sha256 or flagcheck files")

    available_extensions = set()
    for file in available_files:
        if '.' in file:
            ext = file.split('.')[-1].lower()
            available_extensions.add(ext)

    dockerfile_content_lower = dockerfile_content.lower()

    if any(ext in ['py'] for ext in available_extensions):
        if 'python' not in dockerfile_content_lower:
            issues.append("Python files detected but no Python installation found")

    executable_files = [f for f in available_files if not f.endswith(('.py', '.js', '.php', '.html', '.css', '.txt', '.md'))]
    if executable_files:
        has_chmod = 'chmod' in dockerfile_content_lower
        if not has_chmod:
            issues.append("Executable files detected but no chmod permissions set")

    web_extensions = ['html', 'php', 'css', 'js']
    if any(ext in web_extensions for ext in available_extensions):
        if not any(server in dockerfile_content_lower for server in ['apache', 'nginx', 'httpd']):
            issues.append("Web files detected but no web server installation found")

    if verbose and issues:
        print(f"Dockerfile validation issues: {issues}")

    return len(issues) == 0, issues


def remove_duplicate_docker_setup(dockerfile_content: str, verbose: bool = False) -> str:
    """
    Remove duplicate Docker setup commands that conflict with the comprehensive setup.
    This prevents issues like duplicate i386 architecture setup and package installations.
    """
    lines = dockerfile_content.split('\n')
    filtered_lines = []

    comprehensive_packages = {
        'socat', 'libc6:i386', 'libstdc++6:i386', 'lib32gcc-s1', 'lib32stdc++6',
        'libgcc1:i386', 'libpam0g:i386', 'libc6-dev-i386', 'libncurses5:i386',
        'build-essential', 'curl', 'wget', 'git', 'gdb', 'strace', 'ltrace',
        'python3', 'python3-pip', 'python3-dev', 'binutils', 'nasm', 'gcc-multilib',
        'g++-multilib', 'patchelf', 'netcat-openbsd', 'vim', 'nano', 'tmux',
        'valgrind', 'binwalk', 'unzip', 'zip', 'p7zip-full', 'file', 'hexedit'
    }

    handled_commands = {
        'dpkg --add-architecture i386',
        'apt-get update'
    }

    problematic_i386_packages = {
        'coreutils:i386',
        'bash:i386',
        'util-linux:i386',
        'base-files:i386'
    }

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith('RUN') and ('dpkg --add-architecture i386' in line or 'coreutils:i386' in line):
            if verbose:
                print(f"Removing duplicate setup command: {line[:50]}...")
            while i < len(lines) and (lines[i].strip().endswith('\\') or lines[i].strip().endswith('&& \\')):
                i += 1
            i += 1
            continue

        elif line.startswith('RUN') and any(pkg in line for pkg in comprehensive_packages):
            install_packages = set()
            if 'apt-get install' in line:
                parts = line.split()
                in_install_section = False
                for part in parts:
                    if part == 'install':
                        in_install_section = True
                        continue
                    if in_install_section and not part.startswith('-'):
                        install_packages.add(part.strip('\\'))
            if install_packages and install_packages.issubset(comprehensive_packages):
                if verbose:
                    print(f"Removing redundant package install: {install_packages}")
                while i < len(lines) and (lines[i].strip().endswith('\\') or lines[i].strip().endswith('&& \\')):
                    i += 1
                i += 1
                continue

        elif line.startswith('RUN') and any(pkg in line for pkg in problematic_i386_packages):
            if verbose:
                problematic_found = [pkg for pkg in problematic_i386_packages if pkg in line]
                print(f"Removing problematic package install: {problematic_found}")
            while i < len(lines) and (lines[i].strip().endswith('\\') or lines[i].strip().endswith('&& \\')):
                i += 1
            i += 1
            continue

        filtered_lines.append(lines[i])
        i += 1

    result = '\n'.join(filtered_lines)
    result = '\n'.join(line for line in result.split('\n') if line.strip() != 'RUN')

    if verbose and len(filtered_lines) < len(lines):
        print(f"Removed {len(lines) - len(filtered_lines)} duplicate setup lines")

    return result


def check_dockerfile_file_existence(dockerfile_content: str, available_files: List[str]) -> List[str]:
    """Check if files being copied in Dockerfile exist in available files. Returns list of non-existing files."""
    non_existing_files: List[str] = []
    lines = dockerfile_content.strip().split('\n')

    copy_lines = [line.strip() for line in lines if line.strip().upper().startswith(('COPY', 'ADD'))]

    for line in copy_lines:
        parts = line.split()
        if len(parts) >= 3:
            if '--from=' in line:
                continue
            source_parts: List[str] = []
            i = 1
            while i < len(parts):
                part = parts[i]
                if part.startswith('--'):
                    if '=' in part:
                        i += 1
                        continue
                    else:
                        i += 2
                        continue
                else:
                    source_parts.append(part)
                    i += 1
            if source_parts:
                source = source_parts[0].strip('\'"')
                matched_files = _expand_dockerfile_source_pattern(source, available_files)
                if not matched_files and source not in ['.', '..', './']:
                    non_existing_files.append(source)

    return non_existing_files


def fix_dockerfile_in_place(dockerfile_path: str, verbose: bool = False) -> bool:
    """
    Fix trailing backslash issues in an existing Dockerfile.
    Returns True if fixes were made, False otherwise.
    """
    try:
        with open(dockerfile_path, 'r') as f:
            original_content = f.read()
        fixed_content, fixes_made = fix_dockerfile_trailing_backslashes(original_content)
        if fixes_made:
            with open(dockerfile_path, 'w') as f:
                f.write(fixed_content)
            if verbose:
                print(f"Fixed {len(fixes_made)} trailing backslash issues in {dockerfile_path}:")
                for fix in fixes_made:
                    print(f"  - {fix}")
            return True
        else:
            if verbose:
                print(f"No trailing backslash issues found in {dockerfile_path}")
            return False
    except Exception as e:
        if verbose:
            print(f"Error fixing Dockerfile {dockerfile_path}: {e}")
        return False
