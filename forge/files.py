# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

"""
File discovery and metadata helpers extracted from ctf_forge.py to improve modularity.
"""

from pathlib import Path
from typing import Dict, List, Optional
import os
import yaml
import stat
import mimetypes
from typing import Optional as _Optional


def has_required_files(directory: str) -> bool:
    """Check if directory contains both REHOST.md and DESCRIPTION.md files."""
    try:
        files = os.listdir(directory)

        has_rehost = 'REHOST.md' in files
        has_description = 'DESCRIPTION.md' in files

        return has_rehost and has_description

    except (OSError, PermissionError):
        return False


def find_task_directories(base_dir: str) -> List[str]:
    """Find all task directories that contain required files."""
    task_dirs_with_files = []

    for root, dirs, files in os.walk(base_dir):
        if root == base_dir:
            continue

        # Skip hidden directories (those starting with a dot)
        path_parts = Path(root).parts
        skip_directory = False
        for part in path_parts:
            if part.startswith('.'):
                skip_directory = True
                break

        if not skip_directory and has_required_files(root):
            task_dirs_with_files.append(root)

    return sorted(task_dirs_with_files)


def read_description(task_path: str) -> str:
    """Read task description from DESCRIPTION.md file."""
    desc_file = Path(task_path) / "DESCRIPTION.md"
    if desc_file.exists():
        try:
            with open(desc_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                # Remove markdown formatting and author info
                lines = content.split('\n')
                description_lines = []
                for line in lines:
                    line = line.strip()
                    if line.startswith('---') or line.startswith('**Author:**'):
                        break
                    if line and not line.startswith('#'):
                        description_lines.append(line)
                return ' '.join(description_lines)
        except Exception:
            pass

    return ""


def read_rehost_content(task_path: str) -> str:
    """Read REHOST.md file content."""
    rehost_file = Path(task_path) / "REHOST.md"
    if rehost_file.exists():
        try:
            with open(rehost_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                return content
        except Exception:
            pass

    return ""


def read_init_content(task_path: str) -> str:
    """Read .init file content if it exists."""
    init_file = Path(task_path) / ".init"
    if init_file.exists():
        try:
            with open(init_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                return content
        except Exception:
            pass

    return ""


def get_category_from_module_yml(task_path: str) -> Optional[str]:
    """Get category information from module.yml in the parent directory."""
    task_dir = Path(task_path)
    parent_dir = task_dir.parent
    module_yml = parent_dir / "module.yml"

    if not module_yml.exists():
        return None

    try:
        with open(module_yml, 'r', encoding='utf-8') as f:
            module_data = yaml.safe_load(f)

        if not module_data or 'challenges' not in module_data:
            return None

        task_name = task_dir.name
        for challenge in module_data['challenges']:
            if challenge.get('id') == task_name:
                name = challenge.get('name', '')
                if ' - ' in name:
                    category_part = name.split(' - ')[0].strip().upper()
                    category_mapping = {
                        'PWN': 'pwn',
                        'CRYPTO': 'crypto',
                        'CRYTPO': 'crypto',
                        'WEB': 'web',
                        'REV': 'rev',
                        'REVERSE': 'rev',
                        'FORENSICS': 'forensics',
                        'STEGO': 'forensics',
                        'MISC': 'misc',
                        'LOGICAL': 'misc',
                        'EXPLOIT': 'pwn',
                        'EXPLOITATION': 'pwn',
                        'BINARY': 'pwn',
                        'BINARY EXPLOITATION': 'pwn',
                        'VULNERABILITY': 'pwn',
                        'ROP': 'pwn',
                        'TRIVIA': 'misc',
                        'OSINT': 'misc',
                        'RECON': 'misc',
                        'RADIO FREQUENCY': 'misc',
                        'SOCIAL ENGINEERING': 'misc',
                        'BLOCKCHAIN': 'misc',
                        'WWW': 'web',
                        'PWN/MISC': 'misc',
                        'WARMUP': 'misc',
                        'PRIVATE': 'misc',
                        'CLUELESS': 'misc',
                        'FRNG': 'misc',
                        'RNG': 'misc',
                        'NUMBERSLEUTHV1': 'misc',
                        'NUMBERSLEUTHV2': 'misc',
                        'NUMBERSLEUTHV3': 'misc',
                        'SECUREREPITITIONS': 'misc'
                    }
                    return category_mapping.get(category_part, 'misc')

        return None
    except Exception:
        return None


def extract_task_info(task_path: str) -> Optional[Dict]:
    """Extract task information from path and create task data structure."""
    path_parts = Path(task_path).parts

    if len(path_parts) >= 3:
        event = path_parts[1]

        if len(path_parts) >= 4:
            task_name = path_parts[3]
        else:
            task_name = path_parts[2]

        category = get_category_from_module_yml(task_path)

        task_data = {
            "task_name": task_name,
            "task_path": task_path,
            "ctf_name": event,
            "category": category,
            "description": read_description(task_path),
            "rehost_content": read_rehost_content(task_path),
            "init_content": read_init_content(task_path),
        }

        return task_data

    return None


def filter_out_patched_files(files: List[str]) -> List[str]:
    """
    Filter out patched files when both original and patched versions exist.
    If both 'x' and 'x_patched' exist, choose 'x' and exclude 'x_patched'.
    """
    file_set = set(files)
    filtered_files = []

    for file_path in files:
        if file_path.endswith('_patched'):
            original_file = file_path[:-8]
            if original_file in file_set:
                continue
        filtered_files.append(file_path)

    return filtered_files


def get_task_files(task_path: str) -> List[str]:
    """Get list of files in the task directory, excluding certain patterns."""
    exclude_patterns = {"REHOST.md", "DESCRIPTION.md", "README.md", ".git", "Dockerfile", "docker-compose.yml", "Users", "Cryptodome"}

    files: List[str] = []
    task_dir = Path(task_path)

    if not task_dir.exists():
        return files

    try:
        for item in task_dir.rglob("*"):
            if any(part in exclude_patterns for part in item.parts):
                continue

            if item.is_file():
                relative_path = item.relative_to(task_dir)
                if relative_path.name not in exclude_patterns:
                    files.append(str(relative_path))
    except Exception:
        pass

    files = filter_out_patched_files(files)
    return sorted(files)


def get_file_type_info(file_path: Path) -> str:
    """Get detailed file type information for a file."""
    try:
        if not file_path.exists():
            return "missing file"

        if file_path.is_dir():
            return "directory"

        size = file_path.stat().st_size
        size_str = f"{size} bytes"
        if size > 1024:
            size_str = f"{size//1024} KB"
        if size > 1024*1024:
            size_str = f"{size//(1024*1024)} MB"

        file_stat = file_path.stat()
        is_executable = bool(file_stat.st_mode & stat.S_IEXEC)

        mime_type, _ = mimetypes.guess_type(str(file_path))

        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        file_type = "unknown"

        if is_executable and suffix == "":
            file_type = "executable binary"
        elif suffix in ['.py', '.js', '.php', '.rb', '.pl', '.sh', '.bat']:
            file_type = f"{suffix[1:]} script"
        elif suffix in ['.txt', '.md', '.rst']:
            file_type = "text file"
        elif suffix in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
            file_type = "C/C++ source"
        elif suffix in ['.java']:
            file_type = "Java source"
        elif suffix in ['.html', '.htm']:
            file_type = "HTML file"
        elif suffix in ['.css']:
            file_type = "CSS file"
        elif suffix in ['.json']:
            file_type = "JSON file"
        elif suffix in ['.xml']:
            file_type = "XML file"
        elif suffix in ['.sql']:
            file_type = "SQL file"
        elif suffix in ['.yml', '.yaml']:
            file_type = "YAML file"
        elif suffix in ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z']:
            file_type = "archive file"
        elif suffix in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']:
            file_type = "image file"
        elif suffix in ['.pdf']:
            file_type = "PDF file"
        elif suffix in ['.exe', '.dll']:
            file_type = "Windows executable"
        elif suffix in ['.so']:
            file_type = "shared library"
        elif suffix in ['.a']:
            file_type = "static library"
        elif suffix in ['.o']:
            file_type = "object file"
        elif mime_type:
            if mime_type.startswith('text/'):
                file_type = "text file"
            elif mime_type.startswith('image/'):
                file_type = "image file"
            elif mime_type.startswith('application/'):
                file_type = f"application file ({mime_type.split('/')[-1]})"

        exec_flag = " (executable)" if is_executable else ""
        return f"{file_type}{exec_flag} - {size_str}"

    except Exception as e:
        return f"error reading file: {str(e)}"


def get_task_files_with_info(task_path: str) -> str:
    """Get formatted string with file information for all task files."""
    exclude_patterns = {"REHOST.md", "DESCRIPTION.md", "README.md", ".git", "Dockerfile", "docker-compose.yml"}

    files_info: List[str] = []
    task_dir = Path(task_path)

    if not task_dir.exists():
        return "No files found"

    try:
        all_files = []
        for item in task_dir.rglob("*"):
            if item.is_file():
                relative_path = item.relative_to(task_dir)
                if relative_path.name not in exclude_patterns:
                    all_files.append((relative_path, item))

        if not all_files:
            return "No files found"

        file_paths = [str(rel_path) for rel_path, _ in all_files]
        filtered_paths = filter_out_patched_files(file_paths)
        filtered_path_set = set(filtered_paths)

        all_files = [(rel_path, item) for rel_path, item in all_files if str(rel_path) in filtered_path_set]

        all_files.sort(key=lambda x: str(x[0]))

        files_to_show = all_files[:10]

        for relative_path, item in files_to_show:
            file_info = get_file_type_info(item)
            files_info.append(f"  - {relative_path}: {file_info}")

        if len(all_files) > 10:
            files_info.append(f"  ... and {len(all_files) - 10} more files")

        return "\n".join(files_info)

    except Exception as e:
        return f"Error reading directory: {str(e)}"


def find_sha256_file(task_path: str) -> _Optional[str]:
    """Find and read sha256 file content from task directory."""
    task_dir = Path(task_path)

    sha256_files = ['flag.sha256', '.flag.sha256', 'flag.sha256.txt']

    for filename in sha256_files:
        sha256_file = task_dir / filename
        if sha256_file.exists() and sha256_file.is_file():
            try:
                with open(sha256_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    return content
            except Exception:
                pass

    return None


def find_check_file(task_path: str) -> _Optional[str]:
    """Find check file and return its absolute path."""
    task_dir = Path(task_path)

    try:
        for file_path in task_dir.rglob("*"):
            if any(part in ["Users", "Cryptodome"] for part in file_path.parts):
                continue
            if file_path.is_file() and 'check' in file_path.name.lower():
                return str(file_path.absolute())
    except Exception:
        pass

    return None


