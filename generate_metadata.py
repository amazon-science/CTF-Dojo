#!/usr/bin/env python3


# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

import os
import json
import argparse
from pathlib import Path
import multiprocessing as mp

def has_sha256_file(directory):
    """Check if directory contains any of the expected SHA256 files."""
    try:
        files = os.listdir(directory)
        sha256_files = ['flag.sha256', '.flag.sha256', 'flag.sha256.txt']
        
        return any(sha256_file in files for sha256_file in sha256_files)
        
    except (OSError, PermissionError):
        return False

def has_flagcheck_file(directory):
    """Check if directory contains any files with 'flagcheck' in the name."""
    try:
        for root, _, files in os.walk(directory):
            if any('flagcheck' in file.lower() for file in files):
                return True
        return False
    except (OSError, PermissionError):
        return False

def has_compose_true(directory):
    """Check if challenge.json exists and has compose set to true."""
    try:
        challenge_json_path = os.path.join(directory, "challenge.json")
        if not os.path.exists(challenge_json_path):
            return False
        
        with open(challenge_json_path, 'r', encoding='utf-8') as f:
            challenge_info = json.load(f)
            return challenge_info.get('compose', False) is True
            
    except (OSError, PermissionError, json.JSONDecodeError):
        return False

def has_required_files(directory, require_sha256=False, skip_sha256=False, skip_flagcheck=False, require_compose=False):
    """Check if directory contains both REHOST.md and DESCRIPTION.md files, and optionally filter based on SHA256, flagcheck, and compose files."""
    try:
        files = os.listdir(directory)
        
        # Check for both REHOST.md and DESCRIPTION.md (exact match)
        has_rehost = 'REHOST.md' in files
        has_description = 'DESCRIPTION.md' in files
        
        basic_requirements = has_rehost and has_description
        
        if not basic_requirements:
            return False

        if skip_flagcheck and has_flagcheck_file(directory):
            return False
            
        if require_compose and not has_compose_true(directory):
            return False
            
        if require_sha256:
            return basic_requirements and has_sha256_file(directory)
        elif skip_sha256:
            return basic_requirements and not has_sha256_file(directory)
        else:
            return basic_requirements
        
    except (OSError, PermissionError):
        return False

def read_challenge_info(challenge_path):
    """Read challenge.json and extract basic info."""
    try:
        with open(challenge_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {challenge_path}: {e}")
        return {}

def check_directory_files(args_tuple):
    """Helper function for multiprocessing - returns tuple of (directory, has_files)."""
    directory, require_sha256, skip_sha256, skip_flagcheck, require_compose = args_tuple
    return directory, has_required_files(directory, require_sha256, skip_sha256, skip_flagcheck, require_compose)

def find_task_directories(base_dir, require_sha256=False, skip_sha256=False, skip_flagcheck=False, require_compose=False, num_workers=32):
    """Find all task directories that contain required files using parallel processing."""
    task_dirs_with_files = []
    task_dirs_without_files = []
    all_directories = []
    
    # Collect all directories first
    for root, dirs, files in os.walk(base_dir):
        # Skip the base directory itself and only check subdirectories
        if root == base_dir:
            continue
            
        # Skip hidden directories (those starting with a dot)
        path_parts = Path(root).parts
        skip_directory = False
        for part in path_parts:
            if part.startswith('.'):
                skip_directory = True
                break
        
        if not skip_directory:
            all_directories.append(root)
    
    total_dirs = len(all_directories)
    filter_msg = ""
    if require_sha256:
        filter_msg = " (with SHA256 filter)"
    elif skip_sha256:
        filter_msg = " (skipping SHA256 tasks)"
    if skip_flagcheck:
        filter_msg += " (skipping flagcheck tasks)"
    if require_compose:
        filter_msg += " (requiring compose=true)"
    
    print(f"Processing {total_dirs} directories with {num_workers} workers{filter_msg} (skipping hidden directories)...")
    
    # Process directories in parallel
    # Pass both directory and filtering flags to each worker
    args_list = [(directory, require_sha256, skip_sha256, skip_flagcheck, require_compose) for directory in all_directories]
    with mp.Pool(num_workers) as pool:
        results = pool.map(check_directory_files, args_list)
    
    # Separate directories with and without required files
    for directory, has_files in results:
        if has_files:
            task_dirs_with_files.append(directory)
        else:
            task_dirs_without_files.append(directory)
    
    return sorted(task_dirs_with_files), sorted(task_dirs_without_files)

def extract_task_info(task_path):
    """Extract information from task path."""
    path_parts = Path(task_path).parts
    
    # Expected structure: ctf-archive/event/task_name or ctf-archive/event/category/task_name
    if len(path_parts) >= 3:
        event = path_parts[1]  # CTF event name (e.g., "0ctf2017" from "ctf-archive/0ctf2017/easiestprintf")
        
        if len(path_parts) >= 4:
            # Structure: ctf-archive/event/category/task_name
            category = path_parts[2]
            task_name = path_parts[3]
            return event, category, task_name
        else:
            # Structure: ctf-archive/event/task_name
            task_name = path_parts[2]
            return event, None, task_name
    
    return None, None, None

def generate_ctf_archive_dataset(base_dir="ctf-archive", require_sha256=False, skip_sha256=False, skip_flagcheck=False, require_compose=False):
    """Generate dataset for CTF archive challenges."""
    
    if not os.path.exists(base_dir):
        print(f"Error: {base_dir} directory not found")
        return {}
    
    task_dirs_with_files, task_dirs_without_files = find_task_directories(base_dir, require_sha256, skip_sha256, skip_flagcheck, require_compose)
    
    dataset = {}
    
    for task_dir in task_dirs_with_files:
        event, path_category, task_name = extract_task_info(task_dir)
        
        if not event or not task_name:
            print(f"Skipping directory (invalid structure): {task_dir}")
            continue
        
        # Read challenge.json if it exists to get category
        challenge_json_path = os.path.join(task_dir, "challenge.json")
        category = None
        challenge_name = task_name  # Default to directory name
        
        if os.path.exists(challenge_json_path):
            challenge_info = read_challenge_info(challenge_json_path)
            category = challenge_info.get('category', path_category)
            challenge_name = challenge_info.get('name', task_name)
        else:
            category = path_category
        
        # Create key in format: ca-event-taskname (ca = ctf-archive)
        safe_task_name = task_name.replace(' ', '_').replace('[', '').replace(']', '').lower()
        safe_event = event.replace(' ', '_').lower()
        
        if category:
            safe_category = category.replace(' ', '_').lower()
            key = f"ca-{safe_event}-{safe_category}-{safe_task_name}"
        else:
            key = f"ca-{safe_event}-{safe_task_name}"
        
        # Build dataset entry
        entry = {
            "benchmark": "ctf-archive",
            "event": event,
            "challenge": challenge_name,
            "path": task_dir
        }
        
        if category:
            entry["category"] = category
        
        dataset[key] = entry
    
    return dataset

def main():
    parser = argparse.ArgumentParser(description="Generate CTF benchmark datasets")
    parser.add_argument(
        "--folder",
        default="ctf-archive",
        help="Base directory to search for CTF challenges (default: ctf-archive)"
    )
    parser.add_argument(
        "--require-sha256",
        action="store_true",
        help="Only include tasks that have a SHA256 file (flag.sha256, .flag.sha256, or flag.sha256.txt)"
    )
    parser.add_argument(
        "--skip-sha256",
        action="store_true",
        help="Skip tasks that have a SHA256 file (flag.sha256, .flag.sha256, or flag.sha256.txt)"
    )
    parser.add_argument(
        "--skip-flagcheck",
        action="store_true",
        help="Skip tasks that have any files containing 'flagcheck' in the name"
    )
    parser.add_argument(
        "--require-compose",
        action="store_true",
        help="Only include tasks that have compose set to true in challenge.json"
    )
    
    args = parser.parse_args()
    
    # Ensure mutual exclusivity
    if args.require_sha256 and args.skip_sha256:
        parser.error("--require-sha256 and --skip-sha256 are mutually exclusive")
    
    print(f"Generating CTF archive dataset from folder: {args.folder}")
    if args.require_sha256:
        print("Filtering for tasks with SHA256 files...")
    elif args.skip_sha256:
        print("Skipping tasks with SHA256 files...")
    if args.skip_flagcheck:
        print("Skipping tasks with flagcheck files...")
    if args.require_compose:
        print("Filtering for tasks with compose=true...")
    
    ctf_archive_dataset = generate_ctf_archive_dataset(
        base_dir=args.folder,
        require_sha256=args.require_sha256, 
        skip_sha256=args.skip_sha256,
        skip_flagcheck=args.skip_flagcheck,
        require_compose=args.require_compose
    )
    
    # Write CTF archive dataset
    output_filename = 'ctf_archive.json'
    if args.require_sha256:
        output_filename = 'ctf_archive_sha256.json'
    elif args.skip_sha256:
        output_filename = 'ctf_archive_no_sha256.json'
    if args.skip_flagcheck:
        # Insert _no_flagcheck before the .json extension
        output_filename = output_filename.replace('.json', '_no_flagcheck.json')
    if args.require_compose:
        # Insert _compose before the .json extension
        output_filename = output_filename.replace('.json', '_compose.json')
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(ctf_archive_dataset, f, indent=2, ensure_ascii=False)
    
    print(f"Generated {output_filename} with {len(ctf_archive_dataset)} challenges")
    
    # Print some sample entries
    print(f"\nSample CTF archive entries:")
    for i, (key, value) in enumerate(ctf_archive_dataset.items()):
        if i < 3:
            print(f"  {key}: {value}")
    
    # Print statistics
    events = set()
    categories = set()
    for value in ctf_archive_dataset.values():
        events.add(value['event'])
        if 'category' in value:
            categories.add(value['category'])
    
    print(f"\nStatistics:")
    print(f"  Events: {len(events)}")
    print(f"  Categories: {len(categories)}")
    print(f"  Total challenges: {len(ctf_archive_dataset)}")
    
    if args.require_sha256:
        print(f"  (Filtered for tasks with SHA256 files)")
    elif args.skip_sha256:
        print(f"  (Skipped tasks with SHA256 files)")
    if args.require_compose:
        print(f"  (Filtered for tasks with compose=true)")

if __name__ == "__main__":
    main() 