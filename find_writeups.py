#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: CC-BY-NC-4.0

import json
import re
from collections import defaultdict, Counter
from difflib import SequenceMatcher
import argparse
from pathlib import Path
import multiprocessing as mp
from functools import partial

def normalize_string(s):
    """Normalize string for fuzzy matching by removing special characters and converting to lowercase"""
    # Remove special characters and convert to lowercase
    normalized = re.sub(r'[^a-zA-Z0-9]', '', s.lower())
    return normalized

def extract_year(competition_name):
    """Extract year from competition name"""
    import re
    # Look for 4-digit year pattern
    year_match = re.search(r'(19|20)\d{2}', competition_name)
    if year_match:
        return year_match.group(0)
    return None

def extract_competition_task_from_writeup_path(writeup_path):
    """Extract competition and task name from writeup path"""
    # Example: writeup_content/X-MAS_2018/Endless Christmas/writeup_1_Pwnium.json
    # Should return: ('xmas2018', 'endlesschristmas')
    
    parts = writeup_path.split('/')
    if len(parts) < 3:
        return None, None
    
    competition = normalize_string(parts[1])  # X-MAS_2018 -> xmas2018
    task = normalize_string(parts[2])  # Endless Christmas -> endlesschristmas
    
    return competition, task

def extract_competition_task_from_ctf_path(ctf_path):
    """Extract competition and task name from CTF archive path"""
    # Example: ctf-archive/0ctf2017/diethard
    # Should return: ('0ctf2017', 'diethard')
    
    parts = ctf_path.split('/')
    if len(parts) < 3:
        return None, None
    
    competition = normalize_string(parts[1])  # 0ctf2017 -> 0ctf2017
    task = normalize_string(parts[2])  # diethard -> diethard
    
    return competition, task

def fast_similarity_score(s1, s2):
    """Fast similarity score using simple character overlap"""
    if not s1 or not s2:
        return 0
    
    # For short strings, use exact match bonus
    if len(s1) < 8 and len(s2) < 8:
        if s1 == s2:
            return 1.0
        if s1 in s2 or s2 in s1:
            return 0.8
    
    # Fast substring matching
    longer = s1 if len(s1) > len(s2) else s2
    shorter = s2 if len(s1) > len(s2) else s1
    
    if shorter in longer:
        return 0.7 + (len(shorter) / len(longer)) * 0.3
    
    # Character overlap scoring
    set1, set2 = set(s1), set(s2)
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    
    if union == 0:
        return 0
    
    return intersection / union

def enhanced_similarity_score(s1, s2):
    """Enhanced similarity score that handles common CTF naming patterns"""
    if not s1 or not s2:
        return 0
    
    # Check for exact match first
    if s1 == s2:
        return 1.0
    
    # Check for substring containment (with length consideration)
    longer = s1 if len(s1) > len(s2) else s2
    shorter = s2 if len(s1) > len(s2) else s1
    
    if shorter in longer:
        # High score for substring matches, scaled by length ratio
        length_ratio = len(shorter) / len(longer)
        return 0.9 + (length_ratio * 0.1)  # 0.9 to 1.0 range
    
    # For competition names, try removing common suffixes/prefixes
    if len(s1) > 4 and len(s2) > 4:
        # Remove common patterns like "ctf", year suffixes, etc.
        clean1 = re.sub(r'(ctf|20\d{2}|19\d{2})$', '', s1)
        clean2 = re.sub(r'(ctf|20\d{2}|19\d{2})$', '', s2)
        
        if clean1 and clean2 and (clean1 == clean2 or clean1 in clean2 or clean2 in clean1):
            return 0.95
    
    # Use fast similarity for initial screening
    fast_score = fast_similarity_score(s1, s2)
    
    # Only use expensive SequenceMatcher for promising matches
    if fast_score > 0.3:
        return SequenceMatcher(None, s1, s2).ratio()
    
    return fast_score

def similarity_score(s1, s2):
    """Calculate similarity score between two strings"""
    return enhanced_similarity_score(s1, s2)

def find_best_match(writeup_comp, writeup_task, ctf_tasks, min_threshold=0.8):
    """Find the best matching CTF task for a writeup"""
    best_match = None
    best_score = 0
    
    # Extract year from writeup competition name
    writeup_year = extract_year(writeup_comp)
    
    for ctf_key, ctf_data in ctf_tasks.items():
        ctf_comp, ctf_task = extract_competition_task_from_ctf_path(ctf_data['path'])
        
        if not ctf_comp or not ctf_task:
            continue
        
        # Extract year from CTF competition name
        ctf_year = extract_year(ctf_comp)
        
        # Skip if years don't match (strict year matching)
        if writeup_year and ctf_year and writeup_year != ctf_year:
            continue
        
        # Quick rejection based on length difference
        if abs(len(writeup_comp) - len(ctf_comp)) > max(len(writeup_comp), len(ctf_comp)) * 0.5:
            comp_score = 0
        else:
            comp_score = similarity_score(writeup_comp, ctf_comp)
        
        if abs(len(writeup_task) - len(ctf_task)) > max(len(writeup_task), len(ctf_task)) * 0.5:
            task_score = 0
        else:
            task_score = similarity_score(writeup_task, ctf_task)
        
        # Combined score (weighted more towards task name)
        combined_score = (comp_score * 0.4) + (task_score * 0.6)
        
        if combined_score > best_score and combined_score >= min_threshold:
            best_score = combined_score
            best_match = {
                'ctf_key': ctf_key,
                'ctf_path': ctf_data['path'],
                'score': combined_score,
                'comp_score': comp_score,
                'task_score': task_score,
                'writeup_year': writeup_year,
                'ctf_year': ctf_year
            }
    
    return best_match

def find_best_match_verbose(writeup_comp, writeup_task, ctf_tasks, min_threshold=0.8, verbose=False):
    """Find the best matching CTF task for a writeup with verbose logging"""
    best_match = None
    best_score = 0
    year_mismatches = 0
    competition_mismatches = 0
    task_mismatches = 0
    
    # Extract year from writeup competition name
    writeup_year = extract_year(writeup_comp)
    
    for ctf_key, ctf_data in ctf_tasks.items():
        ctf_comp, ctf_task = extract_competition_task_from_ctf_path(ctf_data['path'])
        
        if not ctf_comp or not ctf_task:
            continue
        
        # Extract year from CTF competition name
        ctf_year = extract_year(ctf_comp)
        
        # Skip if years don't match (strict year matching)
        if writeup_year and ctf_year and writeup_year != ctf_year:
            year_mismatches += 1
            continue
        
        # Quick rejection based on length difference
        if abs(len(writeup_comp) - len(ctf_comp)) > max(len(writeup_comp), len(ctf_comp)) * 0.5:
            comp_score = 0
        else:
            comp_score = similarity_score(writeup_comp, ctf_comp)
        
        # Very strict competition name matching - require high competition similarity
        if comp_score < 0.85:  # Require at least 85% similarity for competition names
            competition_mismatches += 1
            continue
        
        if abs(len(writeup_task) - len(ctf_task)) > max(len(writeup_task), len(ctf_task)) * 0.5:
            task_score = 0
        else:
            task_score = similarity_score(writeup_task, ctf_task)
        
        # Strict task name matching - require minimum task similarity
        if task_score < 0.8:  # Require at least 80% similarity for task names
            task_mismatches += 1
            continue
        
        # Combined score (heavily weighted towards competition name)
        combined_score = (comp_score * 0.8) + (task_score * 0.2)
        
        if combined_score > best_score and combined_score >= min_threshold:
            best_score = combined_score
            best_match = {
                'ctf_key': ctf_key,
                'ctf_path': ctf_data['path'],
                'score': combined_score,
                'comp_score': comp_score,
                'task_score': task_score,
                'writeup_year': writeup_year,
                'ctf_year': ctf_year
            }
    
    if verbose and (year_mismatches > 0 or competition_mismatches > 0 or task_mismatches > 0):
        print(f"  Year mismatches rejected: {year_mismatches} tasks")
        print(f"  Competition name mismatches rejected: {competition_mismatches} tasks")
        print(f"  Task name mismatches rejected: {task_mismatches} tasks")
    
    return best_match

def process_writeup(writeup_data, ctf_tasks, min_threshold, verbose=False):
    """Process a single writeup and return match result"""
    writeup_path = writeup_data.get('writeup_path', '')
    
    if not writeup_path:
        return None
    
    # Extract competition and task from writeup path
    writeup_comp, writeup_task = extract_competition_task_from_writeup_path(writeup_path)
    
    if not writeup_comp or not writeup_task:
        return None
    
    # Find best matching CTF task
    best_match = find_best_match_verbose(writeup_comp, writeup_task, ctf_tasks, min_threshold, verbose)
    
    if best_match:
        # Get the original task writeup
        task_writeup = writeup_data.get('task_writeup', '').replace("\\", "").replace("//", "")
        
        # Only replace solution if it exists and is not empty
        solution = writeup_data.get('solution', '')
        if solution and solution.strip():
            task_writeup = task_writeup.replace(solution, 'REDACTED_FLAG')
        
        return {
            'ctf_key': best_match['ctf_key'],
            'writeup_data': {
                'writeup_path': writeup_path,
                'writeup_competition': writeup_comp,
                'writeup_task': writeup_task,
                'match_score': best_match['score'],
                'competition_score': best_match['comp_score'],
                'task_score': best_match['task_score'],
                'writeup_year': best_match['writeup_year'],
                'ctf_year': best_match['ctf_year'],
                'task_name': writeup_data.get('task_name', ''),
                'task_writeup': task_writeup
            }
        }
    
    return None

def main():
    parser = argparse.ArgumentParser(description='Map writeups to CTF tasks using fuzzy matching with strict year filtering')
    parser.add_argument('--jsonl-file', default='writeups.jsonl',
                        help='Path to the JSONL file containing writeups')
    parser.add_argument('--json-file', default='ctf_archive.json',
                        help='Path to the JSON file containing CTF tasks')
    parser.add_argument('--output-file', default='task_writeup_mapping.json',
                        help='Output file for the mapping results')
    parser.add_argument('--min-threshold', type=float, default=0.9,
                        help='Minimum similarity threshold for matching (default: 0.9 - strict matching)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output showing matching details')
    parser.add_argument('--limit', type=int, default=0,
                        help='Limit number of writeups to process (0 for all)')
    parser.add_argument('--workers', type=int, default=32,
                        help='Number of parallel workers to use (default: 32)')
    
    args = parser.parse_args()
    
    # Load CTF tasks
    print(f"Loading CTF tasks from {args.json_file}...")
    with open(args.json_file, 'r') as f:
        ctf_tasks = json.load(f)
    
    print(f"Loaded {len(ctf_tasks)} CTF tasks")
    
    # Load writeups
    print(f"Loading writeups from {args.jsonl_file}...")
    print(f"Using strict matching threshold: {args.min_threshold}")
    print(f"Using strict year filtering (same year required)")
    print(f"Using very strict competition name filtering (min 85% similarity required)")
    print(f"Using strict task name filtering (min 80% similarity required)")
    print(f"Competition name weighted 80%, task name weighted 20%")
    print(f"Using {args.workers} parallel workers")
    
    writeups_data = []
    with open(args.jsonl_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if args.limit > 0 and len(writeups_data) >= args.limit:
                break
                
            if line.strip():
                try:
                    writeup_data = json.loads(line)
                    if writeup_data.get('writeup_path'):
                        writeups_data.append(writeup_data)
                except json.JSONDecodeError as e:
                    print(f"Error parsing line {line_num}: {e}")
                    continue
    
    print(f"Loaded {len(writeups_data)} writeups")
    
    # Process writeups in parallel
    print("Processing writeups in parallel...")
    task_writeup_mapping = defaultdict(list)
    matched_count = 0
    
    # Create partial function with fixed arguments
    process_func = partial(process_writeup, ctf_tasks=ctf_tasks, min_threshold=args.min_threshold, verbose=args.verbose)
    
    # Process in parallel
    with mp.Pool(processes=args.workers) as pool:
        results = pool.map(process_func, writeups_data)
    
    # Collect results
    for result in results:
        if result:
            matched_count += 1
            task_writeup_mapping[result['ctf_key']].append(result['writeup_data'])
            
            if args.verbose:
                print(f"✓ Matched: {result['writeup_data']['writeup_path']}")
                print(f"  -> {ctf_tasks[result['ctf_key']]['path']} (score: {result['writeup_data']['match_score']:.3f})")
                print(f"  Years: {result['writeup_data']['writeup_year']} == {result['writeup_data']['ctf_year']}")
                print()
    
    total_count = len(writeups_data)
    
    print(f"\nMatching complete!")
    print(f"Total writeups processed: {total_count}")
    print(f"Successfully matched writeups: {matched_count}")
    print(f"Writeup match rate: {matched_count/total_count*100:.1f}%")
    print(f"\n--- Task Coverage Statistics ---")
    print(f"Total tasks in CTF archive: {len(ctf_tasks)}")
    print(f"Tasks with at least one writeup: {len(task_writeup_mapping)}")
    print(f"Task coverage rate: {len(task_writeup_mapping)/len(ctf_tasks)*100:.1f}%")
    
    # Prepare output data
    output_data = {
        'summary': {
            'total_writeups_processed': total_count,
            'matched_writeups': matched_count,
            'writeup_match_rate': matched_count/total_count,
            'total_tasks_in_archive': len(ctf_tasks),
            'tasks_with_writeups': len(task_writeup_mapping),
            'task_coverage_rate': len(task_writeup_mapping)/len(ctf_tasks),
            'min_threshold': args.min_threshold,
            'workers_used': args.workers
        },
        'task_writeup_mapping': dict(task_writeup_mapping)
    }
    
    # Add CTF task information to the mapping
    for ctf_key, writeups in task_writeup_mapping.items():
        output_data['task_writeup_mapping'][ctf_key] = {
            'ctf_task_info': ctf_tasks[ctf_key],
            'writeups': writeups
        }
    
    # Save results
    with open(args.output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to {args.output_file}")
    
    # Print some statistics
    print(f"\nTop 10 tasks by number of writeups:")
    sorted_tasks = sorted(task_writeup_mapping.items(), key=lambda x: len(x[1]), reverse=True)
    for i, (ctf_key, writeups) in enumerate(sorted_tasks[:10]):
        ctf_path = ctf_tasks[ctf_key]['path']
        print(f"{i+1:2d}. {ctf_path} - {len(writeups)} writeups")
    
    # Show writeups per task distribution
    if task_writeup_mapping:
        writeup_counts = [len(writeups) for writeups in task_writeup_mapping.values()]
        avg_writeups = sum(writeup_counts) / len(writeup_counts)
        max_writeups = max(writeup_counts)
        min_writeups = min(writeup_counts)
        
        print(f"\nWriteups per task distribution:")
        print(f"  Average: {avg_writeups:.1f}")
        print(f"  Range: {min_writeups} - {max_writeups}")
        
        # Count tasks by writeup count
        count_distribution = Counter(writeup_counts)
        print(f"  Tasks with 1 writeup: {count_distribution.get(1, 0)}")
        print(f"  Tasks with 2+ writeups: {len(task_writeup_mapping) - count_distribution.get(1, 0)}")
    
    # Show some example matches
    if not args.verbose and matched_count > 0:
        print(f"\nExample matches:")
        shown = 0
        for ctf_key, writeups in sorted_tasks[:5]:
            if shown >= 5:
                break
            ctf_path = ctf_tasks[ctf_key]['path']
            for writeup in writeups[:2]:  # Show first 2 writeups per task
                if shown >= 5:
                    break
                print(f"  {writeup['writeup_path']} -> {ctf_path} (score: {writeup['match_score']:.3f})")
                shown += 1
    
    # Show tasks without writeups (if verbose)
    if args.verbose:
        tasks_without_writeups = set(ctf_tasks.keys()) - set(task_writeup_mapping.keys())
        print(f"\nTasks without writeups ({len(tasks_without_writeups)}):")
        for i, ctf_key in enumerate(sorted(tasks_without_writeups)):
            if i >= 20:  # Limit to first 20
                print(f"  ... and {len(tasks_without_writeups) - 20} more")
                break
            print(f"  {ctf_tasks[ctf_key]['path']}")

if __name__ == "__main__":
    main() 