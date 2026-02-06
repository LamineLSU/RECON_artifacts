#!/usr/bin/env python3
"""
Script to clean results folders - keeps only dangerous_apis_found.json
"""

import os
import sys
import shutil
from pathlib import Path


def cleanup_results(results_dir):
    """Clean results directory, keeping only dangerous_apis_found.json in each subfolder"""
    
    results_path = Path(results_dir)
    
    # Check if directory exists
    if not results_path.exists() or not results_path.is_dir():
        print(f"Error: Directory '{results_dir}' does not exist!")
        return False
    
    print("=" * 50)
    print("Results Folder Cleanup Script")
    print("=" * 50)
    print(f"Target directory: {results_path.absolute()}")
    print()
    
    # Get all subfolders
    subfolders = [f for f in results_path.iterdir() if f.is_dir()]
    print(f"Found {len(subfolders)} subfolders")
    print()
    
    # Preview what will be deleted
    print("=" * 50)
    print("PREVIEW: Files/Folders to be DELETED")
    print("=" * 50)
    
    total_to_delete = 0
    folders_with_target = 0
    folders_without_target = 0
    items_to_delete = []
    
    for subfolder in subfolders:
        target_file = subfolder / "dangerous_apis_found.json"
        
        if target_file.exists():
            folders_with_target += 1
            
            # List items to delete
            for item in subfolder.iterdir():
                if item.name != "dangerous_apis_found.json":
                    print(f"  ❌ {subfolder.name}/{item.name}")
                    items_to_delete.append(item)
                    total_to_delete += 1
        else:
            folders_without_target += 1
            print(f"  ⚠️  WARNING: {subfolder.name}/ does NOT contain dangerous_apis_found.json")
            print(f"     (All contents will be deleted)")
            
            for item in subfolder.iterdir():
                print(f"  ❌ {subfolder.name}/{item.name}")
                items_to_delete.append(item)
                total_to_delete += 1
    
    print()
    print("=" * 50)
    print("Summary:")
    print("=" * 50)
    print(f"  Total subfolders: {len(subfolders)}")
    print(f"  Folders WITH dangerous_apis_found.json: {folders_with_target}")
    print(f"  Folders WITHOUT dangerous_apis_found.json: {folders_without_target}")
    print(f"  Total items to DELETE: {total_to_delete}")
    print()
    
    # Ask for confirmation
    confirmation = input("Do you want to proceed with deletion? (yes/no): ").strip().lower()
    
    if confirmation != "yes":
        print("Cleanup cancelled.")
        return False
    
    print()
    print("=" * 50)
    print("Starting cleanup...")
    print("=" * 50)
    
    deleted_count = 0
    kept_count = 0
    
    for subfolder in subfolders:
        # Delete everything except dangerous_apis_found.json
        for item in subfolder.iterdir():
            if item.name != "dangerous_apis_found.json":
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    deleted_count += 1
                except Exception as e:
                    print(f"  ❌ Error deleting {item}: {e}")
            else:
                kept_count += 1
        
        print(f"  ✓ Cleaned: {subfolder.name}/")
    
    print()
    print("=" * 50)
    print("Cleanup Complete!")
    print("=" * 50)
    print(f"  Items deleted: {deleted_count}")
    print(f"  Files kept: {kept_count}")
    print()
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cleanup_results.py <results_folder_path>")
        print("Example: python cleanup_results.py ./results")
        sys.exit(1)
    
    results_directory = sys.argv[1]
    cleanup_results(results_directory)
