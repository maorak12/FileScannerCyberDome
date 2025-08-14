#!/usr/bin/env python3
"""
Setup script for YARA rules Git submodule
This script initializes the Neo23x0 signature-base submodule for YARA rules.
"""

import os
import subprocess
import sys

def run_command(cmd, cwd=None, description=""):
    """Run a command and handle errors"""
    print(f"Running: {description or cmd}")
    try:
        result = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
        print(f"✓ Success: {description or cmd}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Error: {description or cmd}")
        print(f"  Error: {e.stderr}")
        return False

def setup_yara_submodule():
    """Setup the YARA rules Git submodule"""
    print("Setting up YARA rules Git submodule...")
    print("=" * 50)
    
    # Check if we're in a Git repository
    if not os.path.exists('.git'):
        print("Error: This directory is not a Git repository.")
        print("Please run this script from the root of your FileScannerCyberDome repository.")
        return False
    
    # Define paths
    yara_folder = 'yara-rules'
    submodule_path = os.path.join(yara_folder, 'signature_base')
    repo_url = 'https://github.com/Neo23x0/signature-base.git'
    
    print(f"YARA folder: {yara_folder}")
    print(f"Submodule path: {submodule_path}")
    print(f"Repository URL: {repo_url}")
    print()
    
    # Create yara-rules directory if it doesn't exist
    if not os.path.exists(yara_folder):
        print(f"Creating {yara_folder} directory...")
        os.makedirs(yara_folder, exist_ok=True)
    
    # Check if submodule already exists
    if os.path.exists(submodule_path):
        print(f"Submodule already exists at {submodule_path}")
        print("Updating existing submodule...")
        
        # Update existing submodule
        if not run_command(['git', 'submodule', 'update', '--init', '--recursive'], 
                          cwd=submodule_path, description="Update submodule"):
            return False
            
    else:
        print("Initializing new submodule...")
        
        # Change to yara-rules directory
        os.chdir(yara_folder)
        
        # Add submodule
        if not run_command(['git', 'submodule', 'add', repo_url, 'signature_base'], 
                          description="Add signature-base submodule"):
            return False
        
        # Initialize and update submodule
        if not run_command(['git', 'submodule', 'update', '--init', '--recursive'], 
                          description="Initialize submodule"):
            return False
        
        # Return to original directory
        os.chdir('..')
    
    print()
    print("✓ YARA rules submodule setup complete!")
    print()
    print("Next steps:")
    print("1. Run the application: python app.py")
    print("2. Navigate to YARA Rules page")
    print("3. The cache will automatically load rules from the submodule")
    print()
    print("To update rules in the future:")
    print("  cd yara-rules/signature_base")
    print("  git pull origin master")
    print("  cd ../..")
    print("  python app.py  # Cache will refresh automatically")
    
    return True

if __name__ == "__main__":
    try:
        success = setup_yara_submodule()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
