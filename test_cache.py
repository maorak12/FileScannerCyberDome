#!/usr/bin/env python3
"""
Test script for YARA cache system
"""

import os
import sys
import tempfile
import shutil

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from yara_cache import yara_cache
from config import get_config

def test_cache_functionality():
    """Test basic cache functionality"""
    print("Testing YARA Cache System...")
    print("=" * 50)
    
    # Test 1: Basic cache initialization
    print("\n1. Testing cache initialization...")
    try:
        rules = yara_cache.get_rules()
        print(f"   ✓ Cache initialized with {len(rules)} rules")
    except Exception as e:
        print(f"   ✗ Cache initialization failed: {e}")
        return False
    
    # Test 2: Cache statistics
    print("\n2. Testing cache statistics...")
    try:
        stats = yara_cache.get_cache_stats()
        print(f"   ✓ Cache stats retrieved:")
        print(f"     - Total rules: {stats['total_rules']}")
        print(f"     - Valid rules: {stats['valid_rules']}")
        print(f"     - Invalid rules: {stats['invalid_rules']}")
        print(f"     - Compiled rules: {stats['compiled_rules']}")
        print(f"     - Cache enabled: {stats['cache_enabled']}")
    except Exception as e:
        print(f"   ✗ Cache stats failed: {e}")
        return False
    
    # Test 3: Add a test rule
    print("\n3. Testing rule addition...")
    try:
        test_rule_content = '''
rule TestRule
{
    meta:
        description = "Test rule for cache testing"
        author = "Test"
    
    strings:
        $test_string = "test"
    
    condition:
        $test_string
}
'''
        
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
            f.write(test_rule_content)
            test_file_path = f.name
        
        # Add to cache
        success = yara_cache.add_rule(test_file_path, test_rule_content, 'test_folder')
        if success:
            print("   ✓ Test rule added to cache successfully")
        else:
            print("   ✗ Failed to add test rule to cache")
            return False
        
        # Clean up test file
        os.unlink(test_file_path)
        
    except Exception as e:
        print(f"   ✗ Rule addition test failed: {e}")
        return False
    
    # Test 4: Cache refresh
    print("\n4. Testing cache refresh...")
    try:
        yara_cache.get_rules(force_refresh=True)
        print("   ✓ Cache refresh completed successfully")
    except Exception as e:
        print(f"   ✗ Cache refresh failed: {e}")
        return False
    
    # Test 5: Compiled rules access
    print("\n5. Testing compiled rules access...")
    try:
        compiled_rules = yara_cache.get_compiled_rules()
        print(f"   ✓ Retrieved {len(compiled_rules)} compiled rules")
    except Exception as e:
        print(f"   ✗ Compiled rules access failed: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("✓ All cache tests passed successfully!")
    return True

def test_configuration():
    """Test configuration loading"""
    print("\nTesting Configuration...")
    print("=" * 50)
    
    try:
        config = get_config()
        print(f"✓ Configuration loaded successfully")
        print(f"  - YARA folder: {config.YARA_FOLDER}")
        print(f"  - Cache enabled: {config.YARA_CACHE_ENABLED}")
        print(f"  - Cache refresh interval: {config.YARA_CACHE_REFRESH_INTERVAL} seconds")
        print(f"  - Pagination options: {config.PAGINATION_OPTIONS}")
        
        # Test ruleset folders
        print(f"  - YARA ruleset folders:")
        for folder in config.YARA_RULESET_FOLDERS:
            print(f"    * {folder}")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

if __name__ == "__main__":
    print("File Scanner CyberDome - Cache System Test")
    print("=" * 60)
    
    # Test configuration
    if not test_configuration():
        print("\n✗ Configuration test failed. Exiting.")
        sys.exit(1)
    
    # Test cache functionality
    if not test_cache_functionality():
        print("\n✗ Cache functionality test failed. Exiting.")
        sys.exit(1)
    
    print("\n🎉 All tests passed! The YARA cache system is working correctly.")
    print("\nYou can now run the main application with:")
    print("  python app.py")
