import os
import yara
import time
import threading
import logging
from typing import Dict, List, Optional, Tuple
from config import get_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class YaraCache:
    """Cache manager for YARA rules to improve performance"""
    
    def __init__(self):
        self.config = get_config()
        self._rules_cache = []
        self._last_refresh = 0
        self._cache_lock = threading.Lock()
        self._compiled_rules = {}
        self._cache_errors = []
        
    def get_rules(self, force_refresh: bool = False) -> List[Dict]:
        """Get cached YARA rules or refresh if needed"""
        current_time = time.time()
        
        # Check if cache needs refresh
        if (force_refresh or 
            not self._rules_cache or 
            current_time - self._last_refresh > self.config.YARA_CACHE_REFRESH_INTERVAL):
            
            with self._cache_lock:
                self._refresh_cache()
                self._last_refresh = current_time
        
        return self._rules_cache.copy()
    
    def _refresh_cache(self):
        """Refresh the YARA rules cache by reading directly from YARA directories"""
        all_rules = []
        self._cache_errors = []
        
        try:
            logger.info("Refreshing YARA rules cache from YARA directories...")
            
            # Scan all configured YARA folders
            for folder in self.config.YARA_RULESET_FOLDERS:
                if folder.strip() and os.path.exists(folder.strip()):
                    folder_path = folder.strip()
                    folder_name = os.path.basename(folder_path)
                    logger.info(f"Scanning YARA folder: {folder_path}")
                    
                    # Check if this is a Git submodule directory
                    git_dir = os.path.join(folder_path, '.git')
                    is_submodule = os.path.exists(git_dir) or os.path.islink(git_dir)
                    
                    if is_submodule:
                        logger.info(f"Detected Git submodule: {folder_name}")
                    
                    # Count files found
                    yara_files_found = 0
                    
                    for root, dirs, files in os.walk(folder_path):
                        # Skip .git directories
                        if '.git' in dirs:
                            dirs.remove('.git')
                        
                        for file in files:
                            if file.endswith(('.yar', '.yara')):
                                yara_files_found += 1
                                rule_path = os.path.join(root, file)
                                logger.debug(f"Found YARA file: {rule_path}")
                                try:
                                    # Read rule content directly from YARA directory
                                    with open(rule_path, 'r', encoding='utf-8') as f:
                                        rule_content = f.read()
                                    
                                    # Try to compile to validate
                                    try:
                                        compiled_rule = yara.compile(source=rule_content)
                                        status = 'valid'
                                        # Store compiled rule for scanning
                                        self._compiled_rules[rule_path] = compiled_rule
                                        logger.debug(f"Successfully compiled rule: {file}")
                                    except Exception as e:
                                        status = 'invalid'
                                        rule_content = f"# Compilation Error: {str(e)}\n\n{rule_content}"
                                        logger.warning(f"Failed to compile rule {file}: {e}")
                                    
                                    # Get relative path from the ruleset folder for better display
                                    rel_path = os.path.relpath(rule_path, folder.strip())
                                    display_folder = f"{folder_name}/{os.path.dirname(rel_path)}" if os.path.dirname(rel_path) else folder_name
                                    
                                    # Check for duplicates based on path
                                    existing_rule = next((r for r in all_rules if r['path'] == rule_path), None)
                                    if not existing_rule:
                                        all_rules.append({
                                            'name': os.path.splitext(file)[0],
                                            'filename': file,
                                            'folder': display_folder,
                                            'path': rule_path,
                                            'content': rule_content,
                                            'status': status,
                                            'size': os.path.getsize(rule_path),
                                            'is_submodule': is_submodule
                                        })
                                    else:
                                        logger.debug(f"Skipping duplicate rule: {rule_path}")
                                except Exception as e:
                                    error_msg = f"Error reading file {file}: {str(e)}"
                                    logger.error(error_msg)
                                    self._cache_errors.append(error_msg)
                                    
                                    # Check for duplicates based on path
                                    existing_rule = next((r for r in all_rules if r['path'] == rule_path), None)
                                    if not existing_rule:
                                        all_rules.append({
                                            'name': os.path.splitext(file)[0],
                                            'filename': file,
                                            'folder': folder_name,
                                            'path': rule_path,
                                            'content': f"# Error reading file: {str(e)}",
                                            'status': 'error',
                                            'size': 0,
                                            'is_submodule': is_submodule
                                        })
                                    else:
                                        logger.debug(f"Skipping duplicate rule: {rule_path}")
                    
                    logger.info(f"Found {yara_files_found} YARA files in folder: {folder_path}")
            
            # Sort rules by folder and name
            all_rules.sort(key=lambda x: (x['folder'], x['name']))
            self._rules_cache = all_rules
            
            logger.info(f"Cache refresh complete: {len(all_rules)} rules loaded from YARA directories")
            
        except Exception as e:
            error_msg = f"Error refreshing YARA cache: {str(e)}"
            logger.error(error_msg)
            self._cache_errors.append(error_msg)
            
            # Keep existing cache if refresh fails
            if not self._rules_cache:
                self._rules_cache = []
    
    def add_rule(self, rule_path: str, rule_content: str, folder_name: str) -> bool:
        """Add a new rule to the cache"""
        try:
            logger.info(f"Adding rule to cache: {os.path.basename(rule_path)}")
            
            # Validate and compile the rule
            compiled_rule = yara.compile(source=rule_content)
            status = 'valid'
            self._compiled_rules[rule_path] = compiled_rule
            
            # Check for duplicates before adding
            with self._cache_lock:
                existing_rule = next((r for r in self._rules_cache if r['path'] == rule_path), None)
                if existing_rule:
                    logger.warning(f"Rule already exists in cache: {rule_path}")
                    return False
                
                # Add to cache
                rule_info = {
                    'name': os.path.splitext(os.path.basename(rule_path))[0],
                    'filename': os.path.basename(rule_path),
                    'folder': folder_name,
                    'path': rule_path,
                    'content': rule_content,
                    'status': status,
                    'size': len(rule_content.encode('utf-8'))
                }
                
                self._rules_cache.append(rule_info)
                self._rules_cache.sort(key=lambda x: (x['folder'], x['name']))
            
            logger.info(f"Rule added to cache successfully: {rule_info['name']}")
            return True
            
        except Exception as e:
            error_msg = f"Error adding rule to cache: {str(e)}"
            logger.error(error_msg)
            self._cache_errors.append(error_msg)
            return False
    
    def remove_rule(self, rule_path: str) -> bool:
        """Remove a rule from the cache"""
        try:
            logger.info(f"Removing rule from cache: {os.path.basename(rule_path)}")
            
            with self._cache_lock:
                # Remove from rules cache
                self._rules_cache = [r for r in self._rules_cache if r['path'] != rule_path]
                
                # Remove from compiled rules
                if rule_path in self._compiled_rules:
                    del self._compiled_rules[rule_path]
            
            logger.info(f"Rule removed from cache successfully: {os.path.basename(rule_path)}")
            return True
            
        except Exception as e:
            error_msg = f"Error removing rule from cache: {str(e)}"
            logger.error(error_msg)
            self._cache_errors.append(error_msg)
            return False
    
    def get_compiled_rules(self) -> Dict[str, yara.Rules]:
        """Get all compiled YARA rules for scanning"""
        # Ensure cache is up to date
        self.get_rules()
        return self._compiled_rules.copy()
    
    def get_rule_by_path(self, rule_path: str) -> Optional[Dict]:
        """Get a specific rule by its path"""
        rules = self.get_rules()
        for rule in rules:
            if rule['path'] == rule_path:
                return rule
        return None
    
    def clear_cache(self):
        """Clear the entire cache"""
        logger.info("Clearing YARA cache")
        with self._cache_lock:
            self._rules_cache.clear()
            self._compiled_rules.clear()
            self._last_refresh = 0
            self._cache_errors.clear()
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'total_rules': len(self._rules_cache),
            'valid_rules': len([r for r in self._rules_cache if r['status'] == 'valid']),
            'invalid_rules': len([r for r in self._rules_cache if r['status'] == 'invalid']),
            'error_rules': len([r for r in self._rules_cache if r['status'] == 'error']),
            'compiled_rules': len(self._compiled_rules),
            'last_refresh': self._last_refresh,
            'cache_enabled': self.config.YARA_CACHE_ENABLED,
            'errors': self._cache_errors.copy()
        }
    
    def get_cache_errors(self) -> List[str]:
        """Get any cache errors that occurred"""
        return self._cache_errors.copy()

# Global cache instance
yara_cache = YaraCache()
