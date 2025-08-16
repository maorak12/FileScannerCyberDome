# File Scanner CyberDome Configuration
import os

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))  # 100MB default
    
    # YARA Configuration
    YARA_FOLDER = os.environ.get('YARA_FOLDER') or './yara-rules'
    YARA_RULESET_FOLDERS = os.environ.get('YARA_RULESET_FOLDERS', '').split(',') if os.environ.get('YARA_RULESET_FOLDERS') else [
        YARA_FOLDER  # Scan the entire yara-rules folder and all subfolders
    ]
    # For Git submodule setup, use the actual repository URL
    YARA_REPO_URL = os.environ.get('YARA_REPO_URL') or 'https://github.com/Neo23x0/signature-base.git'
    YARA_SUBMODULE_PATH = os.environ.get('YARA_SUBMODULE_PATH') or os.path.join(YARA_FOLDER, 'signature_base')
    MIN_COMMON_RULES = int(os.environ.get('MIN_COMMON_RULES', 2))  # Minimum rules for similar file detection
    
    # Cache Configuration
    YARA_CACHE_ENABLED = os.environ.get('YARA_CACHE_ENABLED', 'True').lower() == 'true'
    YARA_CACHE_REFRESH_INTERVAL = int(os.environ.get('YARA_CACHE_REFRESH_INTERVAL', 300))  # 5 minutes
    
    # Database Configuration
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or 'filescanner.db'
    
    # Server Configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # Security Configuration
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'sys', 'scr', 'com',  # Executables
        'bat', 'cmd', 'ps1', 'vbs', 'js'    # Scripts
    }
    
    # UI Configuration
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', 50))
    PAGINATION_OPTIONS = [10, 50, 100]  # Available pagination limits
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Ensure directories exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['YARA_FOLDER'], exist_ok=True)
        
        # Create custom rules folder
        custom_rules_folder = os.path.join(app.config['YARA_FOLDER'], 'custom_rules')
        os.makedirs(custom_rules_folder, exist_ok=True)
        
       
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB for development

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB for production

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_PATH = ':memory:'  # Use in-memory database for testing
    UPLOAD_FOLDER = 'test_uploads'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    config_name = os.environ.get('FLASK_ENV', 'default')
    return config.get(config_name, config['default']) 