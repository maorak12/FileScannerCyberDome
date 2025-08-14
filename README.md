# File Scanner CyberDome

A powerful web-based file scanner that uses YARA rules to detect malicious patterns in executable files and identify similar files based on shared YARA rule matches.

## Features

- **File Upload & Scanning**: Drag-and-drop interface for uploading executable files
- **YARA Rule Scanning**: Comprehensive malware detection using industry-standard YARA rules
- **Similar File Detection**: Find files with similar YARA rule matches for threat correlation
- **Real-time Progress**: Live progress tracking during file scanning
- **File Management**: Browse, search, and delete uploaded files
- **Custom YARA Rules**: Upload and manage your own YARA rules
- **YARA Rule Browser**: View and preview all loaded YARA rules with syntax highlighting
- **Performance Optimization**: Intelligent caching system for fast YARA rule loading
- **Pagination Support**: Efficient browsing of large rule collections

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **YARA Engine**: yara-python
- **Frontend**: Bootstrap 5, Font Awesome, JavaScript
- **Caching**: Thread-safe in-memory cache with automatic refresh

## Installation

### Prerequisites

- Python 3.7+
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd FileScannerCyberDome
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## First Time Setup

1. **Initialize YARA Rules with Git Submodules**:
   ```bash
   # Navigate to the yara-rules directory
   cd yara-rules
   
   # Initialize the signature-base submodule
   git submodule add https://github.com/Neo23x0/signature-base.git signature_base
   
   # Update and initialize the submodule
   git submodule update --init --recursive
   
   # Return to the main directory
   cd ..
   ```
   
   **Alternative**: Use the web interface:
- Run the application: `python app.py`
- Navigate to the YARA Rules page
- Click "Update Submodule" to initialize the Git submodule

**Or use the setup script**:
```bash
python setup_yara_submodule.py
```

2. **Setup YARA Ruleset Folders**: The application will automatically create the following folder structure:
   ```
   yara-rules/
   ├── signature_base/    # Git submodule (Neo23x0 signature-base)
   │   └── yara/          # YARA rules from submodule
   └── custom_rules/      # Your custom YARA rules
   ```

3. **Upload Files**: Start uploading executable files for scanning.

## Usage

### File Scanning

1. **Upload a file** using the drag-and-drop interface
2. **Automatic scanning** with all available YARA rules
3. **View results** including matched rules and similar files
4. **File management** through the Files page

### YARA Rule Management

1. **Browse Rules**: View all loaded YARA rules with status indicators
2. **Rule Preview**: Hover over rules to see syntax-highlighted previews
3. **Upload Custom Rules**: Add your own YARA rules with automatic validation
4. **Cache Management**: Monitor cache performance and refresh when needed

### Performance Features

- **Intelligent Caching**: YARA rules are cached at startup for instant access
- **Automatic Refresh**: Cache refreshes automatically every 5 minutes
- **Pagination**: Browse rules in configurable page sizes (10, 50, 100)
- **Search & Sort**: Find rules quickly with real-time search and sorting

## Configuration

### Environment Variables

The application can be configured using environment variables:

```bash
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key
FLASK_DEBUG=true

# File Upload Configuration
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=104857600  # 100MB in bytes

# YARA Configuration
YARA_FOLDER=./yara-rules
YARA_RULESET_FOLDERS=yara-rules/signature_base/yara,yara-rules/custom_rules
YARA_REPO_URL=https://github.com/Neo23x0/signature-base.git
YARA_SUBMODULE_PATH=./yara-rules/signature_base
MIN_COMMON_RULES=2

# Cache Configuration
YARA_CACHE_ENABLED=true
YARA_CACHE_REFRESH_INTERVAL=300  # 5 minutes in seconds

# Server Configuration
HOST=0.0.0.0
PORT=5000

# Database Configuration
DATABASE_PATH=filescanner.db

# UI Configuration
ITEMS_PER_PAGE=50
```

### Default Configuration

```python
# File paths
UPLOAD_FOLDER = 'uploads'        # Uploaded files directory
YARA_FOLDER = './yara-rules'     # Default YARA rules directory
YARA_RULESET_FOLDERS = [         # List of YARA ruleset directories
    './yara-rules/signature_base/yara',  # Git submodule directory
    './yara-rules/custom_rules',         # Custom rules directory
    './yara-rules'
]
YARA_SUBMODULE_PATH = './yara-rules/signature_base'  # Git submodule path

# Performance settings
YARA_CACHE_ENABLED = True        # Enable YARA rule caching
YARA_CACHE_REFRESH_INTERVAL = 300  # Cache refresh interval (seconds)
PAGINATION_OPTIONS = [10, 50, 100]  # Available page size options
```

## YARA Rules

The application supports multiple YARA ruleset folders for comprehensive malware detection:

- **`yara-rules/signature_base/yara`**: Git submodule from Neo23x0 signature-base (read directly, not copied)
- **`yara-rules/custom_rules`**: Custom YARA rules uploaded by users
- **`yara-rules`**: Additional rules directory

### Git Submodule Benefits

- **Direct Access**: Rules are read directly from their source directories
- **Version Control**: Easy to update and track rule changes
- **No Duplication**: Rules aren't copied to separate folders
- **Automatic Updates**: Use `git submodule update` to get latest rules

### Git Submodule Management

The application uses Git submodules to manage YARA rules from the [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) repository, which contains:

- **Malware signatures** for various families
- **Packer detection** rules
- **Obfuscation techniques** identification
- **Suspicious behavior** patterns

**Benefits of Submodule Approach**:
- Rules are read directly from source directories
- Easy version control and updates
- No file duplication
- Automatic tracking of rule changes

### Custom Rules

You can add your own YARA rules by placing `.yar` or `.yara` files in any of the configured ruleset folders. The application will automatically compile and use all rules from all configured folders.

### Rule Validation

All YARA rules are automatically validated for:
- **Syntax correctness**
- **Compilation success**
- **File readability**

Rules that fail validation are marked accordingly in the interface.

## Database Schema

### Tables

#### `executables`
- `id`: Primary key
- `filename`: Original filename
- `file_hash`: SHA256 hash (unique)
- `file_size`: File size in bytes
- `upload_date`: Upload timestamp
- `file_path`: Filesystem path

#### `yara_matches`
- `id`: Primary key
- `executable_id`: Foreign key to executables
- `rule_name`: YARA rule name
- `rule_file`: Rule file path
- `match_strings`: Matched strings
- `match_offset`: Match offset in file

## API Endpoints

- `GET /` - Main page with file upload
- `POST /upload` - File upload and scanning
- `GET /files` - List all uploaded files
- `GET /file/<id>` - File details and matches
- `POST /file/<id>/delete` - Delete a file
- `GET /yara_rules` - List all YARA rules
- `GET /yara_rule/<path>` - View specific YARA rule
- `GET /upload_yara_rule` - Upload custom YARA rule form
- `POST /upload_yara_rule` - Process YARA rule upload
- `GET /download_yara_rules` - Initialize/update YARA rules Git submodule
- `POST /yara_cache/refresh` - Manually refresh YARA cache
- `GET /yara_cache/stats` - Get cache statistics

## Supported File Types

- **Executables**: `.exe`, `.dll`, `.sys`, `.scr`, `.com`
- **Scripts**: `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`
- **Other**: Any file type that YARA rules can analyze

## Performance & Scalability

### Caching System

- **Startup Optimization**: YARA rules are pre-loaded and cached at application startup
- **Memory Efficiency**: Compiled rules are stored in memory for fast scanning
- **Automatic Refresh**: Cache refreshes automatically to detect new rules
- **Error Handling**: Failed rules are logged and don't affect scanning performance

### Pagination

- **Configurable Page Sizes**: Choose between 10, 50, or 100 rules per page
- **Efficient Navigation**: Smart pagination with ellipsis for large rule sets
- **URL Persistence**: Page size and current page are maintained in URL parameters

### Scanning Performance

- **Parallel Processing**: YARA rules are compiled once and reused
- **Progress Tracking**: Real-time updates during file scanning
- **Resource Management**: Efficient memory usage for large rule collections

## Troubleshooting

### Common Issues

1. **YARA rules not loading**
   - Verify Git submodule was initialized: `git submodule status`
   - Check if submodule directory exists: `yara-rules/signature_base/`
   - Ensure submodule is up to date: `git submodule update --init --recursive`
   - Check folder permissions
   - Review application logs for cache errors

2. **Slow performance**
   - Ensure YARA cache is enabled
   - Check cache refresh interval settings
   - Monitor memory usage for large rule collections

3. **Rule compilation errors**
   - Validate YARA rule syntax
   - Check for missing dependencies
   - Review rule-specific error messages

### Cache Management

- **Manual Refresh**: Use the refresh button in the YARA Rules page
- **Cache Statistics**: Monitor cache performance through the interface
- **Error Logging**: Check logs for detailed cache operation information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **YARA Project**: For the powerful pattern matching engine
- **Neo23x0**: For the comprehensive signature-base repository
- **Flask Community**: For the excellent web framework
- **Bootstrap Team**: For the responsive UI framework 
