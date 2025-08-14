# File Scanner CyberDome

A powerful web-based file scanner that uses YARA rules to detect malicious patterns in executable files and identify similar files based on shared YARA rule matches.

## Features

- **YARA Rule Scanning**: Comprehensive malware detection using industry-standard YARA rules
- **File Upload & Analysis**: Drag-and-drop file upload with automatic YARA scanning
- **Similar File Detection**: Find files with similar YARA rule patterns to identify related malware families
- **SQLite Database**: Persistent storage of all scanned files and their YARA matches
- **Modern Web Interface**: Beautiful, responsive UI with Bootstrap 5 and Font Awesome icons
- **Export Functionality**: Export scan results to CSV or JSON format
- **Search & Sort**: Advanced file management with search and sorting capabilities
- **Automatic YARA Rules**: Download and extract YARA rules from Neo23x0 signature-base repository

## Screenshots

The application features a modern, cyber-themed interface with:
- Gradient backgrounds and glassmorphism effects
- Interactive file upload with drag-and-drop support
- Detailed file analysis pages showing YARA matches
- Similar file detection with shared rule highlighting
- Comprehensive file database with statistics

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd FileScannerCyberDome
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
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

## Usage

### First Time Setup

1. **Download YARA Rules**: Click the "Download YARA Rules" button to automatically fetch and extract YARA rules from the Neo23x0 signature-base repository.

2. **Setup YARA Ruleset Folders**: The application will automatically create the following folder structure:
   ```
   yara-rules/
   ├── signature_base/
   │   └── yara/          # Neo23x0 signature-base rules
   ├── custom_rules/      # Your custom YARA rules
   └── ./yara-rules       # Downloaded rules
   ```

3. **Upload Files**: Use the drag-and-drop interface or click to browse for executable files to scan.

### File Scanning

1. **Upload an executable file** (.exe, .dll, .sys, .scr, .com, .bat, .cmd, .ps1, .vbs, .js)
2. **Automatic scanning** with all available YARA rules
3. **View results** including:
   - File information (hash, size, upload date)
   - YARA rule matches with details
   - Similar files found in the database
   - Analysis summary and status

### File Management

- **View All Files**: Browse all uploaded files with search and sort functionality
- **File Details**: Click on any file to view detailed analysis
- **Export Data**: Export scan results to CSV or JSON format
- **Similar File Detection**: Automatically find files with shared YARA rule patterns

## Database Schema

The application uses SQLite with two main tables:

### `executables`
- `id`: Primary key
- `filename`: Original filename
- `file_hash`: SHA256 hash (unique)
- `file_size`: File size in bytes
- `upload_date`: Timestamp of upload
- `file_path`: Local file path

### `yara_matches`
- `id`: Primary key
- `executable_id`: Foreign key to executables
- `rule_name`: Name of the matched YARA rule
- `rule_file`: Source YARA rule file
- `match_strings`: Matched strings (if any)
- `match_offset`: Match offset in file

## YARA Rules

The application supports multiple YARA ruleset folders for comprehensive malware detection:

### Default Ruleset Folders
- **`yara-rules/signature_base/yara`**: Neo23x0 signature-base rules
- **`yara-rules/custom_rules`**: Custom YARA rules
- **`./yara-rules`**: Default folder for downloaded rules

### Automatic Rule Download
The application automatically downloads YARA rules from the [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) repository, which contains:

- **APT malware signatures**
- **Ransomware detection rules**
- **Trojan and backdoor patterns**
- **Malware family signatures**
- **Suspicious behavior patterns**

### Custom Rules
You can add your own YARA rules by placing `.yar` or `.yara` files in any of the configured ruleset folders. The application will automatically compile and use all rules from all configured folders.

## Security Features

- **File hash deduplication**: Prevents duplicate scans of identical files
- **Secure file handling**: Uses secure_filename for safe file operations
- **File size limits**: Configurable maximum file size (default: 100MB)
- **Isolated uploads**: Files stored in separate uploads directory

## Configuration

Key configuration options in `config.py`:

```python
# File Upload Configuration
UPLOAD_FOLDER = 'uploads'           # File upload directory
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # Max file size (100MB)

# YARA Configuration
YARA_FOLDER = './yara-rules'        # Default YARA rules directory
YARA_RULESET_FOLDERS = [            # List of YARA ruleset directories
    'yara-rules/signature_base/yara',
    'yara-rules/custom_rules',
    './yara-rules'
]
MIN_COMMON_RULES = 2                # Minimum rules for similar file detection

# Server Configuration
HOST = '0.0.0.0'                   # Server host
PORT = 5000                         # Server port
```

You can also configure these via environment variables:
- `YARA_RULESET_FOLDERS`: Comma-separated list of YARA ruleset folders
- `FLASK_ENV`: Set to 'development', 'production', or 'testing'
- `MAX_CONTENT_LENGTH`: Maximum file upload size in bytes

## API Endpoints

- `GET /` - Main page with file upload
- `POST /upload` - File upload and YARA scanning
- `GET /file/<id>` - File details and analysis
- `GET /files` - List all scanned files
- `GET /download_yara_rules` - Download YARA rules from repository

## File Types Supported

- **Executables**: .exe, .dll, .sys, .scr, .com
- **Scripts**: .bat, .cmd, .ps1, .vbs, .js
- **Other**: Any file type that YARA rules can analyze

## Performance Considerations

- **YARA rule compilation**: Rules are compiled once and reused
- **Database indexing**: File hashes are indexed for fast lookups
- **File deduplication**: Identical files are not rescanned
- **Efficient queries**: Optimized SQL queries for similar file detection

## Troubleshooting

### Common Issues

1. **YARA rules not loading**
   - Check if the YARA folder exists
   - Verify YARA rules were downloaded successfully
   - Check file permissions

2. **File upload errors**
   - Verify file size is under the limit (100MB)
   - Check uploads directory permissions
   - Ensure file type is supported

3. **Database errors**
   - Check if `filescanner.db` file exists
   - Verify SQLite is working properly
   - Check file permissions

### Debug Mode

Run with debug mode for detailed error information:
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **Neo23x0**: For providing the comprehensive YARA signature-base
- **YARA**: For the powerful pattern matching engine
- **Flask**: For the web framework
- **Bootstrap**: For the responsive UI components

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the code comments
3. Open an issue on the repository
4. Check the Flask and YARA documentation

---

**File Scanner CyberDome** - Advanced malware detection through YARA rule analysis 
