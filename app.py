from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import sqlite3
import hashlib
import yara
from werkzeug.utils import secure_filename
import json
from datetime import datetime
import requests
import zipfile
import tempfile
import shutil
from config import get_config

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    config_class = get_config()
    app.config.from_object(config_class)
    config_class.init_app(app)
    
    return app

app = create_app()

def init_db():
    """Initialize the SQLite database"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS executables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT UNIQUE NOT NULL,
            file_size INTEGER,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS yara_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            executable_id INTEGER,
            rule_name TEXT NOT NULL,
            rule_file TEXT NOT NULL,
            match_strings TEXT,
            match_offset INTEGER,
            FOREIGN KEY (executable_id) REFERENCES executables (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def scan_file_with_yara(file_path):
    """Scan a file with all available YARA rules"""
    matches = []
    
    # First, count total YARA rules for progress tracking
    total_rules = 0
    yara_rules = {}
    
    # Compile all YARA rules from all configured folders
    for folder in app.config['YARA_RULESET_FOLDERS']:
        if folder.strip() and os.path.exists(folder.strip()):
            for root, dirs, files in os.walk(folder.strip()):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        total_rules += 1
                        try:
                            rule_path = os.path.join(root, file)
                            rule_name = os.path.splitext(file)[0]
                            # Use folder name as prefix to avoid conflicts
                            folder_name = os.path.basename(folder.strip())
                            unique_rule_name = f"{folder_name}_{rule_name}"
                            yara_rules[unique_rule_name] = yara.compile(rule_path)
                        except Exception as e:
                            print(f"Error compiling rule {file} from {folder}: {e}")
    
    # Scan the file with all rules
    rules_checked = 0
    for rule_name, compiled_rule in yara_rules.items():
        rules_checked += 1
        try:
            file_matches = compiled_rule.match(file_path)
            for match in file_matches:
                # Extract original rule name and folder from unique name
                if '_' in rule_name:
                    folder_name, original_rule_name = rule_name.split('_', 1)
                else:
                    folder_name = "unknown"
                    original_rule_name = rule_name
                
                matches.append({
                    'rule_name': original_rule_name,
                    'rule_file': f"{folder_name}/{original_rule_name}",
                    'match_strings': str(match.strings) if match.strings else '',
                    'match_offset': match.offset if hasattr(match, 'offset') else 0
                })
        except Exception as e:
            print(f"Error scanning with rule {rule_name}: {e}")
    
    return matches, total_rules, rules_checked

def find_similar_files(executable_id, min_common_rules=None):
    """Find files with similar YARA rule matches"""
    if min_common_rules is None:
        min_common_rules = app.config['MIN_COMMON_RULES']
    
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    # Get current file's YARA matches
    cursor.execute('''
        SELECT rule_name FROM yara_matches 
        WHERE executable_id = ?
    ''', (executable_id,))
    current_rules = {row[0] for row in cursor.fetchall()}
    
    if not current_rules:
        conn.close()
        return []
    
    # Find files with similar rules
    cursor.execute('''
        SELECT e.id, e.filename, e.file_hash, e.upload_date,
               COUNT(ym.rule_name) as common_rules,
               GROUP_CONCAT(ym.rule_name) as rule_names
        FROM executables e
        JOIN yara_matches ym ON e.id = ym.executable_id
        WHERE e.id != ? AND ym.rule_name IN ({})
        GROUP BY e.id
        HAVING common_rules >= ?
        ORDER BY common_rules DESC
    '''.format(','.join(['?'] * len(current_rules)), min_common_rules), 
    (executable_id,) + tuple(current_rules) + (min_common_rules,))
    
    similar_files = []
    for row in cursor.fetchall():
        similar_files.append({
            'id': row[0],
            'filename': row[1],
            'file_hash': row[2],
            'upload_date': row[3],
            'common_rules': row[4],
            'rule_names': row[5].split(',') if row[5] else []
        })
    
    conn.close()
    return similar_files

@app.route('/')
def index():
    """Main page with file upload form"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and YARA scanning"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Calculate file hash
        file_hash = get_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        # Check if file already exists
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM executables WHERE file_hash = ?', (file_hash,))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            flash('File already exists in database')
            return redirect(url_for('file_details', file_id=existing[0]))
        
        # Insert file into database
        cursor.execute('''
            INSERT INTO executables (filename, file_hash, file_size, file_path)
            VALUES (?, ?, ?, ?)
        ''', (filename, file_hash, file_size, file_path))
        
        executable_id = cursor.lastrowid
        
        # Scan file with YARA rules
        yara_matches, total_rules, rules_checked = scan_file_with_yara(file_path)
        
        # Store YARA matches
        for match in yara_matches:
            cursor.execute('''
                INSERT INTO yara_matches (executable_id, rule_name, rule_file, match_strings, match_offset)
                VALUES (?, ?, ?, ?, ?)
            ''', (executable_id, match['rule_name'], match['rule_file'], 
                  match['match_strings'], match['match_offset']))
        
        conn.commit()
        conn.close()
        
        flash(f'File uploaded successfully. Found {len(yara_matches)} YARA rule matches.')
        return redirect(url_for('file_details', file_id=executable_id))
    else:
        flash('Invalid file type. Allowed types: ' + ', '.join(app.config['ALLOWED_EXTENSIONS']))
        return redirect(request.url)

@app.route('/file/<int:file_id>')
def file_details(file_id):
    """Show file details and YARA matches"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    # Get file info
    cursor.execute('SELECT * FROM executables WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()
    
    if not file_info:
        conn.close()
        flash('File not found')
        return redirect(url_for('index'))
    
    # Get YARA matches
    cursor.execute('SELECT * FROM yara_matches WHERE executable_id = ?', (file_id,))
    yara_matches = cursor.fetchall()
    
    # Find similar files
    similar_files = find_similar_files(file_id)
    
    conn.close()
    
    return render_template('file_details.html', 
                         file_info=file_info, 
                         yara_matches=yara_matches,
                         similar_files=similar_files)

@app.route('/files')
def list_files():
    """List all uploaded files"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT e.*, COUNT(ym.id) as yara_count
        FROM executables e
        LEFT JOIN yara_matches ym ON e.id = ym.executable_id
        GROUP BY e.id
        ORDER BY e.upload_date DESC
    ''')
    
    files = cursor.fetchall()
    conn.close()
    
    return render_template('files.html', files=files)

@app.route('/upload_yara_rule', methods=['GET', 'POST'])
def upload_yara_rule():
    """Upload custom YARA rule"""
    if request.method == 'POST':
        if 'yara_file' not in request.files:
            flash('No YARA file selected', 'error')
            return redirect(request.url)
        
        file = request.files['yara_file']
        if file.filename == '':
            flash('No YARA file selected', 'error')
            return redirect(request.url)
        
        if not file.filename.endswith(('.yar', '.yara')):
            flash('Invalid file type. Only .yar and .yara files are allowed.', 'error')
            return redirect(request.url)
        
        try:
            # Read and validate the YARA rule content
            rule_content = file.read().decode('utf-8')
            
            # Try to compile the rule to validate it
            try:
                compiled_rule = yara.compile(source=rule_content)
                flash('YARA rule compiled successfully!', 'success')
            except Exception as e:
                flash(f'YARA rule compilation failed: {str(e)}', 'error')
                return redirect(request.url)
            
            # Save the rule to custom rules folder
            custom_rules_folder = os.path.join(app.config['YARA_FOLDER'], 'custom_rules')
            os.makedirs(custom_rules_folder, exist_ok=True)
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(custom_rules_folder, filename)
            
            # Check if file already exists
            if os.path.exists(file_path):
                flash('A YARA rule with this name already exists. Please use a different name.', 'error')
                return redirect(request.url)
            
            # Save the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)
            
            flash(f'YARA rule "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('upload_yara_rule'))
            
        except Exception as e:
            flash(f'Error uploading YARA rule: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload_yara_rule.html')

@app.route('/yara_rules')
def list_yara_rules():
    """List all YARA rules loaded in the system"""
    all_rules = []
    
    try:
        # Scan all configured YARA folders
        for folder in app.config['YARA_RULESET_FOLDERS']:
            if folder.strip() and os.path.exists(folder.strip()):
                folder_name = os.path.basename(folder.strip())
                for root, dirs, files in os.walk(folder.strip()):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            rule_path = os.path.join(root, file)
                            try:
                                # Try to read and compile the rule
                                with open(rule_path, 'r', encoding='utf-8') as f:
                                    rule_content = f.read()
                                
                                # Try to compile to validate
                                try:
                                    compiled_rule = yara.compile(source=rule_content)
                                    status = 'valid'
                                except Exception as e:
                                    status = 'invalid'
                                    rule_content = f"# Compilation Error: {str(e)}\n\n{rule_content}"
                                
                                all_rules.append({
                                    'name': os.path.splitext(file)[0],
                                    'filename': file,
                                    'folder': folder_name,
                                    'path': rule_path,
                                    'content': rule_content,
                                    'status': status,
                                    'size': os.path.getsize(rule_path)
                                })
                            except Exception as e:
                                all_rules.append({
                                    'name': os.path.splitext(file)[0],
                                    'filename': file,
                                    'folder': folder_name,
                                    'path': rule_path,
                                    'content': f"# Error reading file: {str(e)}",
                                    'status': 'error',
                                    'size': 0
                                })
        
        # Sort rules by folder and name
        all_rules.sort(key=lambda x: (x['folder'], x['name']))
        
    except Exception as e:
        flash(f'Error loading YARA rules: {str(e)}', 'error')
        all_rules = []
    
    return render_template('yara_rules.html', rules=all_rules)

@app.route('/yara_rule/<path:rule_path>')
def view_yara_rule(rule_path):
    """View a specific YARA rule content"""
    try:
        # Decode the URL-encoded path
        decoded_path = request.view_args['rule_path']
        
        # Security check: ensure the path is within YARA folders
        is_valid_path = False
        for folder in app.config['YARA_RULESET_FOLDERS']:
            if folder.strip() and os.path.exists(folder.strip()):
                if decoded_path.startswith(folder.strip()):
                    is_valid_path = True
                    break
        
        if not is_valid_path:
            flash('Invalid rule path', 'error')
            return redirect(url_for('list_yara_rules'))
        
        if not os.path.exists(decoded_path):
            flash('Rule file not found', 'error')
            return redirect(url_for('list_yara_rules'))
        
        # Read the rule content
        with open(decoded_path, 'r', encoding='utf-8') as f:
            rule_content = f.read()
        
        rule_name = os.path.basename(decoded_path)
        folder_name = os.path.basename(os.path.dirname(decoded_path))
        
        return render_template('view_yara_rule.html', 
                             rule_name=rule_name,
                             folder_name=folder_name,
                             rule_content=rule_content,
                             rule_path=decoded_path)
        
    except Exception as e:
        flash(f'Error viewing rule: {str(e)}', 'error')
        return redirect(url_for('list_yara_rules'))

@app.route('/scan_progress/<int:file_id>')
def get_scan_progress(file_id):
    """Get real-time scan progress for a file"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Get file info
        cursor.execute('SELECT filename, file_path FROM executables WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            conn.close()
            return jsonify({'error': 'File not found'}), 404
        
        filename, file_path = file_info
        conn.close()
        
        # Check if file exists and get its size
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on filesystem'}), 404
        
        file_size = os.path.getsize(file_path)
        
        # Count total YARA rules
        total_rules = 0
        for folder in app.config['YARA_RULESET_FOLDERS']:
            if folder.strip() and os.path.exists(folder.strip()):
                for root, dirs, files in os.walk(folder.strip()):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            total_rules += 1
        
        return jsonify({
            'file_id': file_id,
            'filename': filename,
            'file_size': file_size,
            'total_rules': total_rules,
            'status': 'ready'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/file/<int:file_id>/delete', methods=['POST'])
def delete_file(file_id):
    """Delete a file from the database and filesystem"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Get file information before deletion
        cursor.execute('SELECT filename, file_path FROM executables WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            conn.close()
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        filename, file_path = file_info
        
        # Delete YARA matches first (foreign key constraint)
        cursor.execute('DELETE FROM yara_matches WHERE executable_id = ?', (file_id,))
        
        # Delete the file record
        cursor.execute('DELETE FROM executables WHERE id = ?', (file_id,))
        
        # Commit the transaction
        conn.commit()
        conn.close()
        
        # Remove the physical file from filesystem
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError as e:
            print(f"Warning: Could not remove physical file {file_path}: {e}")
        
        return jsonify({'success': True, 'message': f'File "{filename}" deleted successfully'})
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download_yara_rules')
def download_yara_rules():
    """Download and extract YARA rules from Neo23x0 signature-base"""
    try:
        # Download the repository
        url = app.config['YARA_REPO_URL']
        response = requests.get(url)
        
        if response.status_code == 200:
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                tmp_file.write(response.content)
                tmp_file_path = tmp_file.name
            
            # Extract YARA rules
            with zipfile.ZipFile(tmp_file_path, 'r') as zip_ref:
                for file_info in zip_ref.filelist:
                    if file_info.filename.endswith(('.yar', '.yara')):
                        # Extract to the first YARA ruleset folder (usually the main one)
                        main_yara_folder = app.config['YARA_RULESET_FOLDERS'][0] if app.config['YARA_RULESET_FOLDERS'] else app.config['YARA_FOLDER']
                        zip_ref.extract(file_info, 'temp_extract')
                        source_path = os.path.join('temp_extract', file_info.filename)
                        target_path = os.path.join(main_yara_folder, os.path.basename(file_info.filename))
                        
                        if os.path.exists(source_path):
                            shutil.move(source_path, target_path)
            
            # Cleanup
            os.unlink(tmp_file_path)
            shutil.rmtree('temp_extract', ignore_errors=True)
            
            flash('YARA rules downloaded and extracted successfully!')
        else:
            flash('Failed to download YARA rules')
            
    except Exception as e:
        flash(f'Error downloading YARA rules: {str(e)}')
    
    return redirect(url_for('index'))

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash('File too large. Maximum size is {} MB'.format(app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)))
    return redirect(url_for('index')), 413

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

if __name__ == '__main__':
    init_db()
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    ) 