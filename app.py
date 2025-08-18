from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
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
import sys
from config import get_config
from yara_cache import yara_cache

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
            file_path TEXT,
            description TEXT
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
    
    # Add description column if it doesn't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE executables ADD COLUMN description TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
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
    """Scan a file with all available YARA rules using cache"""
    matches = []
    
    # Get compiled rules from cache
    compiled_rules = yara_cache.get_compiled_rules()
    total_rules = len(compiled_rules)
    
    # Scan the file with all rules
    rules_checked = 0
    for rule_path, compiled_rule in compiled_rules.items():
        rules_checked += 1
        try:
            file_matches = compiled_rule.match(file_path)
            for match in file_matches:
                # Extract rule name and folder from path
                rule_name = os.path.splitext(os.path.basename(rule_path))[0]
                folder_name = os.path.basename(os.path.dirname(rule_path))
                
                matches.append({
                    'rule_name': rule_name,
                    'rule_file': f"{folder_name}/{rule_name}",
                    'match_strings': str(match.strings) if match.strings else '',
                    'match_offset': match.offset if hasattr(match, 'offset') else 0
                })
        except Exception as e:
            print(f"Error scanning with rule {rule_path}: {e}")
    
    return matches, total_rules, rules_checked

def find_similar_files(executable_id, min_common_rules=None):
    """Find files with exactly the same set of YARA rule matches"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    # Get current file's YARA matches
    cursor.execute('''
        SELECT rule_name FROM yara_matches 
        WHERE executable_id = ?
        ORDER BY rule_name
    ''', (executable_id,))
    current_rules = {row[0] for row in cursor.fetchall()}
    
    if not current_rules:
        conn.close()
        return []
    
    # Convert current rules to a sorted string for comparison
    current_rules_str = ','.join(sorted(current_rules))
    current_rules_count = len(current_rules)
    
    print(f"DEBUG: Looking for files with exactly {current_rules_count} rules: {current_rules_str}")
    
    # Find files with exactly the same set of YARA rule matches
    cursor.execute('''
        SELECT e.id, e.filename, e.file_hash, e.upload_date,
               COUNT(ym.rule_name) as rule_count,
               GROUP_CONCAT(ym.rule_name ORDER BY ym.rule_name) as rule_names
        FROM executables e
        JOIN yara_matches ym ON e.id = ym.executable_id
        WHERE e.id != ?
        GROUP BY e.id
        HAVING rule_count = ? AND GROUP_CONCAT(ym.rule_name ORDER BY ym.rule_name) = ?
        ORDER BY e.upload_date DESC
    ''', (executable_id, current_rules_count, current_rules_str))
    
    similar_files = []
    for row in cursor.fetchall():
        similar_files.append({
            'id': row[0],
            'filename': row[1],
            'file_hash': row[2],
            'upload_date': row[3],
            'common_rules': row[4],  # This will always equal current_rules_count
            'rule_names': row[5].split(',') if row[5] else []
        })
    
    print(f"DEBUG: Found {len(similar_files)} files with exact YARA rule matches")
    
    conn.close()
    return similar_files

def find_files_with_common_rules(executable_id, min_common_rules=None):
    """Find files that share some YARA rules with the current file (for reference)"""
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
    
    # Find files with some common rules (but not exact matches)
    cursor.execute('''
        SELECT e.id, e.filename, e.file_hash, e.upload_date,
               COUNT(ym.rule_name) as common_rules,
               GROUP_CONCAT(ym.rule_name) as rule_names
        FROM executables e
        JOIN yara_matches ym ON e.id = ym.executable_id
        WHERE e.id != ? AND ym.rule_name IN ({})
        GROUP BY e.id
        HAVING common_rules >= ?
        ORDER BY common_rules DESC, e.upload_date DESC
    '''.format(','.join(['?'] * len(current_rules)), min_common_rules), 
    (executable_id,) + tuple(current_rules) + (min_common_rules,))
    
    common_rule_files = []
    for row in cursor.fetchall():
        common_rule_files.append({
            'id': row[0],
            'filename': row[1],
            'file_hash': row[2],
            'upload_date': row[3],
            'common_rules': row[4],
            'rule_names': row[5].split(',') if row[5] else []
        })
    
    conn.close()
    return common_rule_files

def rescan_all_files_with_new_rule(rule_path, rule_filename, folder_name):
    """Re-scan all existing files with a newly uploaded YARA rule"""
    try:
        # Get the compiled rule
        compiled_rules = yara_cache.get_compiled_rules()
        if rule_path not in compiled_rules:
            print(f"Warning: Rule {rule_filename} not found in compiled rules")
            flash(f'Warning: Rule {rule_filename} not found in compiled rules', 'warning')
            return
        
        compiled_rule = compiled_rules[rule_path]
        rule_name = os.path.splitext(rule_filename)[0]
        
        print(f"Re-scanning with rule: {rule_name} from {rule_path}")
        
        # Get all existing files
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        cursor.execute('SELECT id, file_path FROM executables')
        files = cursor.fetchall()
        
        print(f"Found {len(files)} existing files to re-scan")
        
        new_matches_count = 0
        files_scanned = 0
        
        for file_id, file_path in files:
            if os.path.exists(file_path):
                try:
                    files_scanned += 1
                    # Scan the file with the new rule
                    matches = compiled_rule.match(file_path)
                    
                    print(f"File {file_id}: {os.path.basename(file_path)} - Found {len(matches)} matches")
                    
                    for match in matches:
                        # Check if this match already exists
                        cursor.execute('''
                            SELECT id FROM yara_matches 
                            WHERE executable_id = ? AND rule_name = ?
                        ''', (file_id, rule_name))
                        
                        existing_match = cursor.fetchone()
                        
                        if not existing_match:
                            # Add new match
                            cursor.execute('''
                                INSERT INTO yara_matches (executable_id, rule_name, rule_file, match_strings, match_offset)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (file_id, rule_name, f"{folder_name}/{rule_name}", 
                                  str(match.strings) if match.strings else '', 
                                  match.offset if hasattr(match, 'offset') else 0))
                            new_matches_count += 1
                            print(f"  -> Added new match for file {file_id}")
                        else:
                            print(f"  -> Match already exists for file {file_id}")
                
                except Exception as e:
                    print(f"Error scanning file {file_path} with rule {rule_filename}: {e}")
        
        conn.commit()
        conn.close()
        
        print(f"Re-scan complete: {files_scanned} files scanned, {new_matches_count} new matches found")
        
        if new_matches_count > 0:
            flash(f'Re-scanned all files with new rule "{rule_name}". Found {new_matches_count} additional matches.', 'success')
        else:
            flash(f'Re-scanned all files with new rule "{rule_name}". No additional matches found.', 'info')
            
    except Exception as e:
        print(f"Error during file re-scan: {e}")
        flash(f'Warning: Error during file re-scan: {str(e)}', 'warning')

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
        
        # Get description from form
        description = request.form.get('description', '').strip()
        
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
            INSERT INTO executables (filename, file_hash, file_size, file_path, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file_hash, file_size, file_path, description))
        
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

@app.route('/file/<int:file_id>/update_description', methods=['POST'])
def update_file_description(file_id):
    """Update file description"""
    try:
        description = request.form.get('description', '').strip()
        
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Update the description
        cursor.execute('UPDATE executables SET description = ? WHERE id = ?', (description, file_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Description updated successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/files')
def list_files():
    """List all uploaded files"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT e.id, e.filename, e.file_hash, e.file_size, e.upload_date, e.file_path, e.description, COUNT(ym.id) as yara_count
        FROM executables e
        LEFT JOIN yara_matches ym ON e.id = ym.executable_id
        GROUP BY e.id, e.filename, e.file_hash, e.file_size, e.upload_date, e.file_path, e.description
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
            
            # Add to cache
            folder_name = 'custom_rules'
            if yara_cache.add_rule(file_path, rule_content, folder_name):
                flash(f'YARA rule "{filename}" uploaded successfully and added to cache!', 'success')
                
                # Force cache refresh to ensure the new rule is available
                yara_cache.get_rules(force_refresh=True)
                
                # Small delay to ensure cache is fully updated
                import time
                time.sleep(0.5)
                
                # Re-scan all existing files with the new rule
                rescan_all_files_with_new_rule(file_path, filename, folder_name)
                
            else:
                flash(f'YARA rule "{filename}" uploaded but failed to add to cache.', 'warning')
            
            return redirect(url_for('upload_yara_rule'))
            
        except Exception as e:
            flash(f'Error uploading YARA rule: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload_yara_rule.html')

@app.route('/yara_rules')
def list_yara_rules():
    """List all YARA rules loaded in the system with client-side pagination"""
    # Get per_page parameter for initial display
    per_page = request.args.get('per_page', 50, type=int)
    
    # Validate per_page against allowed options
    if per_page not in app.config['PAGINATION_OPTIONS']:
        per_page = 50
    
    # Get all rules from cache
    all_rules = yara_cache.get_rules()
    
    # Get cache statistics
    cache_stats = yara_cache.get_cache_stats()
    
    return render_template('yara_rules.html', 
                         rules=all_rules,  # Pass all rules for client-side pagination
                         pagination={
                             'per_page': per_page,
                             'total_rules': len(all_rules),
                             'options': app.config['PAGINATION_OPTIONS']
                         },
                         cache_stats=cache_stats)

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
        
        # Get rule from cache
        rule_info = yara_cache.get_rule_by_path(decoded_path)
        
        if not rule_info:
            flash('Rule not found in cache', 'error')
            return redirect(url_for('list_yara_rules'))
        
        return render_template('view_yara_rule.html', 
                             rule_name=rule_info['name'],
                             folder_name=rule_info['folder'],
                             rule_content=rule_info['content'],
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
        
        # Get total rules from cache
        cache_stats = yara_cache.get_cache_stats()
        total_rules = cache_stats['total_rules']
        
        return jsonify({
            'file_id': file_id,
            'filename': filename,
            'file_size': file_size,
            'total_rules': total_rules,
            'status': 'ready'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/yara_cache/refresh', methods=['POST'])
def refresh_yara_cache():
    """Manually refresh the YARA cache"""
    try:
        yara_cache.get_rules(force_refresh=True)
        flash('YARA cache refreshed successfully!', 'success')
    except Exception as e:
        flash(f'Error refreshing YARA cache: {str(e)}', 'error')
    
    return redirect(url_for('list_yara_rules'))

@app.route('/yara_cache/stats')
def get_cache_stats():
    """Get YARA cache statistics"""
    try:
        stats = yara_cache.get_cache_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/yara_rule/<path:rule_path>/delete', methods=['POST'])
def delete_yara_rule(rule_path):
    """Delete a YARA rule from the filesystem and cache"""
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
            return jsonify({'success': False, 'error': 'Invalid rule path'}), 400
        
        # Check if file exists
        if not os.path.exists(decoded_path):
            return jsonify({'success': False, 'error': 'Rule file not found'}), 404
        
        # Get rule info before deletion
        rule_info = yara_cache.get_rule_by_path(decoded_path)
        if not rule_info:
            return jsonify({'success': False, 'error': 'Rule not found in cache'}), 404
        
        rule_name = rule_info['name']
        rule_filename = rule_info['filename']
        
        # Check if this is a submodule rule (should not be deleted)
        if rule_info.get('is_submodule', False):
            return jsonify({'success': False, 'error': 'Cannot delete submodule rules. Only custom rules can be deleted.'}), 403
        
        # Remove from cache first
        if not yara_cache.remove_rule(decoded_path):
            return jsonify({'success': False, 'error': 'Failed to remove rule from cache'}), 500
        
        # Delete the physical file
        try:
            os.remove(decoded_path)
        except OSError as e:
            # If file deletion fails, try to re-add to cache
            yara_cache.add_rule(decoded_path, rule_info['content'], rule_info['folder'])
            return jsonify({'success': False, 'error': f'Failed to delete file: {str(e)}'}), 500
        
        # Remove any YARA matches from database that reference this rule
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Delete matches for this rule
        cursor.execute('DELETE FROM yara_matches WHERE rule_file LIKE ?', (f"%{rule_name}",))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': f'YARA rule "{rule_filename}" deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
    """Download all YARA rules as a compressed ZIP file"""
    try:
        import zipfile
        import tempfile
        from io import BytesIO
        
        yara_folder = app.config['YARA_FOLDER']
        
        if not os.path.exists(yara_folder):
            flash('YARA rules folder not found', 'error')
            return redirect(url_for('index'))
        
        # Create a temporary file for the ZIP
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        # Create ZIP file
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the yara-rules directory
            for root, dirs, files in os.walk(yara_folder):
                # Skip .git directories
                if '.git' in dirs:
                    dirs.remove('.git')
                
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        file_path = os.path.join(root, file)
                        
                        # Calculate relative path from yara-rules folder
                        rel_path = os.path.relpath(file_path, yara_folder)
                        
                        # Add file to ZIP with relative path
                        zipf.write(file_path, rel_path)
        
        # Read the ZIP file content
        with open(temp_zip.name, 'rb') as f:
            zip_content = f.read()
        
        # Clean up temporary file
        os.unlink(temp_zip.name)
        
        # Create response with ZIP file
        response = BytesIO(zip_content)
        response.seek(0)
        
        # Get current timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'yara_rules_{timestamp}.zip'
        
        return send_file(
            response,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f'Error creating YARA rules archive: {str(e)}', 'error')
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
    
    # Pre-load YARA cache for better performance
    print("Initializing YARA cache...")
    try:
        yara_cache.get_rules(force_refresh=True)
        cache_stats = yara_cache.get_cache_stats()
        print(f"YARA cache initialized: {cache_stats['total_rules']} rules loaded ({cache_stats['valid_rules']} valid, {cache_stats['invalid_rules']} invalid)")
    except Exception as e:
        print(f"Warning: Failed to initialize YARA cache: {e}")
    
    print(f"Starting Cyberdome Sentinel on {app.config['HOST']}:{app.config['PORT']}")
    # Disable reloader/debugger if not attached to a TTY to avoid termios errors
    run_kwargs = {
        'host': app.config['HOST'],
        'port': app.config['PORT'],
        'debug': app.config['DEBUG']
    }
    if not sys.stdin.isatty():
        run_kwargs.update({'use_reloader': False, 'use_debugger': False})
    else:
        # Still prefer no reloader to avoid double-process issues
        run_kwargs.setdefault('use_reloader', False)
    app.run(**run_kwargs) 