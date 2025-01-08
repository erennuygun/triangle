from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, send_from_directory
import google.generativeai as genai
import os
import json
import re
from typing import List, Dict
from functools import wraps
import bcrypt
import sqlite3
import zipfile
from pathlib import Path
from werkzeug.utils import secure_filename
import tempfile
import shutil
from datetime import datetime
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = 'c26d0e5c6a7380f6c4f4a7a3d8a0f4b2'

# Veritabanı yapılandırması
DATABASE = 'database.db'

# Login decorator tanımı
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Önce tabloları sil
        c.execute('DROP TABLE IF EXISTS vulnerabilities')
        c.execute('DROP TABLE IF EXISTS scans')
        c.execute('DROP TABLE IF EXISTS users')
        
        # Tabloları yeniden oluştur
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_name TEXT NOT NULL,
            total_files INTEGER NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            solution TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_name TEXT NOT NULL,
            line_number INTEGER,
            line_content TEXT,
            source TEXT NOT NULL,
            code_context TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        ''')
        
        # Admin kullanıcısını ekle
        c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not c.fetchone():
            hashed_password = bcrypt.hashpw('Test.12345!'.encode('utf-8'), bcrypt.gensalt())
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     ('admin', hashed_password, 'admin'))
        
        conn.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def analyze_file(file_path: str, file_name: str) -> Dict:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code_content = f.read()
            code_lines = code_content.splitlines()
        
        print("Dosya okundu:", file_name)
        
        vulnerabilities = []
        
        # Statik analiz
        static_vulns = find_vulnerabilities_with_rules(code_content, file_name)
        print("Statik analiz sonuçları:", len(static_vulns))
        
        # Her zafiyet için kod bloğunu ekle
        for vuln in static_vulns:
            if vuln.get('line_number'):
                line_num = vuln['line_number']
                start_line = max(0, line_num - 10)
                end_line = min(len(code_lines), line_num + 10)
                
                code_block = []
                for i in range(start_line, end_line):
                    code_block.append({
                        'line_number': i + 1,
                        'content': code_lines[i],
                        'is_vulnerable': i + 1 == line_num
                    })
                vuln['code_context'] = code_block
            vulnerabilities.append(vuln)
        
        # AI analiz
        ai_vulns = analyze_with_ai(code_content, file_name)
        print("AI analiz sonuçları:", len(ai_vulns))
        
        # AI zafiyetleri için de kod bloğunu ekle
        for vuln in ai_vulns:
            if vuln.get('line_number'):
                line_num = vuln['line_number']
                start_line = max(0, line_num - 10)
                end_line = min(len(code_lines), line_num + 10)
                
                code_block = []
                for i in range(start_line, end_line):
                    code_block.append({
                        'line_number': i + 1,
                        'content': code_lines[i],
                        'is_vulnerable': i + 1 == line_num
                    })
                vuln['code_context'] = code_block
            vulnerabilities.append(vuln)
        
        print("Toplam zafiyet sayısı:", len(vulnerabilities))
        
        return {
            'success': True,
            'vulnerabilities': vulnerabilities
        }
    except Exception as e:
        print("Analiz hatası:", str(e))
        return {
            'success': False,
            'error': str(e)
        }

def analyze_with_ai(code_content: str, file_name: str) -> List[Dict]:
    prompt = f"""
    Aşağıdaki kodu güvenlik açısından analiz et ve potansiyel güvenlik açıklarını bul.
    Her bir güvenlik açığı için tam olarak şu formatta yanıt ver (başka format kullanma):

    ZAFIYET_ADI: [Zafiyet Adı]
    AÇIKLAMA: [Detaylı Açıklama]
    ÇÖZÜM_ÖNERİSİ: [Çözüm Önerisi]
    ÖNEM_DERECESİ: [CRITICAL, HIGH, MEDIUM veya LOW olarak belirt]
    DOSYA: {file_name}
    SATIR: [Eğer belirli bir satırda tespit edildiyse satır numarası, değilse 'Genel']

    Analiz edilecek kod:
    ```
    {code_content}
    ```
    """
    
    try:
        response = model.generate_content(prompt)
        ai_vulns = []
        
        if response.parts:
            text = response.parts[0].text.replace('**', '').replace('*', '')
            blocks = text.split('\n\n')
            
            for block in blocks:
                if not block.strip():
                    continue
                
                lines = block.split('\n')
                vuln = {
                    'source': 'ai_analysis',
                    'file_name': file_name
                }
                
                for line in lines:
                    if line.startswith('ZAFIYET_ADI:'):
                        vuln['name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('AÇÇIKLAMA:'):
                        vuln['description'] = line.split(':', 1)[1].strip()
                    elif line.startswith('ÇÖZÜM_ÖNERİSİ:'):
                        vuln['solution'] = line.split(':', 1)[1].strip()
                    elif line.startswith('ÖNEM_DERECESİ:'):
                        vuln['severity'] = line.split(':', 1)[1].strip()
                    elif line.startswith('SATIR:'):
                        try:
                            vuln['line_number'] = int(line.split(':', 1)[1].strip())
                        except:
                            vuln['line_number'] = None
                
                if all(k in vuln for k in ['name', 'description', 'solution', 'severity']):
                    ai_vulns.append(vuln)
        
        return ai_vulns
    except Exception as e:
        print(f"AI analiz hatası: {str(e)}")
        return []

def find_vulnerabilities_with_rules(code_content: str, file_name: str) -> List[Dict]:
    vulnerabilities = []
    lines = code_content.split('\n')
    
    for rule in SECURITY_RULES['rules']:
        for pattern in rule['patterns']:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vuln = {
                        'id': rule['id'],
                        'name': rule['name'],
                        'description': rule['description'],
                        'solution': rule['solution'],
                        'severity': rule['severity'],
                        'line_number': i,
                        'line_content': line.strip(),
                        'source': 'static_analysis',
                        'file_name': file_name
                    }
                    vulnerabilities.append(vuln)
    
    return vulnerabilities

def group_vulnerabilities(vulns: List[Dict]) -> List[Dict]:
    grouped = {}
    
    for vuln in vulns:
        key = f"{vuln['name'].lower()}_{vuln['file_name']}"
        if key not in grouped:
            grouped[key] = {
                'name': vuln['name'],
                'description': vuln['description'],
                'solution': vuln['solution'],
                'severity': vuln.get('severity', 'MEDIUM'),
                'file_name': vuln['file_name'],
                'locations': [],
                'sources': set()
            }
        
        if 'line_number' in vuln:
            grouped[key]['locations'].append({
                'line': vuln['line_number'],
                'content': vuln.get('line_content', '')
            })
        
        grouped[key]['sources'].add(vuln['source'])
    
    return [dict(v, sources=list(v['sources'])) for v in grouped.values()]

@app.route('/analyze', methods=['POST'])
@login_required
def analyze_endpoint():
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya yüklenmedi'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    try:
        filename = secure_filename(file.filename)
        
        # Geçici dizin oluştur
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            
            all_vulnerabilities = []
            
            # ZIP dosyası kontrolü
            if filename.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    extract_dir = os.path.join(temp_dir, 'extracted')
                    os.makedirs(extract_dir, exist_ok=True)
                    zip_ref.extractall(extract_dir)
                    
                    for root, _, files in os.walk(extract_dir):
                        for file_name in files:
                            if file_name.endswith(('.py', '.js', '.php', '.java', '.cpp', '.cs')):
                                file_path = os.path.join(root, file_name)
                                relative_path = os.path.relpath(file_path, extract_dir)
                                file_results = analyze_file(file_path, relative_path)
                                if file_results.get('success'):
                                    all_vulnerabilities.extend(file_results['vulnerabilities'])
            else:
                results = analyze_file(file_path, filename)
                if results.get('success'):
                    all_vulnerabilities = results['vulnerabilities']
            
            # Kullanıcı ID'sini al
            db = get_db()
            user = db.execute('SELECT id FROM users WHERE username = ?', 
                            (session['user'],)).fetchone()
            
            # Sonuçları veritabanına kaydet
            scan_id = save_scan_results(user['id'], filename, all_vulnerabilities)
            
            return jsonify({
                'success': True,
                'vulnerabilities': all_vulnerabilities
            })
            
    except Exception as e:
        print("Hata:", str(e))
        return jsonify({'error': str(e)}), 500

# .env dosyasını yükle
load_dotenv()

# API anahtarını kontrol et
api_key = os.getenv('GOOGLE_API_KEY')
if not api_key:
    raise ValueError("GOOGLE_API_KEY bulunamadı")

# Google AI modelini yapılandır
genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-pro')

# API'yi test et
try:
    response = model.generate_content("Test message")
    print("API bağlantısı başarılı")
except Exception as e:
    print("API hatası:", str(e))
    raise

# Güvenlik kurallarını yükle
with open('rules/security_rules.json', 'r', encoding='utf-8') as f:
    SECURITY_RULES = json.load(f)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))  # index yerine dashboard'a yönlendir
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error="Kullanıcı adı ve şifre gerekli")
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user'] = username
            return redirect(url_for('dashboard'))  # index yerine dashboard'a yönlendir
        else:
            return render_template('login.html', error="Geçersiz kullanıcı adı veya şifre")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # Tüm oturum verilerini temizle
    return redirect(url_for('login'))

@app.before_request
def before_request():
    # Login ve static dosyalar hariç tüm isteklerde oturum kontrolü yap
    if not session.get('user'):
        if request.endpoint and request.endpoint != 'login' and \
           not request.endpoint.startswith('static'):
            return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session.get('user'))

def save_scan_results(user_id, file_name, vulnerabilities):
    db = get_db()
    try:
        # Taramayı kaydet
        cursor = db.execute('''
            INSERT INTO scans (user_id, file_name, total_files)
            VALUES (?, ?, ?)
        ''', (user_id, file_name, 1))
        scan_id = cursor.lastrowid
        
        # Zafiyet sayılarını hesapla
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        # Zafiyetleri kaydet
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            severity_counts[severity] += 1
            
            db.execute('''
                INSERT INTO vulnerabilities 
                (scan_id, name, description, solution, severity, 
                file_name, line_number, line_content, code_context, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln.get('name', ''),
                vuln.get('description', ''),
                vuln.get('solution', ''),
                severity,
                vuln.get('file_name', ''),
                vuln.get('line_number'),
                vuln.get('line_content'),
                json.dumps(vuln.get('code_context')),
                vuln.get('source', 'static')
            ))
        
        # Zafiyet sayılarını güncelle
        db.execute('''
            UPDATE scans 
            SET critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?
            WHERE id = ?
        ''', (
            severity_counts['CRITICAL'],
            severity_counts['HIGH'],
            severity_counts['MEDIUM'],
            severity_counts['LOW'],
            scan_id
        ))
        
        db.commit()
        return scan_id
    except Exception as e:
        print("Hata:", str(e))
        return None

@app.route('/history')
@login_required
def scan_history():
    db = get_db()
    try:
        # Kullanıcının taramalarını al
        scans = db.execute('''
            SELECT 
                s.id, 
                s.scan_date, 
                s.file_name, 
                COALESCE(s.critical_count, 0) as critical_count,
                COALESCE(s.high_count, 0) as high_count, 
                COALESCE(s.medium_count, 0) as medium_count, 
                COALESCE(s.low_count, 0) as low_count,
                COUNT(v.id) as total_vulnerabilities
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
            GROUP BY s.id
            ORDER BY s.scan_date DESC
        ''', (session['user'],)).fetchall()
        
        # Row factory'yi dict'e çevir
        scans = [dict(row) for row in scans]
        
        # Tarihleri formatla
        for scan in scans:
            scan['scan_date'] = datetime.strptime(scan['scan_date'], '%Y-%m-%d %H:%M:%S')
            # Sayıları integer'a çevir
            scan['critical_count'] = int(scan['critical_count'])
            scan['high_count'] = int(scan['high_count'])
            scan['medium_count'] = int(scan['medium_count'])
            scan['low_count'] = int(scan['low_count'])
        
        return render_template('history.html', scans=scans)
    except Exception as e:
        print("Hata:", str(e))
        return render_template('history.html', scans=[], error="Veriler yüklenirken bir hata oluştu")

@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    db = get_db()
    try:
        # Tarama detaylarını al
        scan = db.execute('''
            SELECT s.*, u.username, datetime(s.scan_date) as scan_date
            FROM scans s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND u.username = ?
        ''', (scan_id, session['user'])).fetchone()
        
        if not scan:
            return redirect(url_for('scan_history'))
        
        # Row factory'yi dict'e çevir
        scan = dict(scan)
        
        # Tarihi datetime objesine çevir
        scan['scan_date'] = datetime.strptime(scan['scan_date'], '%Y-%m-%d %H:%M:%S')
        
        # Zafiyetleri al ve code_context'i parse et
        vulnerabilities = db.execute('''
            SELECT * FROM vulnerabilities 
            WHERE scan_id = ?
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        ''', (scan_id,)).fetchall()
        
        # Zafiyetleri dict'e çevir ve code_context'i parse et
        vulnerabilities = [dict(vuln) for vuln in vulnerabilities]
        for vuln in vulnerabilities:
            if vuln.get('code_context'):
                vuln['code_context'] = json.loads(vuln['code_context'])
        
        return render_template('scan_detail.html', scan=scan, vulnerabilities=vulnerabilities)
    except Exception as e:
        print("Hata:", str(e))
        return redirect(url_for('scan_history'))

@app.route('/documentation')
@login_required
def documentation():
    try:
        return render_template('documentation.html')
    except Exception as e:
        print("Dokümantasyon hatası:", str(e))
        return redirect(url_for('dashboard'))

@app.route('/about')
@login_required
def about():
    try:
        return render_template('about.html')
    except Exception as e:
        print("Hakkında hatası:", str(e))
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    try:
        # Toplam tarama sayısı
        total_scans = db.execute('''
            SELECT COUNT(*) as count FROM scans 
            WHERE user_id = (SELECT id FROM users WHERE username = ?)
        ''', (session['user'],)).fetchone()['count']
        
        # Toplam zafiyet sayısı
        total_vulnerabilities = db.execute('''
            SELECT COUNT(*) as count FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
        ''', (session['user'],)).fetchone()['count']
        
        # Son tarama tarihi
        last_scan = db.execute('''
            SELECT datetime(scan_date) as scan_date FROM scans 
            WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ORDER BY scan_date DESC LIMIT 1
        ''', (session['user'],)).fetchone()
        
        last_scan_date = datetime.strptime(last_scan['scan_date'], '%Y-%m-%d %H:%M:%S') if last_scan else None
        
        # Zafiyet istatistikleri
        vuln_stats_row = db.execute('''
            SELECT 
                COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical,
                COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) as high,
                COALESCE(SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) as medium,
                COALESCE(SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) as low
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
        ''', (session['user'],)).fetchone()

        # SQLite Row'u dictionary'ye çevir
        vuln_stats = dict(zip(['critical', 'high', 'medium', 'low'], 
                            [vuln_stats_row['critical'], vuln_stats_row['high'], 
                             vuln_stats_row['medium'], vuln_stats_row['low']]))
        
        # Risk skoru hesaplama (0-100 arası)
        if total_vulnerabilities > 0:
            risk_score = 100 - min(100, (
                (vuln_stats['critical'] * 10) + 
                (vuln_stats['high'] * 5) + 
                (vuln_stats['medium'] * 3) + 
                (vuln_stats['low'])
            ))
        else:
            risk_score = 100
        
        # Son taramalar
        recent_scans_rows = db.execute('''
            SELECT 
                s.id,
                s.file_name,
                datetime(s.scan_date) as scan_date,
                s.critical_count,
                s.high_count,
                s.medium_count,
                s.low_count
            FROM scans s
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
            ORDER BY s.scan_date DESC LIMIT 5
        ''', (session['user'],)).fetchall()
        
        # SQLite Row'ları dictionary'ye çevir ve tarihleri formatla
        recent_scans = []
        for row in recent_scans_rows:
            scan = dict(row)
            # Tarihi datetime objesine çevir
            scan_date = datetime.strptime(scan['scan_date'], '%Y-%m-%d %H:%M:%S')
            scan['scan_date'] = scan_date
            recent_scans.append(scan)

        # Kritik zafiyetler
        critical_vulns_rows = db.execute('''
            SELECT 
                v.id,
                v.name,
                v.description,
                v.file_name,
                v.severity,
                datetime(s.scan_date) as scan_date
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
            AND v.severity = 'CRITICAL'
            ORDER BY s.scan_date DESC LIMIT 5
        ''', (session['user'],)).fetchall()
        
        # SQLite Row'ları dictionary'ye çevir
        critical_vulnerabilities = []
        for row in critical_vulns_rows:
            vuln = dict(row)
            if 'scan_date' in vuln:
                scan_date = datetime.strptime(vuln['scan_date'], '%Y-%m-%d %H:%M:%S')
                vuln['scan_date'] = scan_date
            critical_vulnerabilities.append(vuln)

        # Trend analizi için son 7 günün verileri
        trend_data = db.execute('''
            SELECT DATE(scan_date) as date, COUNT(*) as count
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = (SELECT id FROM users WHERE username = ?)
            GROUP BY DATE(scan_date)
            ORDER BY date DESC LIMIT 7
        ''', (session['user'],)).fetchall()
        
        trend_dates = [row['date'] for row in trend_data][::-1]
        trend_counts = [row['count'] for row in trend_data][::-1]
        
        return render_template('dashboard.html',
            total_scans=total_scans,
            total_vulnerabilities=total_vulnerabilities,
            last_scan_date=last_scan_date.strftime('%d.%m.%Y %H:%M') if last_scan_date else 'Henüz tarama yok',
            vuln_stats=vuln_stats,
            risk_score=risk_score,
            recent_scans=recent_scans,
            critical_vulnerabilities=critical_vulnerabilities,
            trend_dates=trend_dates,
            trend_counts=trend_counts
        )
        
    except Exception as e:
        print("Dashboard hatası:", str(e))
        return render_template('dashboard.html', 
            error="Veriler yüklenirken bir hata oluştu",
            total_scans=0,
            total_vulnerabilities=0,
            last_scan_date='Henüz tarama yok',
            vuln_stats={'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            risk_score=100,
            recent_scans=[],
            critical_vulnerabilities=[],
            trend_dates=[],
            trend_counts=[]
        )

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.run(debug=True) 