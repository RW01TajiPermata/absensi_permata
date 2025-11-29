from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import mysql.connector
import qrcode
from io import BytesIO, StringIO
import base64
import datetime
import secrets
import threading
import time
from werkzeug.security import generate_password_hash, check_password_hash
import re
import csv
import string
import random

app = Flask(__name__)
app.secret_key = 'absensi-permata-secret-key-2024'

# Konfigurasi database
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='ls4zzp.h.filess.io',
            user='absensi_permata_inventeddo',
            password='542d71cd4aa005eba4c81953fc47384f599b315f',
            database='absensi_permata_inventeddo',
            auth_plugin='mysql_native_password',
            port='3307'
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Simple QR Manager dengan interval 2 menit
class QRCodeManager:
    def __init__(self):
        self.update_interval = 120  # 2 menit dalam detik
        
    def start(self):
        print("QR Manager started")
        return True

qr_manager = QRCodeManager()

# Fungsi generate token
def generate_token(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Fungsi untuk memastikan admin ada dengan password yang benar
def ensure_admin_exists():
    conn = get_db_connection()
    if not conn:
        return False
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Cek apakah admin sudah ada
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if admin:
            # Test password admin123
            if check_password_hash(admin['password'], 'admin123'):
                print("✅ Admin exists with correct password")
                return True
            else:
                # Update password admin
                new_hash = generate_password_hash('admin123')
                cursor.execute("UPDATE users SET password = %s WHERE username = 'admin'", (new_hash,))
                conn.commit()
                print("✅ Admin password updated to 'admin123'")
                return True
        else:
            # Buat admin baru
            hashed_password = generate_password_hash('admin123')
            cursor.execute(
                "INSERT INTO users (username, password, nama_lengkap, nomor_telepon, rt, role) VALUES (%s, %s, %s, %s, %s, 'admin')",
                ('admin', hashed_password, 'Administrator Permata', '081234567890', '001')
            )
            conn.commit()
            print("✅ Admin user created with password 'admin123'")
            return True
            
    except Exception as e:
        print(f"❌ Error ensuring admin exists: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# Fungsi untuk cek apakah user sudah absen di event tertentu
def sudah_absen(user_id, event_id):
    conn = get_db_connection()
    if not conn:
        return True  # Untuk safety, anggap sudah absen jika koneksi gagal
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id FROM absensi WHERE user_id = %s AND event_id = %s", (user_id, event_id))
        absen = cursor.fetchone()
        return absen is not None
    except Exception as e:
        print(f"Error checking absensi: {e}")
        return True
    finally:
        cursor.close()
        conn.close()

# Routes untuk Lupa Sandi
@app.route('/lupa-sandi', methods=['GET', 'POST'])
def lupa_sandi():
    if request.method == 'POST':
        username = request.form['username']
        
        conn = get_db_connection()
        if not conn:
            flash('Koneksi database gagal!', 'error')
            return render_template('lupa_sandi.html')
            
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Cari user berdasarkan username
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user:
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                expires_at = datetime.datetime.now() + datetime.timedelta(minutes=30)  # Token berlaku 30 menit
                
                # Simpan token ke database
                cursor.execute(
                    "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                    (user['id'], reset_token, expires_at)
                )
                conn.commit()
                
                # Redirect ke halaman reset dengan token
                session['reset_token'] = reset_token
                session['reset_user_id'] = user['id']
                
                flash('Token reset password telah dibuat. Silakan buat password baru.', 'success')
                return redirect(url_for('reset_sandi', token=reset_token))
                
            else:
                flash('Username tidak ditemukan!', 'error')
                
        except Exception as e:
            flash('Terjadi kesalahan saat memproses permintaan.', 'error')
            print(f"Error in lupa_sandi: {e}")
        finally:
            cursor.close()
            conn.close()
    
    return render_template('lupa_sandi.html')

@app.route('/reset-sandi/<token>', methods=['GET', 'POST'])
def reset_sandi(token):
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('lupa_sandi'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Validasi token
        cursor.execute("""
            SELECT prt.*, u.username 
            FROM password_reset_tokens prt 
            JOIN users u ON prt.user_id = u.id 
            WHERE prt.token = %s AND prt.expires_at > NOW() AND prt.used = FALSE
        """, (token,))
        
        token_data = cursor.fetchone()
        
        if not token_data:
            flash('Token tidak valid atau sudah kedaluwarsa!', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('lupa_sandi'))
        
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if not password or not confirm_password:
                flash('Password dan konfirmasi password harus diisi!', 'error')
                return render_template('reset_sandi.html', token=token, username=token_data['username'])
            
            if password != confirm_password:
                flash('Password dan konfirmasi password tidak cocok!', 'error')
                return render_template('reset_sandi.html', token=token, username=token_data['username'])
            
            if len(password) < 6:
                flash('Password harus minimal 6 karakter!', 'error')
                return render_template('reset_sandi.html', token=token, username=token_data['username'])
            
            # Update password
            hashed_password = generate_password_hash(password)
            cursor.execute(
                "UPDATE users SET password = %s WHERE id = %s",
                (hashed_password, token_data['user_id'])
            )
            
            # Tandai token sebagai sudah digunakan
            cursor.execute(
                "UPDATE password_reset_tokens SET used = TRUE WHERE token = %s",
                (token,)
            )
            
            conn.commit()
            
            # Hapus session reset
            session.pop('reset_token', None)
            session.pop('reset_user_id', None)
            
            flash('Password berhasil direset! Silakan login dengan password baru.', 'success')
            return redirect(url_for('login'))
        
        cursor.close()
        conn.close()
        return render_template('reset_sandi.html', token=token, username=token_data['username'])
        
    except Exception as e:
        flash('Terjadi kesalahan saat mereset password.', 'error')
        print(f"Error in reset_sandi: {e}")
        cursor.close()
        conn.close()
        return redirect(url_for('lupa_sandi'))

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Pastikan admin exists dengan password yang benar
    ensure_admin_exists()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"Login attempt for: {username}")
        
        conn = get_db_connection()
        if not conn:
            flash('Koneksi database gagal!', 'error')
            return render_template('login.html')
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:
            print(f"User found: {user['username']}")
            print(f"User role: {user['role']}")
            
            # SPECIAL CASE: Jika admin dan password adalah admin123, langsung approve
            if user['role'] == 'admin' and password == 'admin123':
                print("✅ Admin login with fixed password")
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['nama_lengkap'] = user['nama_lengkap']
                session['nomor_telepon'] = user['nomor_telepon']
                session['rt'] = user['rt']
                session['role'] = user['role']
                
                cursor.close()
                conn.close()
                
                flash(f'Login berhasil! Selamat datang {user["nama_lengkap"]}', 'success')
                return redirect(url_for('admin_dashboard'))
            
            # Check password dengan method yang sama untuk user biasa
            is_valid = check_password_hash(user['password'], password)
            print(f"Password valid: {is_valid}")
        else:
            print("User not found")
            is_valid = False
        
        cursor.close()
        conn.close()
        
        if user and is_valid:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nama_lengkap'] = user['nama_lengkap']
            session['nomor_telepon'] = user['nomor_telepon']
            session['rt'] = user['rt']
            session['role'] = user['role']
            
            flash(f'Login berhasil! Selamat datang {user["nama_lengkap"]}', 'success')
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Username atau password salah!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        nomor_telepon = request.form['nomor_telepon']
        rt = request.form['rt']
        
        if not username or not password:
            flash('Username dan password harus diisi!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password harus minimal 6 karakter!', 'error')
            return render_template('register.html')
        
        # Validasi username yang lebih fleksibel - bisa huruf, angka, spasi, dan karakter umum
        if len(username) < 3:
            flash('Username harus minimal 3 karakter!', 'error')
            return render_template('register.html')
        
        if len(username) > 50:
            flash('Username maksimal 50 karakter!', 'error')
            return render_template('register.html')
        
        # Cek karakter yang tidak diizinkan
        if re.match(r'^[a-zA-Z0-9\s\.\-_@]+$', username) is None:
            flash('Username mengandung karakter yang tidak diizinkan! Hanya boleh huruf, angka, spasi, titik, dash, underscore, dan @.', 'error')
            return render_template('register.html')
        
        # Validasi nomor telepon
        if nomor_telepon:
            # Hapus karakter non-digit
            nomor_telepon_clean = re.sub(r'\D', '', nomor_telepon)
            if len(nomor_telepon_clean) < 10 or len(nomor_telepon_clean) > 15:
                flash('Nomor telepon harus antara 10-15 digit!', 'error')
                return render_template('register.html')
            if not nomor_telepon_clean.startswith('0'):
                flash('Nomor telepon harus dimulai dengan angka 0!', 'error')
                return render_template('register.html')
            # Simpan nomor telepon yang sudah dibersihkan
            nomor_telepon = nomor_telepon_clean
        
        # Validasi RT - hanya 4 pilihan yang diperbolehkan
        valid_rt = ['001', '002', '003', '004']
        if not rt:
            flash('RT harus dipilih!', 'error')
            return render_template('register.html')
        if rt not in valid_rt:
            flash('RT yang dipilih tidak valid!', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        if not conn:
            flash('Koneksi database gagal!', 'error')
            return render_template('register.html')
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Username sudah digunakan! Silakan pilih username lain.', 'error')
            cursor.close()
            conn.close()
            return render_template('register.html')
        
        # Generate hash password dengan method yang sama
        hashed_password = generate_password_hash(password)
        nama_lengkap = username  # Gunakan username sebagai nama lengkap
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password, nama_lengkap, nomor_telepon, rt, role) VALUES (%s, %s, %s, %s, %s, 'user')",
                (username, hashed_password, nama_lengkap, nomor_telepon if nomor_telepon else None, rt)
            )
            conn.commit()
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Terjadi kesalahan saat registrasi. Silakan coba lagi.', 'error')
            cursor.close()
            conn.close()
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout!', 'success')
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return render_template('admin_dashboard.html',
                             total_events=0,
                             total_users=0,
                             total_absen_hari_ini=0,
                             events_hari_ini=[])
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT COUNT(*) as total_events FROM events WHERE created_by = %s", (session['user_id'],))
        total_events = cursor.fetchone()['total_events']
        
        cursor.execute("SELECT COUNT(*) as total_users FROM users WHERE role = 'user'")
        total_users = cursor.fetchone()['total_users']
        
        cursor.execute("""
            SELECT COUNT(DISTINCT a.user_id) as total_absen_hari_ini 
            FROM absensi a 
            JOIN events e ON a.event_id = e.id 
            WHERE DATE(a.waktu_absen) = CURDATE() AND e.created_by = %s
        """, (session['user_id'],))
        result = cursor.fetchone()
        total_absen_hari_ini = result['total_absen_hari_ini'] if result else 0
        
        cursor.execute("""
            SELECT * FROM events 
            WHERE tanggal_event = CURDATE() AND created_by = %s 
            ORDER BY waktu_event
        """, (session['user_id'],))
        events_hari_ini = cursor.fetchall()
        
    except Exception as e:
        print(f"Error: {e}")
        total_events = 0
        total_users = 0
        total_absen_hari_ini = 0
        events_hari_ini = []
    
    cursor.close()
    conn.close()
    
    return render_template('admin_dashboard.html',
                         total_events=total_events,
                         total_users=total_users,
                         total_absen_hari_ini=total_absen_hari_ini,
                         events_hari_ini=events_hari_ini)

@app.route('/admin/events')
def admin_events():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return render_template('list_event.html', events=[], is_admin=True)
        
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM events WHERE created_by = %s ORDER BY tanggal_event DESC, waktu_event DESC", (session['user_id'],))
    events = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('list_event.html', events=events, is_admin=True)

@app.route('/admin/buat-event', methods=['GET', 'POST'])
def buat_event():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        nama_event = request.form['nama_event']
        deskripsi = request.form['deskripsi']
        tanggal_event = request.form['tanggal_event']
        waktu_event = request.form['waktu_event']
        lokasi = request.form['lokasi']
        
        conn = get_db_connection()
        if not conn:
            flash('Koneksi database gagal!', 'error')
            return render_template('buat_event.html')
            
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO events (nama_event, deskripsi, tanggal_event, waktu_event, lokasi, created_by) VALUES (%s, %s, %s, %s, %s, %s)",
                (nama_event, deskripsi, tanggal_event, waktu_event, lokasi, session['user_id'])
            )
            
            conn.commit()
            flash('Event berhasil dibuat!', 'success')
            
        except Exception as e:
            flash('Terjadi kesalahan saat membuat event.', 'error')
            
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for('admin_events'))
    
    return render_template('buat_event.html')

@app.route('/admin/hapus-event/<int:event_id>', methods=['POST'])
def hapus_event(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor()
    
    try:
        # Hapus event (akan otomatis hapus absensi terkait karena foreign key constraint)
        cursor.execute("DELETE FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
        
        if cursor.rowcount > 0:
            conn.commit()
            flash('Event berhasil dihapus!', 'success')
        else:
            flash('Event tidak ditemukan atau tidak memiliki akses!', 'error')
            
    except Exception as e:
        flash('Terjadi kesalahan saat menghapus event.', 'error')
        print(f"Error deleting event: {e}")
        
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_events'))

@app.route('/admin/hapus-absen/<int:absen_id>', methods=['POST'])
def hapus_absen(absen_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Cek apakah absensi ada dan milik event yang dibuat oleh admin
        cursor.execute("""
            SELECT a.id, e.created_by 
            FROM absensi a 
            JOIN events e ON a.event_id = e.id 
            WHERE a.id = %s
        """, (absen_id,))
        
        absen = cursor.fetchone()
        
        if not absen:
            flash('Data absensi tidak ditemukan!', 'error')
        elif absen['created_by'] != session['user_id']:
            flash('Anda tidak memiliki akses untuk menghapus absensi ini!', 'error')
        else:
            # Hapus absensi
            cursor.execute("DELETE FROM absensi WHERE id = %s", (absen_id,))
            conn.commit()
            flash('Data absensi berhasil dihapus!', 'success')
            
    except Exception as e:
        flash('Terjadi kesalahan saat menghapus absensi.', 'error')
        print(f"Error deleting absensi: {e}")
        
    finally:
        cursor.close()
        conn.close()
    
    # Redirect kembali ke halaman hasil absen
    event_id = request.form.get('event_id')
    if event_id:
        return redirect(url_for('hasil_absen', event_id=event_id))
    else:
        return redirect(url_for('admin_events'))

@app.route('/admin/hapus-semua-absen/<int:event_id>', methods=['POST'])
def hapus_semua_absen(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor()
    
    try:
        # Cek apakah event milik admin
        cursor.execute("SELECT created_by FROM events WHERE id = %s", (event_id,))
        event = cursor.fetchone()
        
        if not event:
            flash('Event tidak ditemukan!', 'error')
        elif event[0] != session['user_id']:
            flash('Anda tidak memiliki akses untuk menghapus absensi event ini!', 'error')
        else:
            # Hapus semua absensi untuk event ini
            cursor.execute("DELETE FROM absensi WHERE event_id = %s", (event_id,))
            conn.commit()
            flash('Semua data absensi untuk event ini berhasil dihapus!', 'success')
            
    except Exception as e:
        flash('Terjadi kesalahan saat menghapus absensi.', 'error')
        print(f"Error deleting all absensi: {e}")
        
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('hasil_absen', event_id=event_id))

@app.route('/admin/qr-code/<int:event_id>')
def generate_qr_code(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))
    
    # Get current QR code
    cursor.execute("""
        SELECT qr_code_data, expires_at
        FROM qr_codes 
        WHERE event_id = %s AND expires_at > NOW() 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (event_id,))
    
    qr_code = cursor.fetchone()
    
    if qr_code:
        qr_data = qr_code['qr_code_data']
        expires_at = qr_code['expires_at']
        
        # Hitung waktu tersisa sampai QR code expired
        now = datetime.datetime.now()
        expires_dt = expires_at
        time_remaining = expires_dt - now
        seconds_remaining = max(0, int(time_remaining.total_seconds()))
    else:
        # Generate new QR code jika tidak ada yang aktif
        qr_data = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=120)  # 2 menit
        
        try:
            cursor.execute(
                "INSERT INTO qr_codes (event_id, qr_code_data, expires_at) VALUES (%s, %s, %s)",
                (event_id, qr_data, expires_at)
            )
            conn.commit()
            seconds_remaining = 120  # 2 menit
        except Exception as e:
            print(f"Error inserting QR code: {e}")
            seconds_remaining = 120
    
    # Generate QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    cursor.close()
    conn.close()
    
    return render_template('absen.html', 
                         qr_code=img_str, 
                         event=event, 
                         is_admin=True,
                         refresh_interval=seconds_remaining * 1000,  # Convert to milliseconds
                         seconds_remaining=seconds_remaining)

@app.route('/admin/token/<int:event_id>')
def generate_token_page(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))
    
    # Get current token
    cursor.execute("""
        SELECT token_data, expires_at
        FROM tokens 
        WHERE event_id = %s AND expires_at > NOW() 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (event_id,))
    
    token = cursor.fetchone()
    
    if token:
        token_data = token['token_data']
        expires_at = token['expires_at']
        
        # Hitung waktu tersisa sampai token expired
        now = datetime.datetime.now()
        expires_dt = expires_at
        time_remaining = expires_dt - now
        seconds_remaining = max(0, int(time_remaining.total_seconds()))
    else:
        # Generate new token jika tidak ada yang aktif
        token_data = generate_token(6)
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=10)  # Token berlaku 10 menit
        
        try:
            cursor.execute(
                "INSERT INTO tokens (event_id, token_data, expires_at) VALUES (%s, %s, %s)",
                (event_id, token_data, expires_at)
            )
            conn.commit()
            seconds_remaining = 600  # 10 menit
        except Exception as e:
            print(f"Error inserting token: {e}")
            seconds_remaining = 600
    
    cursor.close()
    conn.close()
    
    return render_template('token.html', 
                         token=token_data, 
                         event=event, 
                         refresh_interval=60000,  # Refresh setiap 1 menit
                         seconds_remaining=seconds_remaining)

@app.route('/admin/absen-manual/<int:event_id>', methods=['GET', 'POST'])
def absen_manual(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))
    
    # Get semua users untuk dropdown
    cursor.execute("SELECT id, username, nama_lengkap, nomor_telepon, rt FROM users WHERE role = 'user' ORDER BY nama_lengkap")
    users = cursor.fetchall()
    
    # Get absensi yang sudah dilakukan
    cursor.execute("""
        SELECT u.id, u.nama_lengkap, u.username, u.nomor_telepon, u.rt
        FROM absensi a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.event_id = %s
    """, (event_id,))
    sudah_absen = cursor.fetchall()
    sudah_absen_ids = [user['id'] for user in sudah_absen]
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        
        # Cek apakah sudah absen
        if int(user_id) in sudah_absen_ids:
            flash('User sudah melakukan absen untuk event ini!', 'warning')
        else:
            # Simpan absensi manual
            try:
                cursor.execute(
                    "INSERT INTO absensi (event_id, user_id, metode_absen) VALUES (%s, %s, 'manual')",
                    (event_id, user_id)
                )
                conn.commit()
                flash('Absensi manual berhasil!', 'success')
                
                # Refresh list yang sudah absen
                cursor.execute("""
                    SELECT u.id, u.nama_lengkap, u.username, u.nomor_telepon, u.rt
                    FROM absensi a 
                    JOIN users u ON a.user_id = u.id 
                    WHERE a.event_id = %s
                """, (event_id,))
                sudah_absen = cursor.fetchall()
                sudah_absen_ids = [user['id'] for user in sudah_absen]
                
            except Exception as e:
                flash('Terjadi kesalahan saat menyimpan absensi.', 'error')
    
    cursor.close()
    conn.close()
    
    return render_template('absen_manual.html', 
                         event=event, 
                         users=users, 
                         sudah_absen=sudah_absen,
                         sudah_absen_ids=sudah_absen_ids)

@app.route('/admin/hasil-absen/<int:event_id>')
def hasil_absen(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))
    
    # Get data absensi dengan metode
    cursor.execute("""
        SELECT a.id, u.nama_lengkap, u.username, u.nomor_telepon, u.rt, a.waktu_absen, a.metode_absen
        FROM absensi a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.event_id = %s 
        ORDER BY a.waktu_absen DESC
    """, (event_id,))
    
    absensi = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('hasil_absen.html', event=event, absensi=absensi)

@app.route('/admin/download-absen/<int:event_id>')
def download_absen(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('admin_events'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s AND created_by = %s", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))
    
    # Get data absensi dengan metode
    cursor.execute("""
        SELECT u.nama_lengkap, u.username, u.nomor_telepon, u.rt, a.waktu_absen, a.metode_absen
        FROM absensi a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.event_id = %s 
        ORDER BY a.waktu_absen DESC
    """, (event_id,))
    
    absensi = cursor.fetchall()
    
    # Create CSV dengan delimiter semicolon untuk Excel compatibility
    output = StringIO()
    
    # Gunakan semicolon sebagai delimiter untuk kompatibilitas Excel Indonesia
    writer = csv.writer(output, delimiter=';')
    
    # Header informasi event
    writer.writerow(['LAPORAN ABSENSI'])
    writer.writerow([])
    writer.writerow(['Nama Event:', event['nama_event']])
    writer.writerow(['Tanggal Event:', event['tanggal_event']])
    writer.writerow(['Waktu Event:', event['waktu_event']])
    writer.writerow(['Lokasi:', event['lokasi']])
    writer.writerow(['Total Hadir:', len(absensi)])
    writer.writerow([])
    
    # Header tabel
    writer.writerow(['No', 'Nama Lengkap', 'Username', 'Nomor Telepon', 'RT', 'Waktu Absen', 'Metode Absen'])
    
    # Data absensi
    for i, absen in enumerate(absensi, 1):
        writer.writerow([
            i,
            absen['nama_lengkap'],
            absen['username'],
            absen['nomor_telepon'] or '-',
            absen['rt'] or '-',
            absen['waktu_absen'].strftime('%d-%m-%Y %H:%M:%S'),
            absen['metode_absen'].upper()
        ])
    
    # Summary metode absensi
    writer.writerow([])
    writer.writerow(['REKAP METODE ABSENSI'])
    
    # Hitung per metode
    metode_count = {}
    for absen in absensi:
        metode = absen['metode_absen']
        metode_count[metode] = metode_count.get(metode, 0) + 1
    
    for metode, count in metode_count.items():
        writer.writerow([f'{metode.upper()}:', count])
    
    writer.writerow([])
    writer.writerow(['Downloaded pada:', datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')])
    
    output.seek(0)
    
    cursor.close()
    conn.close()
    
    # Create filename dengan format yang baik
    filename = f"absen_{event['nama_event'].replace(' ', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8-sig')),  # utf-8-sig untuk Excel compatibility
        mimetype='text/csv; charset=utf-8-sig',
        as_attachment=True,
        download_name=filename
    )

# User Routes
@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return render_template('user_dashboard.html',
                             events_akan_datang=[],
                             riwayat_absen=[])
        
    cursor = conn.cursor(dictionary=True)
    
    # Event yang akan datang
    cursor.execute("""
        SELECT e.* 
        FROM events e 
        WHERE e.tanggal_event >= CURDATE() 
        ORDER BY e.tanggal_event, e.waktu_event
    """)
    events_akan_datang = cursor.fetchall()
    
    # Riwayat absensi user
    cursor.execute("""
        SELECT e.nama_event, e.tanggal_event, e.waktu_event, a.waktu_absen, a.metode_absen
        FROM absensi a 
        JOIN events e ON a.event_id = e.id 
        WHERE a.user_id = %s 
        ORDER BY a.waktu_absen DESC 
        LIMIT 10
    """, (session['user_id'],))
    riwayat_absen = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('user_dashboard.html',
                         events_akan_datang=events_akan_datang,
                         riwayat_absen=riwayat_absen)

@app.route('/user/events')
def user_events():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return render_template('list_event.html', events=[], is_admin=False)
        
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT e.*, 
               CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END as sudah_absen
        FROM events e 
        LEFT JOIN absensi a ON e.id = a.event_id AND a.user_id = %s
        WHERE e.tanggal_event >= CURDATE() 
        ORDER BY e.tanggal_event, e.waktu_event
    """, (session['user_id'],))
    
    events = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('list_event.html', events=events, is_admin=False)

@app.route('/absen/<int:event_id>', methods=['GET', 'POST'])
def absen(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Koneksi database gagal!', 'error')
        return redirect(url_for('user_dashboard'))
        
    cursor = conn.cursor(dictionary=True)
    
    # Cek event
    cursor.execute("SELECT * FROM events WHERE id = %s", (event_id,))
    event = cursor.fetchone()
    
    if not event:
        flash('Event tidak ditemukan!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('user_dashboard'))
    
    # Cek apakah sudah absen - PENAMBAHAN VALIDASI DOUBLE ABSEN
    if sudah_absen(session['user_id'], event_id):
        flash('Anda sudah absen untuk event ini!', 'warning')
        cursor.close()
        conn.close()
        return redirect(url_for('user_events'))
    
    if request.method == 'POST':
        absen_type = request.form.get('absen_type')
        
        # DOUBLE CHECK: Cek lagi sebelum menyimpan untuk menghindari race condition
        if sudah_absen(session['user_id'], event_id):
            flash('Anda sudah absen untuk event ini!', 'warning')
            cursor.close()
            conn.close()
            return redirect(url_for('user_events'))
        
        if absen_type == 'qr_code':
            qr_code_input = request.form['qr_code']
            
            # Validasi QR code
            cursor.execute("""
                SELECT * FROM qr_codes 
                WHERE event_id = %s AND qr_code_data = %s AND expires_at > NOW()
            """, (event_id, qr_code_input))
            
            valid_qr = cursor.fetchone()
            
            if valid_qr:
                # DOUBLE CHECK: Cek sekali lagi sebelum insert
                cursor.execute("SELECT id FROM absensi WHERE user_id = %s AND event_id = %s", (session['user_id'], event_id))
                existing_absen = cursor.fetchone()
                
                if existing_absen:
                    flash('Anda sudah absen untuk event ini!', 'warning')
                else:
                    # Simpan absensi QR code
                    cursor.execute(
                        "INSERT INTO absensi (event_id, user_id, qr_code_used, metode_absen) VALUES (%s, %s, %s, 'qr_code')",
                        (event_id, session['user_id'], qr_code_input)
                    )
                    conn.commit()
                    flash('Absensi dengan QR Code berhasil!', 'success')
            else:
                flash('QR Code tidak valid atau sudah expired!', 'error')
                cursor.close()
                conn.close()
                return render_template('absen.html', event=event, is_admin=False)
                
        elif absen_type == 'token':
            token_input = request.form['token']
            
            # Validasi token
            cursor.execute("""
                SELECT * FROM tokens 
                WHERE event_id = %s AND token_data = %s AND expires_at > NOW()
            """, (event_id, token_input))
            
            valid_token = cursor.fetchone()
            
            if valid_token:
                # DOUBLE CHECK: Cek sekali lagi sebelum insert
                cursor.execute("SELECT id FROM absensi WHERE user_id = %s AND event_id = %s", (session['user_id'], event_id))
                existing_absen = cursor.fetchone()
                
                if existing_absen:
                    flash('Anda sudah absen untuk event ini!', 'warning')
                else:
                    # Simpan absensi token
                    cursor.execute(
                        "INSERT INTO absensi (event_id, user_id, token_used, metode_absen) VALUES (%s, %s, %s, 'token')",
                        (event_id, session['user_id'], token_input)
                    )
                    conn.commit()
                    flash('Absensi dengan Token berhasil!', 'success')
            else:
                flash('Token tidak valid atau sudah expired!', 'error')
                cursor.close()
                conn.close()
                return render_template('absen.html', event=event, is_admin=False)
        
        cursor.close()
        conn.close()
        return redirect(url_for('user_events'))
    
    # Untuk admin, tampilkan QR code
    if session['role'] == 'admin':
        cursor.close()
        conn.close()
        return redirect(url_for('generate_qr_code', event_id=event_id))
    
    cursor.close()
    conn.close()
    
    return render_template('absen.html', event=event, is_admin=False)

if __name__ == '__main__':
    # Pastikan admin exists saat aplikasi start
    ensure_admin_exists()
    qr_manager.start()
    app.run(debug=True)
