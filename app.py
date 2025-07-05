import os
import re
import json
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- 2FA ve E-posta için importlar ---
from flask_mail import Mail, Message
import pyotp
from datetime import datetime, timedelta

# --- Ortam değişkenlerini yükle ---
from dotenv import load_dotenv
load_dotenv()

# --- Flask Uygulaması ve Veritabanı Kurulumu ---
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Hassas bilgileri ortam değişkenlerinden al!
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key_please_change_it_make_it_long')

# ... (app = Flask(__name__) öncesi)

# Veritabanı Yapılandırması: Heroku'da DATABASE_URL ortam değişkenini kullan
# Eğer DATABASE_URL yoksa, bu bir hata olarak kabul edilir ve uygulama başlamaz.
# Bu, sorunun nedenini daha net görmemizi sağlar.
database_url = os.getenv('DATABASE_URL')

if database_url is None:
    # Sadece yerel geliştirme için SQLite fallback'i (Heroku'da bu çalışmamalı)
    print("WARNING: DATABASE_URL not found in environment. Using SQLite. This should not happen on Heroku.")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users_and_passwords.db')
elif database_url.startswith('postgres://'):
    # Heroku Postgres URL'si 'postgres://...' şeklinde gelir, ama SQLAlchemy 'postgresql://...' bekler
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('postgres://', 'postgresql://', 1)
elif database_url.startswith('postgresql://'):
    # Zaten doğru formatta ise
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Bilinmeyen bir protokol ise hata ver
    raise ValueError(f"Unsupported database URL scheme: {database_url}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Gereksiz uyarıları kapatır

# ... (db = SQLAlchemy(app) ve diğer kodlar devam eder)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Gereksiz uyarıları kapatır


# Flask-Mail Yapılandırması - Bilgiler .env dosyasından alınır!
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Bu sayfaya erişmek için giriş yapmalısınız."
login_manager.login_message_category = "danger"

# --- Sabit bir tuz (salt) ---
# APP_SALT'ı ortam değişkeninden alıyoruz. Yoksa varsayılan rastgele bir tane kullanırız.
APP_SALT_ENV = os.getenv('APP_SALT')
if APP_SALT_ENV:
    APP_SALT = APP_SALT_ENV.encode('utf-8')
else:
    print("WARNING: APP_SALT is not set in .env. Using a default random value. Please set APP_SALT in your .env file for production.")
    APP_SALT = b'gL6G4wWp0cTjK5q9VfB2zXyN7eU1sC3a' # Örnek, lütfen kendiniz rastgele oluşturun ve .env'ye ekleyin


# --- Şifreleme ve Anahtar Türetme Fonksiyonları ---
def generate_derived_key(password: str, salt: bytes):
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def encrypt_data(data: str, key: bytes):
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt_data(encrypted_data: str, key: bytes):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')


# --- Şifre Gücü Kontrolü ---
def check_password_strength(password: str):
    score = 0
    feedback = []

    if len(password) >= 14:
        score += 4
        feedback.append("Şifre uzunluğu mükemmel! (14+ karakter)")
    elif len(password) >= 10:
        score += 3
        feedback.append("Şifre yeterince uzun. Daha uzun olması daha iyi olur (min 10).")
    elif len(password) >= 8:
        score += 2
        feedback.append("Şifre kısa. En az 8, tercihen 14+ karakter olmalı.")
    else:
        feedback.append("Şifre çok kısa. En az 8 karakter olmalı, 14+ önerilir.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Büyük harf (A-Z) ekleyin.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Küçük harf (a-z) ekleyin.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Sayı (0-9) ekleyin.")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        score += 1
    else:
        feedback.append("Özel karakter (!@#$ vb.) ekleyin.")

    if len(password) > 5 and len(set(list(password))) < len(password) * 0.7:
        feedback.append("Çok fazla tekrar eden karakter veya basit desenler içeriyor. Daha çeşitli yapın.")

    common_words = ["password", "123456", "qwerty", "admin", "yusuf", "sifre", "parola", "12345678", "abcde"]
    if any(word in password.lower() for word in common_words):
        score -= 2
        feedback.append("Ortak veya tahmin edilebilir kelimeler kullanmaktan kaçının.")
    
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        score -= 1
        feedback.append("Ardışık karakterler kullanmaktan kaçının (örn. 'abc').")
    if re.search(r"(123|234|345|456|567|678|789|012)", password):
        score -= 1
        feedback.append("Ardışık sayılar kullanmaktan kaçının (örn. '123').")
    if re.search(r"(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)", password.lower()):
        score -= 1
        feedback.append("Klavye dizilimi kullanmaktan kaçının (örn. 'qwe').")

    if re.search(r"(cba|edc|fed|gfe|ihg|kji|lkj|pon|rqp|tsr|vut|xwv|zyx)", password.lower()):
        score -= 1
        feedback.append("Tersten ardışık karakterler kullanmaktan kaçının (örn. 'cba').")
    if re.search(r"(321|432|543|654|765|876|987)", password):
        score -= 1
        feedback.append("Tersten ardışık sayılar kullanmaktan kaçının (örn. '321').")
    if re.search(r"(ewq|tre|yrt|iuy|poi|dsa|gfd|jhg|lkj|vbn|mno|xcz)", password.lower()):
        score -= 1
        feedback.append("Tersten klavye dizilimi kullanmaktan kaçının (örn. 'ewq').")

    if score >= 7:
        strength = "Çok Güçlü"
        color = "#4CAF50" # Green
    elif score >= 5:
        strength = "Güçlü"
        color = "#8BC34A" # Light Green
    elif score >= 3:
        strength = "Orta"
        color = "#FFC107" # Yellow
    else:
        strength = "Zayıf"
        color = "#F44336" # Red
        
    return strength, color, feedback


# --- Veritabanı Modelleri ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128)) 
    encrypted_data_encryption_key = db.Column(db.Text, nullable=True) 
    
    email_confirmed = db.Column(db.Boolean, default=False)
    confirmation_code = db.Column(db.String(6), nullable=True) 
    login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True) 

    password_entries = db.relationship('PasswordEntry', backref='user_rel', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_decrypted_data_key(self, master_password: str) -> bytes:
        master_derived_key = generate_derived_key(master_password, APP_SALT)
        try:
            decrypted_key_bytes_str = decrypt_data(self.encrypted_data_encryption_key, master_derived_key)
            return decrypted_key_bytes_str.encode('utf-8')
        except Exception as e:
            print(f"Error decrypting data encryption key: {e}")
            raise ValueError("Ana şifre yanlış veya anahtar bozulmuş.")

    def generate_confirmation_code(self):
        import random 
        return ''.join(random.choices('0123456789', k=6))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False) 
    category = db.Column(db.String(100), default="Genel")
    strength = db.Column(db.String(50)) 


# --- Rotalar ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user) 
    return render_template('index.html', user=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('Geçersiz e-posta formatı. Lütfen geçerli bir e-posta adresi girin.', 'danger')
            return redirect(url_for('register'))

        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Kullanıcı adı zaten mevcut. Lütfen başka bir tane seçin.', 'danger')
            return redirect(url_for('register'))

        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Bu e-posta adresi zaten kayıtlı. Lütfen başka bir tane kullanın.', 'danger')
            return redirect(url_for('register'))

        try:
            new_user_data_encryption_key = Fernet.generate_key() 
            master_key_for_dek_encryption = generate_derived_key(password, APP_SALT)
            encrypted_dek_for_storage = encrypt_data(new_user_data_encryption_key.decode('utf-8'), master_key_for_dek_encryption)

            new_user = User(username=username, email=email, encrypted_data_encryption_key=encrypted_dek_for_storage)
            new_user.set_password(password)
            
            confirmation_code = new_user.generate_confirmation_code()
            new_user.confirmation_code = confirmation_code 
            
            db.session.add(new_user)
            db.session.commit()

            msg = Message("Şifre Yöneticisi - E-posta Doğrulama Kodunuz",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[new_user.email])
            msg.body = f"Merhaba {new_user.username},\n\nŞifre Yöneticisi hesabınızı doğrulamak için kodunuz: {confirmation_code}\n\nBu kodu kayıt işlemini tamamlamak için kullanın."
            mail.send(msg)
            
            session['email_confirm_user_id'] = new_user.id 
            flash('Hesabınızı doğrulamak için e-posta adresinize bir kod gönderildi.', 'info')
            return redirect(url_for('confirm_email'))
        except Exception as e:
            print(f"Kayıt sırasında veya e-posta gönderme hatası: {e}") 
            flash(f'Kayıt tamamlandı, ancak doğrulama e-postası gönderilirken bir sorun oluştu: {e}. Lütfen e-posta adresinizi kontrol edin veya destekle iletişime geçin.', 'danger')
            return redirect(url_for('login')) 
    return render_template('register.html', user=None)

# --- E-posta Doğrulama Rotası ---
@app.route('/confirm_email', methods=['GET', 'POST'])
def confirm_email():
    user_id = session.get('email_confirm_user_id')
    if not user_id:
        flash('Lütfen kayıt veya giriş işlemini baştan başlatın.', 'danger')
        return redirect(url_for('register'))

    user = User.query.get(user_id)
    if not user:
        flash('Kullanıcı bulunamadı. Lütfen tekrar kayıt olmaya çalışın.', 'danger')
        return redirect(url_for('register'))

    if user.email_confirmed:
        flash('E-posta adresiniz zaten doğrulanmış. Giriş yapabilirsiniz.', 'info')
        return redirect(url_for('login')) 

    if request.method == 'POST':
        code = request.form['code'].strip()
        if user.confirmation_code == code:
            user.email_confirmed = True
            user.confirmation_code = None 
            db.session.commit()
            session.pop('email_confirm_user_id', None)
            flash('E-posta adresiniz başarıyla doğrulandı! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Geçersiz doğrulama kodu.', 'danger')
            return render_template('confirm_email.html', user=None)
    
    flash(f"Doğrulama kodunuz {user.email} adresine gönderildi. Lütfen gelen kutunuzu kontrol edin.", 'info')
    return render_template('confirm_email.html', user=None)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = User.query.filter_by(username=username).first()
        
        # --- Kilitleme Kontrolü Başlangıcı ---
        if user and user.lockout_until and user.lockout_until > datetime.now():
            remaining_time = user.lockout_until - datetime.now()
            hours, remainder = divmod(remaining_time.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            flash_msg = "Hesabınız kilitli. "
            if hours > 0:
                flash_msg += f"{int(hours)} saat "
            if minutes > 0:
                flash_msg += f"{int(minutes)} dakika "
            if seconds > 0:
                flash_msg += f"{int(seconds)} saniye "
            flash_msg += "sonra tekrar deneyin."
            
            flash(flash_msg, 'danger')
            return redirect(url_for('login'))
        # --- Kilitleme Kontrolü Sonu ---

        if user and user.check_password(password):
            # E-posta doğrulaması yapılmamışsa, confirm_email sayfasına yönlendir
            if not user.email_confirmed: 
                session['email_confirm_user_id'] = user.id
                flash('E-posta adresiniz doğrulanmadı. Lütfen e-postanıza gönderilen kodu girin.', 'danger')
                return redirect(url_for('confirm_email'))

            # Giriş başarılı, kilitleme denemelerini sıfırla
            user.login_attempts = 0
            user.lockout_until = None
            db.session.commit()

            try:
                decrypted_data_key_bytes = user.get_decrypted_data_key(password)
                session['data_encryption_key'] = base64.urlsafe_b64encode(decrypted_data_key_bytes).decode('utf-8')
                
                login_user(user)
                flash('Başarıyla giriş yaptınız!', 'success')
                return redirect(url_for('dashboard'))
            except ValueError as e:
                flash(f'Giriş başarısız: {e}. Lütfen şifrenizi kontrol edin.', 'danger') 
            except Exception as e:
                flash(f'Giriş sırasında beklenmeyen bir hata oluştu: {e}', 'danger')
        else:
            # --- Yanlış Giriş Denemesi ve Kilitleme Mantığı ---
            if user: # Sadece kullanıcı adı varsa denemeleri say
                user.login_attempts += 1
                db.session.commit()

                # Kilitleme süreleri
                lockout_durations = {
                    3: timedelta(minutes=10),
                    6: timedelta(hours=1),
                    9: timedelta(days=1)
                }
                
                current_attempts_mod_3 = user.login_attempts % 3
                if current_attempts_mod_3 == 0 and user.login_attempts <= 9: # Her 3 denemede bir kilit
                    duration = lockout_durations.get(user.login_attempts)
                    if duration:
                        user.lockout_until = datetime.now() + duration
                        db.session.commit()
                        
                        flash_msg = 'Çok fazla yanlış deneme! Hesabınız '
                        if duration.total_seconds() >= 3600 * 24:
                            flash_msg += f"{int(duration.total_seconds() / (3600 * 24))} gün "
                        elif duration.total_seconds() >= 3600:
                            flash_msg += f"{int(duration.total_seconds() / 3600)} saat "
                        else:
                            flash_msg += f"{int(duration.total_seconds() / 60)} dakika "
                        flash_msg += 'kilitlendi.'
                        flash(flash_msg, 'danger')
                        return redirect(url_for('login'))
                
                remaining_in_level = 3 - (current_attempts_mod_3 if current_attempts_mod_3 != 0 else 3)
                if user.login_attempts >= 9: 
                    flash('Kullanıcı adı veya şifre hatalı. Çok fazla yanlış deneme. Hesabınız 1 gün kilitlendi.', 'danger')
                else:
                    flash(f'Kullanıcı adı veya şifre hatalı. Kalan deneme: {remaining_in_level}', 'danger')
            else: 
                flash('Kullanıcı adı veya şifre hatalı.', 'danger')
    return render_template('login.html', user=None) 

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('data_encryption_key', None) 
    flash('Başarıyla çıkış yaptınız.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # E-posta doğrulanmadan dashboard'a erişimi engelle!
    if not current_user.email_confirmed:
        session['email_confirm_user_id'] = current_user.id 
        flash('E-posta adresiniz doğrulanmadı. Lütfen önce e-postanızı doğrulayın.', 'danger')
        return redirect(url_for('confirm_email'))


    data_encryption_key_b64_str = session.get('data_encryption_key')
    if not data_encryption_key_b64_str:
        flash('Güvenlik nedeniyle tekrar giriş yapmanız gerekiyor.', 'danger')
        return redirect(url_for('login'))

    try:
        encryption_key = base64.urlsafe_b64decode(data_encryption_key_b64_str.encode('utf-8'))
    except Exception as e:
        flash(f'Oturum anahtarı hatası: {e}. Lütfen tekrar giriş yapın.', 'danger')
        return redirect(url_for('logout')) 

    user_passwords = db.session.query(PasswordEntry).filter_by(user_id=current_user.id).all() # db.session.query kullanıldı
    
    decrypted_passwords = []
    for pwd_entry in user_passwords:
        try:
            decrypted_password = decrypt_data(pwd_entry.encrypted_password, encryption_key)
            decrypted_passwords.append({
                'id': pwd_entry.id,
                'site': pwd_entry.site,
                'username': pwd_entry.username,
                'password': decrypted_password,
                'category': pwd_entry.category,
                'strength': pwd_entry.strength 
            })
        except Exception as e:
            print(f"Hata: Şifre çözülürken problem oluştu ID {pwd_entry.id}: {e}")
            decrypted_passwords.append({
                'id': pwd_entry.id,
                'site': pwd_entry.site,
                'username': pwd_entry.username,
                'password': "[Şifre çözülemedi]", 
                'category': pwd_entry.category,
                'strength': "Bilinmiyor"
            })
    
    all_categories_db = db.session.query(PasswordEntry.category).filter_by(user_id=current_user.id).distinct().all()
    categories_list = sorted([cat[0] for cat in all_categories_db])
    if "Genel" not in categories_list:
        categories_list.insert(0, "Genel") 

    return render_template('dashboard.html', user=current_user, passwords=decrypted_passwords, categories=categories_list)


@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    # E-posta doğrulanmadan işlem engelle!
    if not current_user.email_confirmed:
        session['email_confirm_user_id'] = current_user.id
        flash('E-posta adresiniz doğrulanmadı. Lütfen önce e-postanızı doğrulayın.', 'danger')
        return redirect(url_for('confirm_email'))

    data_encryption_key_b64_str = session.get('data_encryption_key')
    if not data_encryption_key_b64_str:
        flash('Şifre eklemek için tekrar giriş yapmanız gerekiyor.', 'danger')
        return redirect(url_for('login'))

    try:
        encryption_key = base64.urlsafe_b64decode(data_encryption_key_b64_str.encode('utf-8'))
    except Exception as e:
        flash(f'Oturum anahtarı hatası: {e}. Lütfen tekrar giriş yapın.', 'danger')
        return redirect(url_for('logout'))

    all_categories_db = db.session.query(PasswordEntry.category).filter_by(user_id=current_user.id).distinct().all()
    categories_list = sorted([cat[0] for cat in all_categories_db])
    if "Genel" not in categories_list:
        categories_list.insert(0, "Genel")

    if request.method == 'POST':
        site = request.form['site'].strip()
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        category = request.form.get('category', 'Genel').strip()
        strength_text_from_js = request.form.get('strength-text-add') 

        if not site or not username or not password:
            flash('Site, Kullanıcı Adı ve Şifre alanları boş bırakılamaz.', 'danger')
            return redirect(url_for('add_password'))
        if not category:
            category = "Genel"
        
        try:
            encrypted_password = encrypt_data(password, encryption_key)
        except Exception as e:
            flash(f'Şifre şifrelenirken hata oluştu: {e}', 'danger')
            return redirect(url_for('add_password'))

        new_password_entry = PasswordEntry(
            user_id=current_user.id,
            site=site,
            username=username,
            encrypted_password=encrypted_password,
            category=category,
            strength=strength_text_from_js 
        )
        db.session.add(new_password_entry)
        db.session.commit()
        flash('Şifre başarıyla eklendi!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_password.html', user=current_user, categories=categories_list)

@app.route('/update_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def update_password(password_id):
    # E-posta doğrulanmadan işlem engelle!
    if not current_user.email_confirmed:
        session['email_confirm_user_id'] = current_user.id
        flash('E-posta adresiniz doğrulanmadı. Lütfen önce e-postanızı doğrulayın.', 'danger')
        return redirect(url_for('confirm_email'))

    data_encryption_key_b64_str = session.get('data_encryption_key')
    if not data_encryption_key_b64_str:
        flash('Şifreyi güncellemek için tekrar giriş yapmanız gerekiyor.', 'danger')
        return redirect(url_for('login'))

    try:
        encryption_key = base64.urlsafe_b64decode(data_encryption_key_b64_str.encode('utf-8'))
    except Exception as e:
        flash(f'Oturum anahtarı hatası: {e}. Lütfen tekrar giriş yapın.', 'danger')
        return redirect(url_for('logout'))

    entry_to_update = db.session.query(PasswordEntry).filter_by(id=password_id, user_id=current_user.id).first_or_404()
    
    try:
        decrypted_pwd = decrypt_data(entry_to_update.encrypted_password, encryption_key)
    except Exception as e:
        flash(f'Şifre çözülürken hata oluştu: {e}. Lütfen tekrar deneyin.', 'danger')
        decrypted_pwd = "[Çözülemedi]" 
    
    all_categories_db = db.session.query(PasswordEntry.category).filter_by(user_id=current_user.id).distinct().all()
    categories_list = sorted([cat[0] for cat in all_categories_db])
    if "Genel" not in categories_list:
        categories_list.insert(0, "Genel")

    if request.method == 'POST':
        entry_to_update.site = request.form['site'].strip()
        entry_to_update.username = request.form['username'].strip()
        new_password_plain = request.form['password'].strip() 
        entry_to_update.category = request.form.get('category', 'Genel').strip()
        strength_text_from_js = request.form.get('strength-text-update') 

        if not entry_to_update.site or not entry_to_update.username or not new_password_plain:
            flash('Tüm alanları doldurmak zorunludur.', 'danger')
            return redirect(url_for('update_password', password_id=password_id))
        
        try:
            encrypted_new_password = encrypt_data(new_password_plain, encryption_key)
            entry_to_update.encrypted_password = encrypted_new_password
            entry_to_update.strength = strength_text_from_js 
        except Exception as e:
            flash(f'Şifre şifrelenirken hata oluştu: {e}', 'danger')
            return redirect(url_for('update_password', password_id=password_id))

        db.session.commit()
        flash('Şifre başarıyla güncellendi!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_password.html', user=current_user, entry=entry_to_update, decrypted_pwd=decrypted_pwd, categories=categories_list)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    # E-posta doğrulanmadan işlem engelle!
    if not current_user.email_confirmed:
        session['email_confirm_user_id'] = current_user.id
        flash('E-posta adresiniz doğrulanmadı. Lütfen önce e-postanızı doğrulayın.', 'danger')
        return redirect(url_for('confirm_email'))

    entry_to_delete = db.session.query(PasswordEntry).filter_by(id=password_id, user_id=current_user.id).first_or_404()
    
    db.session.delete(entry_to_delete)
    db.session.commit()
    flash('Şifre başarıyla silindi!', 'info')
    return redirect(url_for('dashboard'))

# --- Şifremi Unuttum Rotası ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        user = db.session.query(User).filter_by(email=email).first()

        if user:
            # Şifre sıfırlama token'ı oluştur (basit bir örnek)
            # GERÇEK SİSTEMDE: Bu token veritabanında saklanmalı, süresi olmalı, kullanıldıktan sonra geçersiz kılınmalı!
            reset_token = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
            # user.reset_token = reset_token (User modeline yeni alan ekle: reset_token, reset_token_expiration)
            # user.reset_token_expiration = datetime.now() + timedelta(hours=1)
            # db.session.commit()
            
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            
            try:
                msg = Message("Şifre Yöneticisi - Şifre Sıfırlama İsteği",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[user.email])
                msg.body = f"Merhaba {user.username},\n\nŞifrenizi sıfırlamak için aşağıdaki bağlantıyı tıklayın:\n{reset_link}\n\nBu bağlantı tek kullanımlıktır ve belirli bir süre sonra geçersiz olacaktır. Eğer şifre sıfırlama talebinde bulunmadıysanız bu e-postayı dikkate almayın."
                mail.send(msg)
                flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.', 'success') 
                return redirect(url_for('login'))
            except Exception as e:
                flash(f'Şifre sıfırlama e-postası gönderilirken hata oluştu: {e}', 'danger')
                return redirect(url_for('forgot_password'))
        else:
            flash('Bu e-posta adresine kayıtlı bir kullanıcı bulunamadı.', 'danger')
    return render_template('forgot_password.html', user=None)

# --- Şifre Sıfırlama Rotası ---
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # BURADA GERÇEK SİSTEMDE token kontrolü yapılmalı (geçerliliği, süresi, sahibinin kim olduğu).
    # If token is invalid or expired, show error message and redirect to forgot_password.
    
    # user = db.session.query(User).filter_by(reset_token=token, reset_token_expiration > datetime.now()).first()
    # if not user:
    #     flash('Geçersiz veya süresi dolmuş sıfırlama bağlantısı.', 'danger')
    #     return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        if password != confirm_password:
            flash('Şifreler uyuşmuyor.', 'danger')
            return render_template('reset_password.html', token=token, user=None)
        
        # Şifre güncelleme (ÖRNEK SADECE, user nesnesi token ile bulunmalıydı)
        # user.set_password(password)
        # user.reset_token = None
        # user.reset_token_expiration = None
        # db.session.commit()

        flash('Şifreniz başarıyla sıfırlandı (Bu sadece bir örnek! Gerçek sistemde token kontrolü ve şifre güncelleme yapılır). Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, user=None)


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)