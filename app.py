from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import pymysql
from pymysql.cursors import DictCursor
from password_utils import prepare_password, ntru_encrypt, ntru_decrypt, password_is_strong
from config import Config
from hash import derive_lattice_key, ph as password_hasher, exceptions
import base64
import secrets
import logging
import time
from database import init_db
from hash import decrypt_component, encrypt_component


# Initialisation de l'application Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = secrets.token_hex(32)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialisation de la base de données
with app.app_context():
    init_db(app)

def get_db():
    """Obtient une connexion à la base de données"""
    if 'db' not in g:
        g.db = pymysql.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            db=app.config['MYSQL_DB'],
            charset='utf8mb4',
            cursorclass=DictCursor
        )
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Ferme la connexion à la base de données"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def validate_password_complexity(password):
    """Valide la complexité du mot de passe (str en entrée)"""
    if not isinstance(password, str):
        raise ValueError("The password must be a string")
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in password)
    return has_upper and has_lower and has_digit and has_special

@app.route('/')
def home():
    """Page d'accueil"""
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Gestion de l'inscription"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')  # str
        full_name = request.form.get('full_name', '').strip()

        # Validation des entrées
        if not all([username, email, password, full_name]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
        
        # Vérification de la complexité du mot de passe
        if not password_is_strong(password):
            flash('The password must contain at least 12 characters, including an uppercase letter, a lowercase letter, a number, and a special character', 'danger')
            return redirect(url_for('register'))

        
        db = get_db()
        try:
            with db.cursor() as cursor:
                # Vérifie si l'utilisateur existe déjà
                cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
                if cursor.fetchone():
                    flash('This username or email is already in use', 'danger')
                    return redirect(url_for('register'))

                # Préparation et chiffrement du mot de passe (conversion interne gérée par prepare_password)
                pw_data = prepare_password(password)  # password est un str
                encrypted_pw = ntru_encrypt(pw_data['hashed'])

                # Insertion en base de données
                cursor.execute(
                    """INSERT INTO users 
                    (username, email, password, lattice, salt, full_name) 
                    VALUES (%s, %s, %s, %s, %s, %s)""",
                    (username, email, encrypted_pw, pw_data['lattice'], pw_data['salt'], full_name)
                )
                db.commit()
                
                flash('Registration successful! You can now log in', 'success')
                return redirect(url_for('login'))
                
        except Exception as e:
            db.rollback()
            logger.error(f"Erreur inscription: {str(e)}")
            flash('Error during registration', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Gestion de la connexion"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please provide a username and password', 'danger')
            return redirect(url_for('login'))
        
        db = get_db()
        try:
            with db.cursor() as cursor:
                cursor.execute("""
                    SELECT id, username, password, lattice, salt, failed_attempts,
                    TIMESTAMPDIFF(SECOND, last_attempt, NOW()) as attempt_diff
                    FROM users WHERE username = %s
                """, (username,))
                user = cursor.fetchone()
                
                if not user:
                    time.sleep(1)  # Délai pour éviter l'énumération d'utilisateurs
                    flash('Invalid credentials', 'danger')
                    return redirect(url_for('login'))
                
                # Vérification du verrouillage du compte
                if user['failed_attempts'] >= Config.MAX_LOGIN_ATTEMPTS:
                    if user['attempt_diff'] < Config.LOCKOUT_TIME:
                        remaining = Config.LOCKOUT_TIME - user['attempt_diff']
                        flash(f'Account locked. Please try again in {remaining}  seconds.', 'danger')
                        return redirect(url_for('login'))
                    else:
                        # Réinitialisation après période de verrouillage
                        cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = %s", (user['id'],))
                        db.commit()
                
                # Récupération des composants
                try:
                    lattice = decrypt_component(user['lattice'])  # Handles base64 and AES-GCM
                    salt = decrypt_component(user['salt'])       # Handles base64 and AES-GCM
                    stored_encrypted_hash = user['password']
                    
                    # Déchiffrement du hash stocké
                    stored_decrypted_hash = ntru_decrypt(stored_encrypted_hash)
                    
                    # Recréation du hash
                    derived_key = derive_lattice_key(password, lattice, salt)
                    if not password_hasher.verify(stored_decrypted_hash, derived_key):
                        raise ValueError("The derived password does not match the stored hash")

                    # Authentification réussie
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    
                    # Réinitialisation des tentatives
                    cursor.execute("""
                        UPDATE users SET 
                        failed_attempts = 0,
                        last_login = NOW()
                        WHERE id = %s
                    """, (user['id'],))
                    db.commit()
                    
                    return redirect(url_for('home'))
                
                except Exception as e:
                    # Incrémentation des tentatives échouées
                    cursor.execute("""
                        UPDATE users SET 
                        failed_attempts = failed_attempts + 1,
                        last_attempt = NOW()
                        WHERE id = %s
                    """, (user['id'],))
                    db.commit()
                    
                    logger.error(f"Authentication failed for {username}: {str(e)}")
                    flash('Invalid credentials', 'danger')
                    return redirect(url_for('login'))
        
        except Exception as e:
            logger.error(f"Erreur système: {str(e)}")
            flash('Login failed due to a system error', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Gestion de la déconnexion"""
    session.clear()
    flash('You have been successfully logged out', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)