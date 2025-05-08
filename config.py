import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'  # Utilisateur par défaut XAMPP
    MYSQL_PASSWORD = ''  # Mot de passe par défaut XAMPP
    MYSQL_DB = 'ntru_auth_db'  # Remplacez par le nom de votre base
    NTRU_SCRIPT_PATH = 'C:/Users/hp/Documents/ntru_auth_app/NTRU_python-main/NTRU.py'
    NTRU_KEY_PATH = 'C:/Users/hp/Documents/ntru_auth_app/NTRU_python-main/examples/NTRU_key'
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300  # 5 minutes en secondes