import numpy as np
import secrets
import json
import os
import time
import logging
from getpass import getpass
from hashlib import shake_256, sha3_512
from argon2 import PasswordHasher, exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode

# Configuration renforcée
ENCRYPTION_KEY = os.getenv('COMPONENT_ENCRYPTION_KEY', secrets.token_bytes(32))
LATTICE_SIZE = 64          # Augmenté à 64 bytes (512 bits)
DERIVED_KEY_SIZE = 64      # Augmenté à 64 bytes (512 bits)
USER_DB_FILE = "secure_user_database.json"
SALT_SIZE = 32             # Augmenté à 32 bytes (256 bits)
MAX_LOGIN_ATTEMPTS = 5     # Nombre maximum de tentatives de connexion
LOCKOUT_TIME = 300         # Temps de verrouillage en secondes (5 minutes)
LOG_FILE = "auth_security.log"

# Configuration Argon2 renforcée
ph = PasswordHasher(
    time_cost=4,           # Augmenté
    memory_cost=262144,    # Augmenté à 256 MB
    parallelism=8,
    hash_len=64            # Augmenté
)

# Configuration du logging sécurisé
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Stockage des tentatives de connexion
login_attempts = {}

def secure_compare(a, b):
    """Compare deux chaînes de façon sécurisée contre les attaques temporelles"""
    return secrets.compare_digest(a, b)

def derive_lattice_key(password: str, lattice_matrix: bytes, salt: bytes) -> bytes:
    """Derive une clé à partir du mot de passe en utilisant plusieurs techniques"""
    # Étape 1: Préparation des données d'entrée
    password_bytes = password.encode('utf-8')
    
    # Étape 2: Première dérivation avec PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=salt,
        iterations=100000,
    )
    intermediate_key = kdf.derive(password_bytes)
    
    # Étape 3: Combinaison avec la matrice lattice
    combined = intermediate_key + lattice_matrix
    
    # Étape 4: Hachage final avec SHAKE-256 pour plus de sécurité
    return shake_256(combined).digest(DERIVED_KEY_SIZE)

def encrypt_sensitive_data(data: dict, master_key: bytes) -> bytes:
    """Chiffre des données sensibles avec AES-GCM"""
    # Génération d'un nonce aléatoire pour AES-GCM
    nonce = secrets.token_bytes(12)
    
    # Conversion des données en JSON puis en bytes
    data_bytes = json.dumps(data).encode('utf-8')
    
    # Chiffrement avec AES-GCM
    aesgcm = AESGCM(master_key[:32])  # On utilise les 32 premiers octets pour AES-256
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    
    # Combinaison du nonce et du ciphertext pour le stockage
    return b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_sensitive_data(encrypted_data: str, master_key: bytes) -> dict:
    """Déchiffre des données sensibles"""
    try:
        # Décodage base64
        data_bytes = b64decode(encrypted_data)
        
        # Extraction du nonce et du ciphertext
        nonce = data_bytes[:12]
        ciphertext = data_bytes[12:]
        
        # Déchiffrement avec AES-GCM
        aesgcm = AESGCM(master_key[:32])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Conversion bytes en dictionnaire JSON
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        logging.error(f"Erreur de déchiffrement: {e}")
        return None
    
def encrypt_component(data: bytes) -> str:
    """Encrypt lattice/salt components with AES-GCM"""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(ENCRYPTION_KEY)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_component(encrypted: str) -> bytes:
    """Decrypt lattice/salt components"""
    data = b64decode(encrypted)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(ENCRYPTION_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

# 1. Key Management: Use environment variables, not hardcoded keys
ENCRYPTION_KEY = os.getenv('COMPONENT_ENCRYPTION_KEY', secrets.token_bytes(32))

# 2. Key Rotation: Periodically rotate keys for long-term security
KEY_ROTATION_DAYS = 90  # Rotate every 90 days

def rotate_encryption_key():
    """Example key rotation logic (call periodically)"""
    global ENCRYPTION_KEY
    new_key = secrets.token_bytes(32)
    # TODO: Add migration logic for re-encrypting existing data
    ENCRYPTION_KEY = new_key

# 3. Validate inputs to prevent tampering
def validate_encrypted_component(encrypted: str) -> bool:
    """Check if the encrypted data has a valid format (nonce + ciphertext)"""
    try:
        data = b64decode(encrypted)
        return len(data) >= 12  # Nonce (12) + minimum ciphertext length
    except Exception:
        return False
# ===== END SECURITY CONSIDERATIONS ===== #

def create_account(username: str, password: str):
    """Crée un compte avec sécurité maximale"""
    # Validation des entrées
    if len(username) < 4 or len(password) < 12:
        print("Le nom d'utilisateur doit contenir au moins 4 caractères et le mot de passe au moins 12 caractères.")
        return
    
    # Vérification de la complexité du mot de passe
    if not (any(c.isupper() for c in password) and 
            any(c.islower() for c in password) and 
            any(c.isdigit() for c in password) and 
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in password)):
        print("Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial.")
        return
    
    # Initialisation de la base de données si nécessaire
    if not os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'w') as f:
            json.dump({}, f)
    
    # Lecture de la base de données existante
    try:
        with open(USER_DB_FILE, 'r') as f:
            user_db = json.load(f)
    except json.JSONDecodeError:
        user_db = {}
    
    # Vérification si l'utilisateur existe déjà
    if username in user_db:
        print("Nom d'utilisateur déjà existant.")
        return
    
    # Génération de la matrice et du sel aléatoires
    lattice_matrix = secrets.token_bytes(LATTICE_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    
    # Double dérivation de clé avec la matrice et le sel
    derived_key = derive_lattice_key(password, lattice_matrix, salt)
    
    # Hachage final avec Argon2
    try:
        password_hash = ph.hash(derived_key)
        
        # Génération d'un sel supplémentaire pour le chiffrement des données
        encryption_salt = secrets.token_bytes(SALT_SIZE)
        
        # Dérivation d'une clé de chiffrement distincte
        encryption_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=encryption_salt,
            iterations=50000,
        )
        encryption_key = encryption_kdf.derive(derived_key)
        
        # Préparation des données utilisateur
        user_profile = {
            "created_at": time.time(),
            "last_password_change": time.time(),
            "account_type": "standard",
            "session_data": {}
        }
        
        # Chiffrement des données sensibles
        encrypted_profile = encrypt_sensitive_data(user_profile, encryption_key)
        
        # Stockage sécurisé des données
        user_db[username] = {
            "hash": password_hash,
            "lattice_matrix": b64encode(lattice_matrix).decode('utf-8'),
            "salt": b64encode(salt).decode('utf-8'),
            "encryption_salt": b64encode(encryption_salt).decode('utf-8'),
            "profile": encrypted_profile,
            "created_at": time.time(),
            "login_blocked_until": 0,
            "failed_attempts": 0
        }
        
        # Écriture sécurisée avec transaction atomique
        temp_file = USER_DB_FILE + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(user_db, f, indent=4)
        
        # Remplacement atomique pour éviter la corruption de fichier
        os.replace(temp_file, USER_DB_FILE)
        
        logging.info(f"Compte créé pour l'utilisateur: {username}")
        print(f"Compte créé avec succès pour {username}.")
        
    except exceptions.HashingError as e:
        logging.error(f"Erreur de hachage pour {username}: {e}")
        print("Erreur lors de la création du compte. Veuillez réessayer.")

def login(username: str, password: str) -> bool:
    """Vérifie les identifiants avec protection avancée"""
    # Vérification de l'existence de la base de données
    if not os.path.exists(USER_DB_FILE):
        logging.warning("Tentative de connexion: Base de données introuvable")
        print("Base de données introuvable.")
        return False
    
    # Lecture de la base de données
    try:
        with open(USER_DB_FILE, 'r') as f:
            user_db = json.load(f)
    except json.JSONDecodeError:
        logging.error("Erreur de lecture de la base de données utilisateurs")
        print("Erreur de lecture de la base de données.")
        return False
    
    # Vérification de l'existence de l'utilisateur
    if username not in user_db:
        # Simulation d'un temps de vérification pour éviter les attaques temporelles
        time.sleep(secrets.randbelow(500) / 1000)  # Délai aléatoire entre 0 et 500ms
        logging.warning(f"Tentative de connexion avec un utilisateur inconnu: {username}")
        print("Identifiants incorrects.")
        return False
    
    user_data = user_db[username]
    
    # Vérification du verrouillage de compte
    current_time = time.time()
    if user_data["login_blocked_until"] > current_time:
        remaining_time = int(user_data["login_blocked_until"] - current_time)
        logging.warning(f"Tentative de connexion à un compte verrouillé: {username}")
        print(f"Compte temporairement verrouillé. Réessayez dans {remaining_time} secondes.")
        return False
    
    # Récupération de la matrice et du sel
    try:
        lattice_matrix = b64decode(user_data["lattice_matrix"])
        salt = b64decode(user_data["salt"])
    except Exception as e:
        logging.error(f"Erreur de décodage des données pour {username}: {e}")
        print("Erreur système. Contactez l'administrateur.")
        return False
    
    # Régénération de la clé dérivée
    derived_key = derive_lattice_key(password, lattice_matrix, salt)
    
    # Vérification du mot de passe
    try:
        ph.verify(user_data["hash"], derived_key)
        
        # Réinitialisation des tentatives de connexion
        user_db[username]["failed_attempts"] = 0
        user_db[username]["last_login"] = current_time
        
        # Vérification besoin de rehachage
        if ph.check_needs_rehash(user_data["hash"]):
            logging.info(f"Rehachage du mot de passe pour {username}")
            user_db[username]["hash"] = ph.hash(derived_key)
        
        # Enregistrement des modifications
        temp_file = USER_DB_FILE + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(user_db, f, indent=4)
        os.replace(temp_file, USER_DB_FILE)
        
        logging.info(f"Connexion réussie pour {username}")
        print("Connexion réussie.")
        return True
    
    except exceptions.VerifyMismatchError:
        # Gestion des tentatives échouées
        user_db[username]["failed_attempts"] += 1
        failed_attempts = user_db[username]["failed_attempts"]
        
        # Verrouillage du compte si nécessaire
        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            user_db[username]["login_blocked_until"] = current_time + LOCKOUT_TIME
            logging.warning(f"Compte verrouillé pour {username} après {failed_attempts} tentatives échouées")
            print(f"Trop de tentatives échouées. Compte verrouillé pendant {LOCKOUT_TIME//60} minutes.")
        else:
            remaining_attempts = MAX_LOGIN_ATTEMPTS - failed_attempts
            print(f"Échec d'authentification. {remaining_attempts} tentative(s) restante(s).")
        
        # Enregistrement des modifications
        temp_file = USER_DB_FILE + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(user_db, f, indent=4)
        os.replace(temp_file, USER_DB_FILE)
        
        logging.warning(f"Échec d'authentification pour {username} - {failed_attempts} tentative(s)")
        return False
    except Exception as e:
        logging.error(f"Erreur lors de la vérification pour {username}: {e}")
        print("Erreur système lors de la vérification.")
        return False

def change_password(username: str, current_password: str, new_password: str) -> bool:
    """Permet de changer le mot de passe de manière sécurisée"""
    # Vérification de la force du nouveau mot de passe
    if len(new_password) < 12:
        print("Le nouveau mot de passe doit contenir au moins 12 caractères.")
        return False
        
    if not (any(c.isupper() for c in new_password) and 
            any(c.islower() for c in new_password) and 
            any(c.isdigit() for c in new_password) and 
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in new_password)):
        print("Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial.")
        return False
    
    # Vérification des identifiants actuels
    if not login(username, current_password):
        return False
    
    try:
        with open(USER_DB_FILE, 'r') as f:
            user_db = json.load(f)
        
        user_data = user_db[username]
        
        # Génération d'une nouvelle matrice et d'un nouveau sel
        new_lattice_matrix = secrets.token_bytes(LATTICE_SIZE)
        new_salt = secrets.token_bytes(SALT_SIZE)
        
        # Dérivation et hachage du nouveau mot de passe
        derived_key = derive_lattice_key(new_password, new_lattice_matrix, new_salt)
        password_hash = ph.hash(derived_key)
        
        # Mise à jour des données utilisateur
        user_db[username]["hash"] = password_hash
        user_db[username]["lattice_matrix"] = b64encode(new_lattice_matrix).decode('utf-8')
        user_db[username]["salt"] = b64encode(new_salt).decode('utf-8')
        user_db[username]["last_password_change"] = time.time()
        
        # Enregistrement des modifications
        temp_file = USER_DB_FILE + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(user_db, f, indent=4)
        os.replace(temp_file, USER_DB_FILE)
        
        logging.info(f"Mot de passe modifié pour {username}")
        print("Mot de passe modifié avec succès.")
        return True
        
    except Exception as e:
        logging.error(f"Erreur lors du changement de mot de passe pour {username}: {e}")
        print("Erreur lors du changement de mot de passe.")
        return False

def delete_account(username: str, password: str) -> bool:
    """Supprime un compte utilisateur de façon sécurisée"""
    # Vérification des identifiants
    if not login(username, password):
        return False
    
    try:
        with open(USER_DB_FILE, 'r') as f:
            user_db = json.load(f)
        
        # Suppression du compte
        if username in user_db:
            del user_db[username]
            
            # Enregistrement des modifications
            temp_file = USER_DB_FILE + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(user_db, f, indent=4)
            os.replace(temp_file, USER_DB_FILE)
            
            logging.info(f"Compte supprimé: {username}")
            print("Compte supprimé avec succès.")
            return True
    
    except Exception as e:
        logging.error(f"Erreur lors de la suppression du compte {username}: {e}")
        print("Erreur lors de la suppression du compte.")
        return False

def main():
    """Interface principale du système d'authentification"""
    print("\n===== SYSTÈME D'AUTHENTIFICATION SÉCURISÉ =====")
    print("1. Créer un compte")
    print("2. Se connecter")
    print("3. Changer de mot de passe")
    print("4. Supprimer un compte")
    print("5. Quitter")
    
    try:
        choice = input("\nChoisissez une option (1-5): ")
        
        if choice == '1':
            username = input("Nom d'utilisateur: ")
            password = getpass("Mot de passe: ")
            password_confirm = getpass("Confirmez le mot de passe: ")
            
            if password != password_confirm:
                print("Les mots de passe ne correspondent pas.")
                return
            
            create_account(username, password)
            
        elif choice == '2':
            username = input("Nom d'utilisateur: ")
            password = getpass("Mot de passe: ")
            
            if login(username, password):
                print("\nBienvenue dans le système sécurisé !")
                print("Accès accordé. Vous êtes maintenant connecté.")
            
        elif choice == '3':
            username = input("Nom d'utilisateur: ")
            current_password = getpass("Mot de passe actuel: ")
            new_password = getpass("Nouveau mot de passe: ")
            confirm_password = getpass("Confirmez le nouveau mot de passe: ")
            
            if new_password != confirm_password:
                print("Les nouveaux mots de passe ne correspondent pas.")
                return
                
            change_password(username, current_password, new_password)
            
        elif choice == '4':
            username = input("Nom d'utilisateur: ")
            password = getpass("Mot de passe: ")
            confirm = input("Êtes-vous sûr de vouloir supprimer votre compte ? (oui/non): ")
            
            if confirm.lower() == 'oui':
                delete_account(username, password)
            else:
                print("Suppression annulée.")
                
        elif choice == '5':
            print("Au revoir !")
            
        else:
            print("Option invalide.")
            
    except KeyboardInterrupt:
        print("\nOpération annulée.")
    except Exception as e:
        logging.error(f"Erreur non gérée: {e}")
        print("Une erreur inattendue s'est produite.")

if __name__ == "__main__":
    main()