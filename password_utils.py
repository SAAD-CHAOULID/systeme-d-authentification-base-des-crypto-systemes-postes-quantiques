import subprocess
from config import Config
from hash import derive_lattice_key, ph as password_hasher
import base64
import secrets
import logging
import json
import re  
from hash import encrypt_component 



logger = logging.getLogger(__name__)

def password_is_strong(password: str) -> bool:
    """
    Vérifie la complexité d'un mot de passe.
    Règles : min 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial.
    """
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True
def prepare_password(password: str) -> dict:
    salt = secrets.token_bytes(16)
    lattice = secrets.token_bytes(32)
    derived_key = derive_lattice_key(password, lattice, salt)
    
    # Encrypt the components before storage
    return {
        'hashed': password_hasher.hash(derived_key),
        'lattice': encrypt_component(lattice),  # Now encrypted
        'salt': encrypt_component(salt)         # Now encrypted
    }
def ntru_encrypt(data: str) -> str:
    """
    Chiffre des données avec NTRU via le script externe
    :param data: Données à chiffrer
    :return: Données chiffrées
    """
    try:
        cmd = [
            'python',
            Config.NTRU_SCRIPT_PATH,
            '-k', Config.NTRU_KEY_PATH,
            '-eS', data,
            '-T'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            error_msg = f"NTRU encryption error: {result.stderr}"
            logger.error(error_msg)
            raise Exception(error_msg)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        error_msg = "NTRU encryption timeout"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        logger.error(f"Unexpected NTRU encryption error: {str(e)}")
        raise

def ntru_decrypt(encrypted: str) -> str:
    """
    Déchiffre des données avec NTRU via le script externe
    :param encrypted: Données chiffrées
    :return: Données déchiffrées
    """
    try:
        cmd = [
            'python',
            Config.NTRU_SCRIPT_PATH,
            '-k', Config.NTRU_KEY_PATH,
            '-dS', encrypted,
            '-T'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            error_msg = f"NTRU decryption error: {result.stderr}"
            logger.error(error_msg)
            raise Exception(error_msg)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        error_msg = "NTRU decryption timeout"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        logger.error(f"Unexpected NTRU decryption error: {str(e)}")
        raise