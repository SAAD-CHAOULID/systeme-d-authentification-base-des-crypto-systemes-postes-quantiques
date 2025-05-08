import sys
sys.path.append('.')  # Pour importer app.py

from app import app, prepare_password, ntru_encrypt, ntru_decrypt, derive_lattice_key
from hash import ph as password_hasher
import base64

def test_ntru_chain():
    test_pw = "TestPassword123!"
    print("\n=== Test complet ===")
    
    # 1. Préparation
    test_data = prepare_password(test_pw)
    print("Salt:", test_data['salt'][:10] + "...")
    print("Lattice:", test_data['lattice'][:10] + "...")
    
    # 2. Test NTRU
    encrypted = ntru_encrypt(test_data['hashed'])
    decrypted = ntru_decrypt(encrypted)
    print("\n[NTRU]")
    print("Original:", test_data['hashed'][:50] + "...")
    print("Déchiffré:", decrypted[:50] + "...")
    print("Match:", decrypted == test_data['hashed'])
    
    # 3. Test Dérivation
    lattice = base64.b64decode(test_data['lattice'].encode('utf-8'))
    salt = base64.b64decode(test_data['salt'].encode('utf-8'))
    derived = derive_lattice_key(test_pw, lattice, salt)
    print("\n[Dérivation]")
    match = password_hasher.verify(test_data['hashed'], derived)
    print("Match:", match)

if __name__ == '__main__':
    with app.app_context():
        test_ntru_chain()