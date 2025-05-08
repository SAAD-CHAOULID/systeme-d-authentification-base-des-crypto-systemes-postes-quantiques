import pymysql
from pymysql.cursors import DictCursor
from config import Config
import logging

logger = logging.getLogger(__name__)

def init_db(app):
    """Crée la table users avec toutes les colonnes nécessaires"""
    try:
        connection = pymysql.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            db=Config.MYSQL_DB,
            charset='utf8mb4',
            cursorclass=DictCursor
        )
        
        with connection.cursor() as cursor:
            # Création complète de la table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    lattice TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name VARCHAR(100) NOT NULL,
                    failed_attempts INT DEFAULT 0,
                    last_attempt TIMESTAMP NULL,
                    last_login TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            connection.commit()
            logger.info("Table users créée avec succès")
            
    except pymysql.Error as e:
        logger.error(f"Erreur DB: {e}")
        raise
    finally:
        if connection:
            connection.close()