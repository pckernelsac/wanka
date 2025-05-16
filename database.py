import sqlite3
import os
from flask import g, current_app
import hashlib
import secrets

def get_db():
    """Obtener una conexión a la base de datos"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Cerrar la conexión a la base de datos"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def column_exists(table, column):
    """Verifica si una columna existe en una tabla"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row['name'] for row in cursor.fetchall()]
    return column in columns

def init_db():
    """Inicializar la base de datos con el esquema"""
    db = get_db()
    
    # Crear la tabla de roles si no existe
    db.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
    ''')
    
    # Crear la tabla de usuarios si no existe
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role_id INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            is_verified BOOLEAN NOT NULL DEFAULT 0,
            verification_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (id)
        )
    ''')
    
    # Verificar si la tabla translations existe
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='translations'")
    table_exists = cursor.fetchone() is not None
    
    if not table_exists:
        # Crear tabla translations con todas las columnas nuevas
        db.execute('''
            CREATE TABLE translations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                spanish_word TEXT NOT NULL,
                quechua_word TEXT NOT NULL,
                audio_path TEXT NOT NULL,
                user_id INTEGER,
                is_approved BOOLEAN NOT NULL DEFAULT 0,
                allow_download BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(spanish_word COLLATE NOCASE),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    else:
        # La tabla ya existe, verificar y añadir columnas que falten
        # Verificar columna user_id
        if not column_exists('translations', 'user_id'):
            db.execute('ALTER TABLE translations ADD COLUMN user_id INTEGER')
        
        # Verificar columna is_approved
        if not column_exists('translations', 'is_approved'):
            db.execute('ALTER TABLE translations ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT 1')
            # Establecer todos los registros existentes como aprobados
            db.execute('UPDATE translations SET is_approved = 1')
        
        # Verificar columna allow_download
        if not column_exists('translations', 'allow_download'):
            db.execute('ALTER TABLE translations ADD COLUMN allow_download BOOLEAN NOT NULL DEFAULT 0')
    
    # Insertar roles básicos si no existen
    db.execute('''
        INSERT OR IGNORE INTO roles (id, name, description) 
        VALUES 
            (1, 'admin', 'Administrador con acceso completo'),
            (2, 'translator', 'Traductor certificado'),
            (3, 'user', 'Usuario regular')
    ''')
    
    # Crear usuario administrador por defecto si no existe
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = "admin"')
    if not cursor.fetchone():
        # Generar hash de contraseña para admin (contraseña: "admin123")
        salt = secrets.token_hex(8)
        password_hash = hashlib.sha256(('admin123' + salt).encode()).hexdigest() + ':' + salt
        
        db.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role_id, is_active, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@quechuachanka.org', password_hash, 'Administrador', 1, 1, 1))
    
    db.commit()

def hash_password(password):
    """Genera un hash seguro para la contraseña"""
    salt = secrets.token_hex(8)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt

def verify_password(stored_password, provided_password):
    """Verifica si la contraseña proporcionada coincide con el hash almacenado"""
    hash_part, salt = stored_password.split(':')
    return hash_part == hashlib.sha256((provided_password + salt).encode()).hexdigest()

def get_user_by_username(username):
    """Obtiene un usuario por su nombre de usuario"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT u.*, r.name as role_name 
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.username = ?
        """, (username,)
    )
    return cursor.fetchone()

def get_user_by_email(email):
    """Obtiene un usuario por su correo electrónico"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT u.*, r.name as role_name 
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.email = ?
        """, (email,)
    )
    return cursor.fetchone()

def create_user(username, email, password, full_name, role_id=3):
    """Crea un nuevo usuario"""
    db = get_db()
    cursor = db.cursor()
    
    # Verificar si el usuario o email ya existen
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    if cursor.fetchone():
        return False, "El nombre de usuario o correo electrónico ya está en uso."
    
    # Generar token de verificación
    verification_token = secrets.token_urlsafe(32)
    
    try:
        # Insertar el nuevo usuario
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, full_name, role_id, verification_token)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, hash_password(password), full_name, role_id, verification_token)
        )
        db.commit()
        return True, verification_token
    except sqlite3.Error as e:
        return False, f"Error al crear usuario: {str(e)}"

def verify_user(verification_token):
    """Verifica un usuario mediante su token"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT id FROM users WHERE verification_token = ?', (verification_token,))
    user = cursor.fetchone()
    
    if not user:
        return False
    
    try:
        cursor.execute(
            """
            UPDATE users 
            SET is_verified = 1, verification_token = NULL
            WHERE id = ?
            """, (user['id'],)
        )
        db.commit()
        return True
    except sqlite3.Error:
        return False

def update_last_login(user_id):
    """Actualiza la fecha de último login"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            UPDATE users 
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
            """, (user_id,)
        )
        db.commit()
        return True
    except sqlite3.Error:
        return False