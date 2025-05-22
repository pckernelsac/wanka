import sqlite3
import os
from flask import g, current_app
import hashlib
import secrets
import time
import datetime

def get_db():
    """Obtener una conexión a la base de datos"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        
        # Habilitar clave externa para integridad referencial
        g.db.execute("PRAGMA foreign_keys = ON")
        
        # Optimizar rendimiento para lecturas frecuentes
        g.db.execute("PRAGMA cache_size = -10000")  # ~10MB de caché
        g.db.execute("PRAGMA temp_store = MEMORY")  # Usar memoria para temporales
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
    
    # Crear tabla de planes de suscripción
    db.execute('''
        CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            price REAL NOT NULL,
            duration_days INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1
        )
    ''')
    
    # Crear tabla de suscripciones de usuarios (CORREGIDA - SOLO UNA VEZ)
    db.execute('''
        CREATE TABLE IF NOT EXISTS user_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan_id INTEGER NOT NULL,
            start_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            end_date TIMESTAMP NOT NULL,
            payment_reference TEXT,
            voucher_path TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (plan_id) REFERENCES subscription_plans (id)
        )
    ''')
    
    # Verificar y agregar columnas faltantes en user_subscriptions
    if not column_exists('user_subscriptions', 'voucher_path'):
        try:
            db.execute('ALTER TABLE user_subscriptions ADD COLUMN voucher_path TEXT')
            db.commit()
        except sqlite3.Error:
            pass  # La columna ya existe o hay un error, continuar
    
    if not column_exists('user_subscriptions', 'created_at'):
        try:
            db.execute('ALTER TABLE user_subscriptions ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            db.commit()
        except sqlite3.Error:
            pass  # La columna ya existe o hay un error, continuar
    
    # Crear índices para búsqueda rápida de suscripciones
    db.execute('''
        CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id
        ON user_subscriptions (user_id)
    ''')
    
    db.execute('''
        CREATE INDEX IF NOT EXISTS idx_subscriptions_status
        ON user_subscriptions (status)
    ''')
    
    # Verificar si la tabla translations existe
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='translations'")
    table_exists = cursor.fetchone() is not None
    
    if not table_exists:
        # Crear tabla translations con todas las columnas
        db.execute('''
            CREATE TABLE translations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                spanish_word TEXT NOT NULL,
                quechua_word TEXT NOT NULL,
                audio_path TEXT NOT NULL,
                user_id INTEGER,
                allow_download BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(spanish_word COLLATE NOCASE),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Crear índices para optimizar búsquedas de palabras
        db.execute('''
            CREATE INDEX IF NOT EXISTS idx_translations_spanish
            ON translations (spanish_word COLLATE NOCASE)
        ''')
        
        db.execute('''
            CREATE INDEX IF NOT EXISTS idx_translations_quechua
            ON translations (quechua_word COLLATE NOCASE)
        ''')
    else:
        # La tabla ya existe, verificar y agregar columnas faltantes
        if not column_exists('translations', 'user_id'):
            try:
                db.execute('ALTER TABLE translations ADD COLUMN user_id INTEGER')
                db.execute('CREATE INDEX IF NOT EXISTS idx_translations_user_id ON translations (user_id)')
                db.commit()
            except sqlite3.Error:
                pass
        
        if not column_exists('translations', 'allow_download'):
            try:
                db.execute('ALTER TABLE translations ADD COLUMN allow_download BOOLEAN NOT NULL DEFAULT 0')
                db.commit()
            except sqlite3.Error:
                pass
        
        # Añadir índices si no existen
        try:
            db.execute('''
                CREATE INDEX IF NOT EXISTS idx_translations_spanish
                ON translations (spanish_word COLLATE NOCASE)
            ''')
            
            db.execute('''
                CREATE INDEX IF NOT EXISTS idx_translations_quechua
                ON translations (quechua_word COLLATE NOCASE)
            ''')
        except sqlite3.Error:
            pass  # Ignorar si los índices ya existen
    
    # Crear tabla para manejar caché de búsquedas populares
    db.execute('''
        CREATE TABLE IF NOT EXISTS search_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL UNIQUE,
            results TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            hit_count INTEGER DEFAULT 1
        )
    ''')
    
    # Crear tabla para estadísticas de uso
    db.execute('''
        CREATE TABLE IF NOT EXISTS usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action_type TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insertar roles básicos si no existen
    db.execute('''
        INSERT OR IGNORE INTO roles (id, name, description) 
        VALUES 
            (1, 'admin', 'Administrador con acceso completo'),
            (2, 'user', 'Usuario regular')
    ''')
    
    # Insertar planes de suscripción si no existen
    db.execute('''
        INSERT OR IGNORE INTO subscription_plans (id, name, description, price, duration_days, is_active) 
        VALUES 
            (1, 'Plan Anual', 'Acceso completo al traductor por un año', 80, 365, 1)
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

def create_user(username, email, password, full_name, role_id=2):
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

def create_subscription(user_id, plan_id, payment_reference=None):
    """Crea una nueva suscripción para un usuario"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Obtener detalles del plan
        cursor.execute('SELECT duration_days FROM subscription_plans WHERE id = ?', (plan_id,))
        plan = cursor.fetchone()
        
        if not plan:
            return False, "Plan de suscripción no encontrado"
        
        # Calcular fecha de finalización
        start_date = datetime.datetime.now()
        end_date = start_date + datetime.timedelta(days=plan['duration_days'])
        
        # Verificar si ya existe una suscripción activa
        cursor.execute(
            """
            SELECT id FROM user_subscriptions 
            WHERE user_id = ? AND status = 'active' AND end_date > ?
            """, (user_id, start_date)
        )
        
        if cursor.fetchone():
            return False, "Ya existe una suscripción activa para este usuario"
        
        # Insertar nueva suscripción
        cursor.execute(
            """
            INSERT INTO user_subscriptions 
            (user_id, plan_id, start_date, end_date, payment_reference, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
            """, (user_id, plan_id, start_date, end_date, payment_reference)
        )
        
        subscription_id = cursor.lastrowid
        db.commit()
        return True, subscription_id
    except sqlite3.Error as e:
        return False, f"Error al crear suscripción: {str(e)}"

def create_subscription_with_voucher(user_id, plan_id, voucher_path):
    """Crea una nueva suscripción con voucher de pago"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Obtener detalles del plan
        cursor.execute('SELECT duration_days FROM subscription_plans WHERE id = ?', (plan_id,))
        plan = cursor.fetchone()
        
        if not plan:
            return False, "Plan de suscripción no encontrado"
        
        # Calcular fecha de finalización
        start_date = datetime.datetime.now()
        end_date = start_date + datetime.timedelta(days=plan['duration_days'])
        
        # Verificar si ya existe una suscripción activa o pendiente
        cursor.execute(
            """
            SELECT id FROM user_subscriptions 
            WHERE user_id = ? AND status IN ('active', 'pendiente_pago') 
            AND end_date > ?
            """, (user_id, start_date)
        )
        
        if cursor.fetchone():
            return False, "Ya existe una suscripción activa o pendiente para este usuario"
        
        # Insertar nueva suscripción con voucher
        cursor.execute(
            """
            INSERT INTO user_subscriptions 
            (user_id, plan_id, start_date, end_date, voucher_path, status)
            VALUES (?, ?, ?, ?, ?, 'pendiente_pago')
            """, (user_id, plan_id, start_date, end_date, voucher_path)
        )
        
        subscription_id = cursor.lastrowid
        db.commit()
        return True, subscription_id
        
    except sqlite3.Error as e:
        return False, f"Error al crear suscripción: {str(e)}"

def activate_subscription(subscription_id):
    """Activa una suscripción pendiente"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            UPDATE user_subscriptions 
            SET status = 'active', last_updated = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('pending', 'pendiente_pago')
            """, (subscription_id,)
        )
        
        if cursor.rowcount == 0:
            return False, "Suscripción no encontrada o no se puede activar"
        
        db.commit()
        return True, "Suscripción activada correctamente"
    except sqlite3.Error as e:
        return False, f"Error al activar suscripción: {str(e)}"

def cancel_subscription(subscription_id):
    """Cancela una suscripción activa"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            UPDATE user_subscriptions 
            SET status = 'cancelled', last_updated = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'active'
            """, (subscription_id,)
        )
        
        if cursor.rowcount == 0:
            return False, "Suscripción no encontrada o no se puede cancelar"
        
        db.commit()
        return True, "Suscripción cancelada correctamente"
    except sqlite3.Error as e:
        return False, f"Error al cancelar suscripción: {str(e)}"

def check_active_subscription(user_id):
    """Verifica si un usuario tiene una suscripción activa"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            SELECT us.*, sp.name as plan_name
            FROM user_subscriptions us
            JOIN subscription_plans sp ON us.plan_id = sp.id
            WHERE us.user_id = ? AND us.status = 'active' AND us.end_date > ?
            ORDER BY us.end_date DESC LIMIT 1
            """, (user_id, datetime.datetime.now())
        )
        
        subscription = cursor.fetchone()
        return subscription is not None, subscription
    except sqlite3.Error:
        return False, None

def get_all_subscriptions(status=None, page=1, per_page=20):
    """Obtiene todas las suscripciones, opcionalmente filtradas por estado"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        query = """
            SELECT us.*, u.username, u.email, u.full_name, sp.name as plan_name
            FROM user_subscriptions us
            JOIN users u ON us.user_id = u.id
            JOIN subscription_plans sp ON us.plan_id = sp.id
        """
        params = []
        
        if status:
            query += " WHERE us.status = ?"
            params.append(status)
        
        query += " ORDER BY us.last_updated DESC"
        
        # Aplicar paginación
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        subscriptions = cursor.fetchall()
        
        # Obtener el conteo total para la paginación
        count_query = """
            SELECT COUNT(*) as total FROM user_subscriptions
        """
        
        if status:
            count_query += " WHERE status = ?"
            cursor.execute(count_query, [status])
        else:
            cursor.execute(count_query)
            
        total = cursor.fetchone()['total']
        
        return subscriptions, total, per_page
    except sqlite3.Error as e:
        current_app.logger.error(f"Error en get_all_subscriptions: {str(e)}")
        return [], 0, per_page

def add_search_cache(query, results):
    """Guarda resultados de búsqueda en caché"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Intentar insertar o actualizar
        cursor.execute(
            """
            INSERT INTO search_cache (query, results)
            VALUES (?, ?)
            ON CONFLICT(query) DO UPDATE SET
            hit_count = hit_count + 1,
            created_at = CURRENT_TIMESTAMP
            """, (query.lower(), results)
        )
        db.commit()
        return True
    except sqlite3.Error:
        return False

def get_search_cache(query):
    """Obtiene resultados de caché para una búsqueda"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            SELECT results, hit_count 
            FROM search_cache 
            WHERE query = ? 
            AND created_at > datetime('now', '-1 day')
            """, (query.lower(),)
        )
        
        result = cursor.fetchone()
        if result:
            # Actualizar contador de hits
            cursor.execute(
                """
                UPDATE search_cache 
                SET hit_count = hit_count + 1 
                WHERE query = ?
                """, (query.lower(),)
            )
            db.commit()
            return result['results']
        return None
    except sqlite3.Error:
        return None

def add_usage_stat(user_id, action_type, details=None):
    """Registra una acción de uso para analíticas"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            """
            INSERT INTO usage_stats (user_id, action_type, details)
            VALUES (?, ?, ?)
            """, (user_id, action_type, details)
        )
        db.commit()
        return True
    except sqlite3.Error:
        return False

def get_subscription_stats():
    """Obtiene estadísticas básicas de suscripciones"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'pendiente_pago' THEN 1 ELSE 0 END) as pending_payment,
                SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM user_subscriptions
        """)
        return cursor.fetchone()
    except sqlite3.Error:
        return {
            'total': 0,
            'active': 0,
            'pending': 0,
            'pending_payment': 0,
            'expired': 0,
            'cancelled': 0,
            'rejected': 0
        }