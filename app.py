from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash, session, abort
from functools import wraps
import os
import uuid
import datetime
from database import init_db, get_db, get_user_by_username, get_user_by_email, create_user, verify_password, verify_user, update_last_login, column_exists
import sqlite3
import json
import logging

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Configurar logging
logging.basicConfig(level=logging.INFO)

# Configurar session secret key
app.secret_key = app.config['SECRET_KEY']

# Asegúrate de que exista el directorio para guardar audios
os.makedirs(app.config['AUDIO_FOLDER'], exist_ok=True)

# Inicializar la base de datos
with app.app_context():
    init_db()

# --- Decoradores para autenticación y autorización ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicia sesión para acceder a esta página', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Por favor inicia sesión para acceder a esta página', 'warning')
                return redirect(url_for('login', next=request.url))
            
            if session.get('user_role') != role and session.get('user_role') != 'admin':
                flash('No tienes permiso para acceder a esta página', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Manejador de errores global ---

@app.errorhandler(500)
def internal_server_error(e):
    # Si la solicitud espera JSON, devolver error en formato JSON
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Error interno del servidor', 'details': str(e)}), 500
    # De lo contrario, mostrar página de error
    return render_template('error.html', error=str(e)), 500

@app.errorhandler(404)
def not_found_error(e):
    # Si la solicitud espera JSON, devolver error en formato JSON
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Recurso no encontrado'}), 404
    # De lo contrario, mostrar página de error
    return render_template('error.html', error='Página no encontrada'), 404

# --- Rutas de autenticación ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Vista de inicio de sesión"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username) or get_user_by_email(username)
        
        if user and verify_password(user['password_hash'], password):
            if not user['is_active']:
                flash('Tu cuenta ha sido desactivada. Contacta al administrador.', 'danger')
                return render_template('auth/login.html')
            
            if not user['is_verified']:
                flash('Tu cuenta aún no ha sido verificada. Revisa tu correo electrónico.', 'warning')
                return render_template('auth/login.html')
            
            # Establecer sesión
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_role'] = user['role_name']
            
            # Actualizar último login
            update_last_login(user['id'])
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
                
            flash(f'¡Bienvenido de nuevo, {user["username"]}!', 'success')
            return redirect(next_page)
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session.clear()
    flash('Has cerrado sesión correctamente', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Vista de registro de usuario"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        
        # Validaciones básicas
        if not username or not email or not password or not confirm_password:
            flash('Todos los campos son obligatorios', 'danger')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return render_template('auth/register.html')
        
        # Crear usuario (por defecto como rol 'user')
        success, message = create_user(username, email, password, full_name)
        
        if success:
            flash('Registro exitoso. Por favor, verifica tu correo para activar tu cuenta.', 'success')
            # Para facilitar desarrollo, verificamos automáticamente al usuario
            verify_user(message)  # message contiene el token de verificación
            flash('Tu cuenta ha sido verificada automáticamente para este ambiente de desarrollo.', 'info')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/register.html')

@app.route('/verify/<token>')
def verify_account(token):
    """Verificar cuenta de usuario"""
    if verify_user(token):
        flash('Tu cuenta ha sido verificada correctamente. Ahora puedes iniciar sesión.', 'success')
    else:
        flash('El enlace de verificación es inválido o ha expirado.', 'danger')
    
    return redirect(url_for('login'))

@app.route('/request-translator', methods=['GET', 'POST'])
@login_required
def request_translator():
    """Solicitar rol de traductor"""
    if request.method == 'POST':
        # Aquí se procesaría la solicitud
        flash('Tu solicitud ha sido enviada. Te notificaremos cuando sea revisada.', 'success')
        return redirect(url_for('index'))
    
    return render_template('auth/request_translator.html')

# --- Rutas principales ---

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/translator')
@login_required
@role_required('translator')
def translator_view():
    """Vista del traductor para agregar traducciones (solo traductores)"""
    return render_template('translator.html')

@app.route('/user')
def user_view():
    """Vista del usuario para buscar traducciones (acceso público)"""
    return render_template('user.html')

# --- Rutas de API ---

@app.route('/api/translations')
def get_translations():
    """API para obtener todas las traducciones aprobadas"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si la columna allow_download existe
        has_allow_download = column_exists('translations', 'allow_download')
        has_is_approved = column_exists('translations', 'is_approved')
        has_user_id = column_exists('translations', 'user_id')
        
        query = """
            SELECT t.id, t.spanish_word, t.quechua_word, t.audio_path, t.created_at
        """
        
        # Añadir columnas condicionales a la consulta
        if has_allow_download:
            query += ", t.allow_download"
        else:
            query += ", 0 as allow_download"
            
        if has_user_id:
            query += ", u.username as translator_username"
            
        # Construir la parte FROM de la consulta
        query += " FROM translations t"
        
        if has_user_id:
            query += " LEFT JOIN users u ON t.user_id = u.id"
            
        # Construir la parte WHERE de la consulta
        if has_is_approved:
            query += " WHERE t.is_approved = 1"
            
        query += " ORDER BY t.spanish_word"
        
        cursor.execute(query)
        
        translations = []
        for row in cursor.fetchall():
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': row['created_at'],
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys():
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Anónimo'
                
            translations.append(translation)
        
        return jsonify(translations)
    except Exception as e:
        app.logger.error(f"Error en get_translations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/translation/<string:word>')
def get_translation(word):
    """API para obtener la traducción de una palabra específica"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si las columnas existen
        has_allow_download = column_exists('translations', 'allow_download')
        has_is_approved = column_exists('translations', 'is_approved')
        has_user_id = column_exists('translations', 'user_id')
        
        query = """
            SELECT t.id, t.spanish_word, t.quechua_word, t.audio_path, t.created_at
        """
        
        # Añadir columnas condicionales a la consulta
        if has_allow_download:
            query += ", t.allow_download"
        else:
            query += ", 0 as allow_download"
            
        if has_user_id:
            query += ", u.username as translator_username"
            
        # Construir la parte FROM de la consulta
        query += " FROM translations t"
        
        if has_user_id:
            query += " LEFT JOIN users u ON t.user_id = u.id"
            
        # Construir la parte WHERE de la consulta
        query += " WHERE LOWER(t.spanish_word) = LOWER(?)"
        
        if has_is_approved:
            query += " AND t.is_approved = 1"
        
        cursor.execute(query, (word,))
        
        row = cursor.fetchone()
        if row:
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': row['created_at'],
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys():
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Anónimo'
                
            return jsonify(translation)
        
        return jsonify({'error': 'Traducción no encontrada'}), 404
    except Exception as e:
        app.logger.error(f"Error en get_translation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-translation', methods=['POST'])
@login_required
@role_required('translator')
def save_translation():
    """API para guardar una nueva traducción (solo traductores)"""
    try:
        if 'audio' not in request.files:
            return jsonify({'error': 'No se proporcionó archivo de audio'}), 400
        
        audio_file = request.files['audio']
        spanish_word = request.form.get('spanish_word', '').strip()
        quechua_word = request.form.get('quechua_word', '').strip()
        allow_download = request.form.get('allow_download', 'false').lower() == 'true'
        
        if not spanish_word or not quechua_word:
            return jsonify({'error': 'Faltan campos requeridos'}), 400
        
        if audio_file.filename == '':
            return jsonify({'error': 'No se seleccionó un archivo de audio'}), 400
        
        # Generar nombre único para el archivo de audio
        filename = f"{uuid.uuid4()}.webm"
        file_path = os.path.join(app.config['AUDIO_FOLDER'], filename)
        
        # Guardar el archivo de audio
        audio_file.save(file_path)
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si existen columnas necesarias
        has_allow_download = column_exists('translations', 'allow_download')
        has_is_approved = column_exists('translations', 'is_approved')
        has_user_id = column_exists('translations', 'user_id')
        
        # Si el usuario es admin, la traducción se aprueba automáticamente
        auto_approve = session.get('user_role') == 'admin'
        
        # Construir la consulta según las columnas disponibles
        insert_fields = "spanish_word, quechua_word, audio_path"
        insert_values = "?, ?, ?"
        insert_params = [spanish_word, quechua_word, filename]
        
        if has_user_id:
            insert_fields += ", user_id"
            insert_values += ", ?"
            insert_params.append(session.get('user_id'))
            
        if has_is_approved:
            insert_fields += ", is_approved"
            insert_values += ", ?"
            insert_params.append(1 if auto_approve else 0)
            
        if has_allow_download:
            insert_fields += ", allow_download"
            insert_values += ", ?"
            insert_params.append(allow_download)
        
        query = f"INSERT INTO translations ({insert_fields}) VALUES ({insert_values})"
        cursor.execute(query, insert_params)
        db.commit()
        
        status_message = "Traducción guardada y publicada correctamente" if auto_approve else "Traducción guardada correctamente. Está pendiente de aprobación."
        return jsonify({'success': True, 'message': status_message, 'auto_approved': auto_approve})
    except sqlite3.Error as e:
        app.logger.error(f"Error en save_translation: {str(e)}")
        return jsonify({'error': f'Error en la base de datos: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Error en save_translation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search_translations():
    """API para buscar traducciones"""
    try:
        query = request.args.get('q', '').strip().lower()
        
        if not query:
            return jsonify([])
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si las columnas existen
        has_allow_download = column_exists('translations', 'allow_download')
        has_is_approved = column_exists('translations', 'is_approved')
        has_user_id = column_exists('translations', 'user_id')
        
        sql_query = """
            SELECT t.id, t.spanish_word, t.quechua_word, t.audio_path, t.created_at
        """
        
        # Añadir columnas condicionales a la consulta
        if has_allow_download:
            sql_query += ", t.allow_download"
        else:
            sql_query += ", 0 as allow_download"
            
        if has_user_id:
            sql_query += ", u.username as translator_username"
            
        # Construir la parte FROM de la consulta
        sql_query += " FROM translations t"
        
        if has_user_id:
            sql_query += " LEFT JOIN users u ON t.user_id = u.id"
            
        # Construir la parte WHERE de la consulta
        sql_query += " WHERE (LOWER(t.spanish_word) LIKE ? OR LOWER(t.quechua_word) LIKE ?)"
        
        if has_is_approved:
            sql_query += " AND t.is_approved = 1"
            
        sql_query += " ORDER BY t.spanish_word"
        
        cursor.execute(sql_query, (f'%{query}%', f'%{query}%'))
        
        results = []
        for row in cursor.fetchall():
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': row['created_at'],
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys():
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Anónimo'
                
            results.append(translation)
        
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error en search_translations: {str(e)}")
        return jsonify({'error': str(e)}), 500

# --- Administración ---

@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    """Panel de administración"""
    return render_template('admin/dashboard.html')

@app.route('/admin/translations')
@login_required
@role_required('admin')
def admin_translations():
    """Administrar traducciones"""
    return render_template('admin/translations.html')

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    """Administrar usuarios"""
    return render_template('admin/users.html')

# --- Protección de audio ---

@app.route('/audio/<path:filename>')
def get_audio(filename):
    """Servir archivos de audio con protección"""
    try:
        # Verificar si el archivo existe
        audio_path = os.path.join(app.config['AUDIO_FOLDER'], filename)
        if not os.path.exists(audio_path):
            abort(404)
        
        # Verificar si existe la columna allow_download
        has_allow_download = column_exists('translations', 'allow_download')
        
        allow_download = False
        
        if has_allow_download:
            # Verificar si el audio permite descarga
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT allow_download FROM translations WHERE audio_path = ?', (filename,))
            result = cursor.fetchone()
            
            if result:
                allow_download = bool(result['allow_download'])
        
        # Servir el archivo con las cabeceras apropiadas
        response = send_from_directory(app.config['AUDIO_FOLDER'], filename)
        
        # Si no se permite la descarga o no existe la columna, agregar cabeceras para evitarlo
        if not allow_download:
            response.headers['Content-Disposition'] = 'inline'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            response.headers['X-Content-Type-Options'] = 'nosniff'
        
        return response
    except Exception as e:
        app.logger.error(f"Error en get_audio: {str(e)}")
        abort(500)

# --- Plantilla de error ---
@app.route('/error')
def error_page():
    """Página de error para pruebas"""
    return render_template('error.html', error='Esta es una página de error de ejemplo')

if __name__ == '__main__':
    app.run(debug=True)