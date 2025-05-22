from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash, session, abort, make_response
from functools import wraps
import os
import uuid
import datetime
import json
import re
from database import (
    init_db, get_db, get_user_by_username, get_user_by_email, create_user, verify_password, 
    verify_user, update_last_login, column_exists, check_active_subscription, create_subscription,
    activate_subscription, cancel_subscription, get_all_subscriptions, get_search_cache, 
    add_search_cache, add_usage_stat, get_subscription_stats, hash_password
)
import sqlite3
import logging

app = Flask(__name__)
app.jinja_env.globals.update(min=min, max=max)
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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicia sesión para acceder a esta página', 'warning')
            return redirect(url_for('login', next=request.url))
        
        if session.get('user_role') != 'admin':
            flash('No tienes permiso para acceder a esta página', 'danger')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicia sesión para acceder a esta página', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Los administradores siempre tienen acceso
        if session.get('user_role') == 'admin':
            return f(*args, **kwargs)
            
        # Verificar suscripción activa
        has_subscription, subscription = check_active_subscription(session.get('user_id'))
        
        if not has_subscription:
            flash('Necesitas una suscripción activa para acceder a esta función', 'warning')
            return redirect(url_for('subscription_plans'))
            
        return f(*args, **kwargs)
    return decorated_function

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


# Agregar estas rutas al app.py

@app.route('/profile')
@login_required
def user_profile():
    """Vista del perfil del usuario"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Obtener información del usuario
        cursor.execute('''
            SELECT u.*, r.name as role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        ''', (session.get('user_id'),))
        
        user_info = cursor.fetchone()
        
        if not user_info:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('index'))
        
        # Obtener suscripción activa
        has_subscription, subscription = check_active_subscription(session.get('user_id'))
        
        # Obtener historial de suscripciones
        cursor.execute('''
            SELECT us.*, sp.name as plan_name, sp.price
            FROM user_subscriptions us
            JOIN subscription_plans sp ON us.plan_id = sp.id
            WHERE us.user_id = ?
            ORDER BY us.created_at DESC
            LIMIT 5
        ''', (session.get('user_id'),))
        
        subscription_history = cursor.fetchall()
        
        # Obtener estadísticas de uso
        cursor.execute('''
            SELECT 
                COUNT(*) as total_searches,
                COUNT(CASE WHEN action_type = 'search' THEN 1 END) as searches,
                COUNT(CASE WHEN action_type = 'get_translation' THEN 1 END) as translations_viewed,
                COUNT(CASE WHEN action_type = 'access_translator' THEN 1 END) as translator_accesses
            FROM usage_stats
            WHERE user_id = ?
        ''', (session.get('user_id'),))
        
        usage_stats = cursor.fetchone()
        
        # Obtener búsquedas recientes
        cursor.execute('''
            SELECT details, created_at
            FROM usage_stats
            WHERE user_id = ? AND action_type = 'search' AND details IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 10
        ''', (session.get('user_id'),))
        
        recent_searches = cursor.fetchall()
        
        return render_template('user/profile.html',
                             user=user_info,
                             has_subscription=has_subscription,
                             subscription=subscription,
                             subscription_history=subscription_history,
                             usage_stats=usage_stats,
                             recent_searches=recent_searches)
        
    except Exception as e:
        app.logger.error(f"Error en user_profile: {str(e)}")
        flash('Error al cargar el perfil', 'danger')
        return redirect(url_for('index'))

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Actualizar información del perfil"""
    try:
        action = request.form.get('action')
        
        if action == 'update_info':
            return update_personal_info()
        elif action == 'change_password':
            return change_password()
        else:
            flash('Acción no válida', 'danger')
            return redirect(url_for('user_profile'))
            
    except Exception as e:
        app.logger.error(f"Error en update_profile: {str(e)}")
        flash('Error al actualizar el perfil', 'danger')
        return redirect(url_for('user_profile'))

def update_personal_info():
    """Actualizar información personal del usuario"""
    try:
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        
        if not full_name or not email:
            flash('Todos los campos son obligatorios', 'danger')
            return redirect(url_for('user_profile'))
        
        # Validar formato de email
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Formato de email inválido', 'danger')
            return redirect(url_for('user_profile'))
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si el email ya está en uso por otro usuario
        cursor.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                      (email, session.get('user_id')))
        if cursor.fetchone():
            flash('Este email ya está en uso por otro usuario', 'danger')
            return redirect(url_for('user_profile'))
        
        # Actualizar información
        cursor.execute('''
            UPDATE users 
            SET full_name = ?, email = ?
            WHERE id = ?
        ''', (full_name, email, session.get('user_id')))
        
        db.commit()
        
        flash('Información personal actualizada correctamente', 'success')
        return redirect(url_for('user_profile'))
        
    except Exception as e:
        app.logger.error(f"Error en update_personal_info: {str(e)}")
        flash('Error al actualizar la información', 'danger')
        return redirect(url_for('user_profile'))

def change_password():
    """Cambiar contraseña del usuario"""
    try:
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            flash('Todos los campos de contraseña son obligatorios', 'danger')
            return redirect(url_for('user_profile'))
        
        if new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden', 'danger')
            return redirect(url_for('user_profile'))
        
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres', 'danger')
            return redirect(url_for('user_profile'))
        
        db = get_db()
        cursor = db.cursor()
        
        # Obtener contraseña actual del usuario
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', 
                      (session.get('user_id'),))
        user = cursor.fetchone()
        
        if not user:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('user_profile'))
        
        # Verificar contraseña actual
        if not verify_password(user['password_hash'], current_password):
            flash('La contraseña actual es incorrecta', 'danger')
            return redirect(url_for('user_profile'))
        
        # Actualizar contraseña
        new_password_hash = hash_password(new_password)
        cursor.execute('''
            UPDATE users 
            SET password_hash = ?
            WHERE id = ?
        ''', (new_password_hash, session.get('user_id')))
        
        db.commit()
        
        flash('Contraseña actualizada correctamente', 'success')
        return redirect(url_for('user_profile'))
        
    except Exception as e:
        app.logger.error(f"Error en change_password: {str(e)}")
        flash('Error al cambiar la contraseña', 'danger')
        return redirect(url_for('user_profile'))

@app.route('/profile/download-data')
@login_required
def download_user_data():
    """Descargar datos del usuario (GDPR compliance)"""
    try:
        import json
        from datetime import datetime
        
        db = get_db()
        cursor = db.cursor()
        
        # Obtener todos los datos del usuario
        cursor.execute('''
            SELECT u.username, u.email, u.full_name, u.created_at, u.last_login
            FROM users u
            WHERE u.id = ?
        ''', (session.get('user_id'),))
        
        user_data = cursor.fetchone()
        
        # Obtener suscripciones
        cursor.execute('''
            SELECT us.*, sp.name as plan_name
            FROM user_subscriptions us
            JOIN subscription_plans sp ON us.plan_id = sp.id
            WHERE us.user_id = ?
        ''', (session.get('user_id'),))
        
        subscriptions = cursor.fetchall()
        
        # Obtener estadísticas de uso
        cursor.execute('''
            SELECT action_type, details, created_at
            FROM usage_stats
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session.get('user_id'),))
        
        usage_history = cursor.fetchall()
        
        # Crear archivo JSON con todos los datos
        export_data = {
            'user_info': dict(user_data) if user_data else {},
            'subscriptions': [dict(sub) for sub in subscriptions],
            'usage_history': [dict(usage) for usage in usage_history],
            'export_date': datetime.now().isoformat(),
            'export_type': 'complete_user_data'
        }
        
        # Convertir fechas a string para JSON
        def convert_dates(obj):
            if isinstance(obj, dict):
                return {k: convert_dates(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_dates(item) for item in obj]
            elif hasattr(obj, 'strftime'):
                return obj.strftime('%Y-%m-%d %H:%M:%S')
            else:
                return obj
        
        export_data = convert_dates(export_data)
        
        # Crear respuesta JSON para descarga
        response = make_response(json.dumps(export_data, indent=2, ensure_ascii=False))
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename=mis_datos_quechua_wanka_{datetime.now().strftime("%Y%m%d")}.json'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error en download_user_data: {str(e)}")
        flash('Error al generar la descarga de datos', 'danger')
        return redirect(url_for('user_profile'))

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
            return redirect(url_for('subscription_plans'))
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

# --- Rutas de suscripción ---

@app.route('/subscription/plans')
def subscription_plans():
    """Muestra los planes de suscripción disponibles"""
    db = get_db()
    cursor = db.cursor()
    
    # Obtener planes activos
    cursor.execute('''
        SELECT * FROM subscription_plans
        WHERE is_active = 1
    ''')
    
    plans = cursor.fetchall()
    
    # Verificar si el usuario está logueado y tiene suscripción
    has_subscription = False
    subscription = None
    
    if 'user_id' in session:
        has_subscription, subscription = check_active_subscription(session.get('user_id'))
    
    return render_template('subscription/plans.html', 
                          plans=plans, 
                          has_subscription=has_subscription, 
                          subscription=subscription)

# --- APIs COMPLETAS DE ADMINISTRACIÓN ---

@app.route('/api/admin/translation/<int:translation_id>', methods=['PUT'])
@admin_required
def update_translation(translation_id):
    """API para actualizar una traducción existente"""
    try:
        data = request.get_json()
        spanish_word = data.get('spanish_word', '').strip()
        quechua_word = data.get('quechua_word', '').strip()
        allow_download = data.get('allow_download', False)
        
        if not spanish_word or not quechua_word:
            return jsonify({'error': 'Todos los campos son obligatorios'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar que la traducción existe
        cursor.execute('SELECT id FROM translations WHERE id = ?', (translation_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Traducción no encontrada'}), 404
        
        # Verificar si hay otra traducción con la misma palabra en español (excluyendo la actual)
        cursor.execute(
            'SELECT id FROM translations WHERE LOWER(spanish_word) = LOWER(?) AND id != ?', 
            (spanish_word, translation_id)
        )
        if cursor.fetchone():
            return jsonify({'error': 'Ya existe otra traducción para esta palabra en español'}), 400
        
        # Actualizar la traducción
        cursor.execute('''
            UPDATE translations 
            SET spanish_word = ?, quechua_word = ?, allow_download = ?
            WHERE id = ?
        ''', (spanish_word, quechua_word, allow_download, translation_id))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Traducción actualizada correctamente'
        })
        
    except Exception as e:
        app.logger.error(f"Error al actualizar traducción: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/translation/<int:translation_id>', methods=['DELETE'])
@admin_required
def delete_translation(translation_id):
    """API para eliminar una traducción"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Obtener información de la traducción antes de eliminarla
        cursor.execute('SELECT audio_path FROM translations WHERE id = ?', (translation_id,))
        translation = cursor.fetchone()
        
        if not translation:
            return jsonify({'error': 'Traducción no encontrada'}), 404
        
        audio_path = translation['audio_path']
        
        # Eliminar la traducción de la base de datos
        cursor.execute('DELETE FROM translations WHERE id = ?', (translation_id,))
        db.commit()
        
        # Intentar eliminar el archivo de audio
        if audio_path:
            try:
                full_audio_path = os.path.join(app.config['AUDIO_FOLDER'], audio_path)
                if os.path.exists(full_audio_path):
                    os.remove(full_audio_path)
            except Exception as e:
                app.logger.warning(f"No se pudo eliminar el archivo de audio {audio_path}: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Traducción eliminada correctamente'
        })
        
    except Exception as e:
        app.logger.error(f"Error al eliminar traducción: {str(e)}")
        return jsonify({'error': str(e)}), 500

# --- SISTEMA DE PAGOS CON YAPE ---

@app.route('/subscription/checkout/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def subscription_checkout(plan_id):
    """Proceso de pago para una suscripción con Yape"""
    db = get_db()
    cursor = db.cursor()
    
    # Obtener el plan seleccionado
    cursor.execute('SELECT * FROM subscription_plans WHERE id = ? AND is_active = 1', (plan_id,))
    plan = cursor.fetchone()
    
    if not plan:
        flash('El plan seleccionado no existe o no está disponible', 'danger')
        return redirect(url_for('subscription_plans'))
    
    # Verificar si el usuario ya tiene una suscripción activa
    has_subscription, subscription = check_active_subscription(session.get('user_id'))
    
    if has_subscription:
        flash('Ya tienes una suscripción activa', 'warning')
        return redirect(url_for('user_view'))
    
    if request.method == 'POST':
        # Verificar si se subió un voucher
        if 'voucher' not in request.files:
            flash('Debes subir el voucher de pago', 'danger')
            return render_template('subscription/checkout_yape.html', plan=plan)
        
        voucher_file = request.files['voucher']
        
        if voucher_file.filename == '':
            flash('Debes seleccionar un archivo de voucher', 'danger')
            return render_template('subscription/checkout_yape.html', plan=plan)
        
        # Validar tipo de archivo (imágenes)
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
        file_extension = voucher_file.filename.rsplit('.', 1)[1].lower() if '.' in voucher_file.filename else ''
        
        if file_extension not in allowed_extensions:
            flash('Solo se permiten archivos de imagen (PNG, JPG, JPEG, GIF) o PDF', 'danger')
            return render_template('subscription/checkout_yape.html', plan=plan)
        
        # Guardar el voucher
        voucher_filename = f"voucher_{session.get('user_id')}_{uuid.uuid4().hex[:8]}.{file_extension}"
        voucher_folder = os.path.join(app.config.get('UPLOAD_FOLDER', 'static/vouchers'))
        os.makedirs(voucher_folder, exist_ok=True)
        voucher_path = os.path.join(voucher_folder, voucher_filename)
        voucher_file.save(voucher_path)
        
        # Crear la suscripción en estado "pendiente_pago"
        success, result = create_subscription_with_voucher(
            session.get('user_id'),
            plan_id,
            voucher_filename
        )
        
        if success:
            flash('Tu voucher ha sido recibido. Tu suscripción será activada una vez que el administrador valide el pago.', 'info')
            return redirect(url_for('subscription_plans'))
        else:
            flash(f'Error al procesar la suscripción: {result}', 'danger')
    
    return render_template('subscription/checkout_yape.html', plan=plan)

@app.route('/admin/vouchers')
@admin_required
def admin_vouchers():
    """Panel para revisar vouchers de pago"""
    db = get_db()
    cursor = db.cursor()
    
    # Obtener suscripciones pendientes con voucher
    cursor.execute('''
        SELECT us.*, u.username, u.email, sp.name as plan_name, us.voucher_path,
               u.full_name, sp.price
        FROM user_subscriptions us
        JOIN users u ON us.user_id = u.id
        JOIN subscription_plans sp ON us.plan_id = sp.id
        WHERE us.status = 'pendiente_pago' AND us.voucher_path IS NOT NULL
        ORDER BY us.start_date DESC
    ''')
    
    pending_vouchers = cursor.fetchall()
    
    return render_template('admin/vouchers.html', vouchers=pending_vouchers)

@app.route('/api/admin/voucher/validate', methods=['POST'])
@admin_required
def validate_voucher():
    """API para validar un voucher y activar suscripción"""
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id')
        action = data.get('action')  # 'approve' o 'reject'
        
        if not subscription_id or action not in ['approve', 'reject']:
            return jsonify({'error': 'Datos inválidos'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        if action == 'approve':
            # Activar la suscripción
            cursor.execute('''
                UPDATE user_subscriptions 
                SET status = 'active', last_updated = CURRENT_TIMESTAMP
                WHERE id = ? AND status = 'pendiente_pago'
            ''', (subscription_id,))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Suscripción no encontrada o ya procesada'}), 400
            
            message = 'Voucher aprobado y suscripción activada'
            
        else:  # reject
            # Rechazar la suscripción
            cursor.execute('''
                UPDATE user_subscriptions 
                SET status = 'rejected', last_updated = CURRENT_TIMESTAMP
                WHERE id = ? AND status = 'pendiente_pago'
            ''', (subscription_id,))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Suscripción no encontrada o ya procesada'}), 400
            
            message = 'Voucher rechazado'
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': message
        })
        
    except Exception as e:
        app.logger.error(f"Error al validar voucher: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/voucher/<path:filename>')
@admin_required
def get_voucher(filename):
    """Servir vouchers para administradores"""
    voucher_folder = app.config.get('UPLOAD_FOLDER', 'static/vouchers')
    return send_from_directory(voucher_folder, filename)

# --- APIS DE ADMINISTRACIÓN ADICIONALES ---

@app.route('/api/admin/statistics')
@admin_required
def get_admin_statistics():
    """API para obtener estadísticas completas del sistema"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        stats = {}
        
        # Estadísticas de traducciones
        cursor.execute('SELECT COUNT(*) as total FROM translations')
        stats['translations_total'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM translations WHERE audio_path IS NOT NULL')
        stats['translations_with_audio'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM translations WHERE allow_download = 1')
        stats['translations_downloadable'] = cursor.fetchone()['total']
        
        # Estadísticas de usuarios
        cursor.execute('SELECT COUNT(*) as total FROM users')
        stats['users_total'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE is_active = 1 AND is_verified = 1')
        stats['users_active'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM users WHERE is_verified = 0')
        stats['users_unverified'] = cursor.fetchone()['total']
        
        # Estadísticas de suscripciones
        cursor.execute('SELECT COUNT(*) as total FROM user_subscriptions')
        stats['subscriptions_total'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM user_subscriptions WHERE status = "active"')
        stats['subscriptions_active'] = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM user_subscriptions WHERE status = "pendiente_pago"')
        stats['subscriptions_pending_payment'] = cursor.fetchone()['total']
        
        # Búsquedas más populares (últimos 7 días)
        cursor.execute('''
            SELECT query, hit_count 
            FROM search_cache 
            WHERE created_at > datetime('now', '-7 days')
            ORDER BY hit_count DESC 
            LIMIT 10
        ''')
        stats['popular_searches'] = cursor.fetchall()
        
        # Traducciones recientes (últimas 10)
        cursor.execute('''
            SELECT t.spanish_word, t.quechua_word, t.created_at, u.username
            FROM translations t
            LEFT JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
            LIMIT 10
        ''')
        stats['recent_translations'] = cursor.fetchall()
        
        return jsonify(stats)
        
    except Exception as e:
        app.logger.error(f"Error al obtener estadísticas: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/system/backup', methods=['POST'])
@admin_required
def create_system_backup():
    """API para crear backup del sistema"""
    try:
        import shutil
        import zipfile
        from datetime import datetime
        
        # Crear directorio de backup si no existe
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        # Nombre del archivo de backup
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'backup_{timestamp}.zip'
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Crear archivo ZIP
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
            # Agregar base de datos
            db_path = app.config['DATABASE']
            if os.path.exists(db_path):
                backup_zip.write(db_path, 'database.db')
            
            # Agregar archivos de audio
            audio_folder = app.config['AUDIO_FOLDER']
            if os.path.exists(audio_folder):
                for root, dirs, files in os.walk(audio_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, os.path.dirname(audio_folder))
                        backup_zip.write(file_path, arc_path)
            
            # Agregar vouchers si existen
            voucher_folder = app.config.get('UPLOAD_FOLDER', 'static/vouchers')
            if os.path.exists(voucher_folder):
                for root, dirs, files in os.walk(voucher_folder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, os.path.dirname(voucher_folder))
                        backup_zip.write(file_path, arc_path)
        
        return jsonify({
            'success': True,
            'message': f'Backup creado exitosamente: {backup_filename}',
            'filename': backup_filename,
            'size': os.path.getsize(backup_path)
        })
        
    except Exception as e:
        app.logger.error(f"Error al crear backup: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/user/<int:user_id>/subscriptions')
@admin_required
def get_user_subscriptions(user_id):
    """API para obtener historial de suscripciones de un usuario"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT us.*, sp.name as plan_name, sp.price
            FROM user_subscriptions us
            JOIN subscription_plans sp ON us.plan_id = sp.id
            WHERE us.user_id = ?
            ORDER BY us.created_at DESC
        ''', (user_id,))
        
        subscriptions = cursor.fetchall()
        
        return jsonify([dict(row) for row in subscriptions])
        
    except Exception as e:
        app.logger.error(f"Error al obtener suscripciones del usuario: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Agregar esta función helper a database.py
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
        
        # Verificar si ya existe una suscripción activa
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

@app.route('/subscription/manage')
@login_required
def manage_subscription():
    """Página para gestionar la suscripción del usuario"""
    has_subscription, subscription = check_active_subscription(session.get('user_id'))
    
    if not has_subscription:
        flash('No tienes una suscripción activa', 'warning')
        return redirect(url_for('subscription_plans'))
    
    return render_template('subscription/manage.html', subscription=subscription)

@app.route('/api/subscription/cancel', methods=['POST'])
@login_required
def cancel_user_subscription():
    """Cancela la suscripción del usuario"""
    has_subscription, subscription = check_active_subscription(session.get('user_id'))
    
    if not has_subscription:
        return jsonify({'error': 'No tienes una suscripción activa'}), 400
    
    success, message = cancel_subscription(subscription['id'])
    
    if success:
        return jsonify({'success': True, 'message': 'Suscripción cancelada correctamente'})
    else:
        return jsonify({'error': message}), 500

# --- Rutas principales ---

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/translator')
@admin_required
def translator_view():
    """Vista del traductor para agregar traducciones (solo admin)"""
    return render_template('translator.html')

@app.route('/user')
@subscription_required
def user_view():
    """Vista del usuario para buscar traducciones (acceso con suscripción)"""
    # Registrar estadística de uso
    if 'user_id' in session:
        add_usage_stat(session.get('user_id'), 'access_translator')
        
    return render_template('user.html')

# --- Rutas de API ---

@app.route('/api/translations')
def get_translations():
    """API para obtener todas las traducciones"""
    try:
        # Usar caché para usuarios anónimos o con alta carga
        cache_key = "all_translations"
        cached_results = get_search_cache(cache_key)
        
        if cached_results and 'user_id' not in session:
            return jsonify(json.loads(cached_results))
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si la columna allow_download existe
        has_allow_download = column_exists('translations', 'allow_download')
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
            
        query += " ORDER BY t.spanish_word"
        
        cursor.execute(query)
        
        translations = []
        for row in cursor.fetchall():
            # Convertir datetime a string para JSON
            created_at_str = None
            if row['created_at']:
                if isinstance(row['created_at'], str):
                    created_at_str = row['created_at']
                else:
                    created_at_str = row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': created_at_str,
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys() and row['translator_username']:
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Administrador'
                
            translations.append(translation)
        
        # Guardar en caché
        add_search_cache(cache_key, json.dumps(translations))
        
        return jsonify(translations)
    except Exception as e:
        app.logger.error(f"Error en get_translations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/translation/<string:word>')
@subscription_required
def get_translation(word):
    """API para obtener la traducción de una palabra específica"""
    try:
        # Registrar estadística de uso
        if 'user_id' in session:
            add_usage_stat(session.get('user_id'), 'get_translation', word)
            
        # Verificar caché
        cache_key = f"translation_{word.lower()}"
        cached_results = get_search_cache(cache_key)
        
        if cached_results:
            return jsonify(json.loads(cached_results))
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si las columnas existen
        has_allow_download = column_exists('translations', 'allow_download')
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
        
        cursor.execute(query, (word,))
        
        row = cursor.fetchone()
        if row:
            # Convertir datetime a string para JSON
            created_at_str = None
            if row['created_at']:
                if isinstance(row['created_at'], str):
                    created_at_str = row['created_at']
                else:
                    created_at_str = row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': created_at_str,
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys() and row['translator_username']:
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Administrador'
                
            # Guardar en caché
            add_search_cache(cache_key, json.dumps(translation))
                
            return jsonify(translation)
        
        return jsonify({'error': 'Traducción no encontrada'}), 404
    except Exception as e:
        app.logger.error(f"Error en get_translation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-translation', methods=['POST'])
@admin_required
def save_translation():
    """API para guardar una nueva traducción (solo admin)"""
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
        has_user_id = column_exists('translations', 'user_id')
        
        # Construir la consulta según las columnas disponibles
        insert_fields = "spanish_word, quechua_word, audio_path"
        insert_values = "?, ?, ?"
        insert_params = [spanish_word, quechua_word, filename]
        
        if has_user_id:
            insert_fields += ", user_id"
            insert_values += ", ?"
            insert_params.append(session.get('user_id'))
            
        if has_allow_download:
            insert_fields += ", allow_download"
            insert_values += ", ?"
            insert_params.append(allow_download)
        
        query = f"INSERT INTO translations ({insert_fields}) VALUES ({insert_values})"
        cursor.execute(query, insert_params)
        db.commit()
        
        # Invalidar caché relacionada
        return jsonify({'success': True, 'message': "Traducción guardada y publicada correctamente"})
    except sqlite3.Error as e:
        app.logger.error(f"Error en save_translation: {str(e)}")
        return jsonify({'error': f'Error en la base de datos: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Error en save_translation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/search', methods=['GET'])
@subscription_required
def search_translations():
    """API para buscar traducciones (requiere suscripción)"""
    try:
        query = request.args.get('q', '').strip().lower()
        
        if not query:
            return jsonify([])
        
        # Registrar estadística de uso
        if 'user_id' in session:
            add_usage_stat(session.get('user_id'), 'search', query)
            
        # Verificar caché
        cache_key = f"search_{query}"
        cached_results = get_search_cache(cache_key)
        
        if cached_results:
            return jsonify(json.loads(cached_results))
        
        db = get_db()
        cursor = db.cursor()
        
        # Verificar si las columnas existen
        has_allow_download = column_exists('translations', 'allow_download')
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
            
        sql_query += " ORDER BY t.spanish_word"
        
        cursor.execute(sql_query, (f'%{query}%', f'%{query}%'))
        
        results = []
        for row in cursor.fetchall():
            # Convertir datetime a string para JSON
            created_at_str = None
            if row['created_at']:
                if isinstance(row['created_at'], str):
                    created_at_str = row['created_at']
                else:
                    created_at_str = row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            translation = {
                'id': row['id'],
                'spanish_word': row['spanish_word'],
                'quechua_word': row['quechua_word'],
                'audio_path': row['audio_path'],
                'created_at': created_at_str,
                'allow_download': bool(row['allow_download'])
            }
            
            # Añadir traductor si existe
            if has_user_id and 'translator_username' in row.keys() and row['translator_username']:
                translation['translator'] = row['translator_username']
            else:
                translation['translator'] = 'Administrador'
                
            results.append(translation)
        
        # Guardar en caché
        add_search_cache(cache_key, json.dumps(results))
        
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error en search_translations: {str(e)}")
        return jsonify({'error': str(e)}), 500

# --- Administración ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Panel de administración"""
    # Obtener estadísticas de suscripciones
    subscription_stats = get_subscription_stats()
    
    # Obtener últimas suscripciones (máximo 5)
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            SELECT us.*, u.username, u.email, sp.name as plan_name, u.id as user_id
            FROM user_subscriptions us
            JOIN users u ON us.user_id = u.id
            JOIN subscription_plans sp ON us.plan_id = sp.id
            ORDER BY us.last_updated DESC
            LIMIT 5
        """)
        recent_subscriptions = cursor.fetchall()
    except sqlite3.Error as e:
        app.logger.error(f"Error al obtener suscripciones recientes: {str(e)}")
        recent_subscriptions = []
    
    # Obtener búsquedas populares
    try:
        cursor.execute("""
            SELECT query, hit_count, created_at
            FROM search_cache
            ORDER BY hit_count DESC
            LIMIT 10
        """)
        popular_searches = cursor.fetchall()
    except sqlite3.Error as e:
        app.logger.error(f"Error al obtener búsquedas populares: {str(e)}")
        popular_searches = []
    
    return render_template('admin/dashboard.html', 
                          subscription_stats=subscription_stats,
                          recent_subscriptions=recent_subscriptions,
                          popular_searches=popular_searches)

@app.route('/admin/translations')
@admin_required
def admin_translations():
    """Administrar traducciones"""
    return render_template('admin/translations.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    """Administrar usuarios"""
    db = get_db()
    cursor = db.cursor()
    
    # Obtener parámetros de filtrado y paginación
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Construir consulta con filtros apropiados
    query = """
        SELECT u.*, r.name as role_name
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE 1=1
    """
    query_params = []
    
    # Aplicar filtro de rol
    if role_filter != 'all':
        query += " AND r.name = ?"
        query_params.append(role_filter)
    
    # Aplicar filtro de estado
    if status_filter == 'active':
        query += " AND u.is_active = 1 AND u.is_verified = 1"
    elif status_filter == 'inactive':
        query += " AND u.is_active = 0 AND u.is_verified = 1"
    elif status_filter == 'unverified':
        query += " AND u.is_verified = 0"
    
    # Consulta para contar total de filas
    count_query = query.replace("u.*, r.name as role_name", "COUNT(*) as total")
    
    # Ejecutar consulta de conteo
    cursor.execute(count_query, query_params)
    total_users = cursor.fetchone()['total']
    
    # Añadir paginación a la consulta principal
    query += " ORDER BY u.id DESC LIMIT ? OFFSET ?"
    query_params.extend([per_page, (page - 1) * per_page])
    
    # Ejecutar consulta principal
    cursor.execute(query, query_params)
    users = cursor.fetchall()
    
    return render_template('admin/users.html', 
                          users=users,
                          total_users=total_users,
                          page=page,
                          per_page=per_page,
                          role_filter=role_filter,
                          status_filter=status_filter)

@app.route('/admin/subscriptions')
@admin_required
def admin_subscriptions():
    """Administrar suscripciones"""
    status_filter = request.args.get('status', None)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    subscriptions, total, per_page = get_all_subscriptions(status_filter, page, per_page)
    
    return render_template('admin/subscriptions.html', 
                          subscriptions=subscriptions,
                          total=total,
                          page=page,
                          per_page=per_page,
                          status_filter=status_filter)

@app.route('/api/admin/subscription/activate', methods=['POST'])
@admin_required
def admin_activate_subscription():
    """API para activar una suscripción desde el panel admin"""
    subscription_id = request.json.get('subscription_id')
    
    if not subscription_id:
        return jsonify({'error': 'ID de suscripción no proporcionado'}), 400
    
    success, message = activate_subscription(subscription_id)
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500

@app.route('/api/admin/subscription/cancel', methods=['POST'])
@admin_required
def admin_cancel_subscription():
    """API para cancelar una suscripción desde el panel admin"""
    subscription_id = request.json.get('subscription_id')
    
    if not subscription_id:
        return jsonify({'error': 'ID de suscripción no proporcionado'}), 400
    
    success, message = cancel_subscription(subscription_id)
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500

# --- Protección de audio ---

@app.route('/audio/<path:filename>')
@subscription_required
def get_audio(filename):
    """Servir archivos de audio con protección"""
    try:
        # Verificar si el archivo existe
        audio_path = os.path.join(app.config['AUDIO_FOLDER'], filename)
        if not os.path.exists(audio_path):
            # Si el archivo no existe, devolver un archivo de audio vacío o alternativo
            default_audio = os.path.join(app.config['AUDIO_FOLDER'], 'default.webm')
            
            # Si tampoco existe el archivo por defecto, crear uno
            if not os.path.exists(default_audio):
                # Crear carpeta si no existe
                os.makedirs(os.path.dirname(default_audio), exist_ok=True)
                # Crear archivo vacío
                with open(default_audio, 'wb') as f:
                    f.write(b'')  # Archivo vacío
            
            response = send_from_directory(os.path.dirname(default_audio), os.path.basename(default_audio))
            app.logger.warning(f"Audio no encontrado: {filename}, sirviendo archivo por defecto")
        else:
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
        # En lugar de send_file, usamos abort para devolver un 404 
        return abort(404)
    
@app.route('/api/admin/change-user-role', methods=['POST'])
@admin_required
def api_change_user_role():
    """API para cambiar el rol de un usuario"""
    data = request.json
    user_id = data.get('user_id')
    role = data.get('role')
    
    if not user_id or not role:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Obtener el ID del rol
        cursor.execute('SELECT id FROM roles WHERE name = ?', (role,))
        role_data = cursor.fetchone()
        
        if not role_data:
            return jsonify({'error': 'Rol no encontrado'}), 404
        
        role_id = role_data['id']
        
        # Actualizar rol del usuario
        cursor.execute('UPDATE users SET role_id = ? WHERE id = ?', (role_id, user_id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Rol actualizado correctamente'})
    except sqlite3.Error as e:
        app.logger.error(f"Error al cambiar rol: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/verify-user', methods=['POST'])
@admin_required
def api_verify_user():
    """API para verificar un usuario"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'ID de usuario no proporcionado'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user_id,))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Usuario verificado correctamente'})
    except sqlite3.Error as e:
        app.logger.error(f"Error al verificar usuario: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/change-user-status', methods=['POST'])
@admin_required
def api_change_user_status():
    """API para activar o desactivar un usuario"""
    data = request.json
    user_id = data.get('user_id')
    action = data.get('action')
    
    if not user_id or not action:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    if action not in ['activate', 'deactivate']:
        return jsonify({'error': 'Acción no válida'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        is_active = 1 if action == 'activate' else 0
        cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (is_active, user_id))
        db.commit()
        
        message = f"Usuario {'activado' if is_active else 'desactivado'} correctamente"
        return jsonify({'success': True, 'message': message})
    except sqlite3.Error as e:
        app.logger.error(f"Error al cambiar estado: {str(e)}")
        return jsonify({'error': str(e)}), 500

# --- Plantilla de error ---
@app.route('/error')
def error_page():
    """Página de error para pruebas"""
    return render_template('error.html', error='Esta es una página de error de ejemplo')

if __name__ == '__main__':
    app.run(debug=True)