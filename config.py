import os
import secrets

# Configuración general
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
DEBUG = True

# Configuración de la base de datos
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'quechua_translator.db')

# Configuración de archivos
AUDIO_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'audio')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max tamaño de archivo

# Configuración de sesiones
SESSION_TYPE = 'filesystem'
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 86400  # 24 horas

# Configuración de correo (para verificación)
MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
MAIL_USE_TLS = True
MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'tu_correo@gmail.com'
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'tu_contraseña'
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@quechuachanka.org'

# URL base del sitio
BASE_URL = os.environ.get('BASE_URL') or 'http://localhost:5000'