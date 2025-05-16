import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env si existe
load_dotenv()

# Configuración general
SECRET_KEY = os.environ.get('SECRET_KEY') or 'clave-super-secreta-quechua-chanka'
DEBUG = os.environ.get('FLASK_ENV') == 'development'

# Determinar si estamos en Azure
IN_AZURE = os.environ.get('WEBSITE_HOSTNAME') is not None

# Configuración de la base de datos
if IN_AZURE:
    # Ruta de base de datos en Azure (persistente)
    DATABASE = os.path.join(os.environ.get('HOME', ''), 'site', 'wwwroot', 'quechua_translator.db')
else:
    # Ruta local
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'quechua_translator.db')

# Configuración de archivos
if IN_AZURE:
    # En Azure, usar una carpeta persistente
    AUDIO_FOLDER = os.path.join(os.environ.get('HOME', ''), 'site', 'wwwroot', 'static', 'audio')
else:
    # Localmente
    AUDIO_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'audio')

# Asegurar que existe la carpeta de audio
os.makedirs(AUDIO_FOLDER, exist_ok=True)

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
if IN_AZURE:
    # En Azure, usar el nombre del host
    BASE_URL = f"https://{os.environ.get('WEBSITE_HOSTNAME')}"
else:
    # Localmente
    BASE_URL = os.environ.get('BASE_URL') or 'http://localhost:5000'