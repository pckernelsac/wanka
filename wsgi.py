# Archivo de configuración para Gunicorn
# El servidor web que ejecutará nuestra aplicación en producción

from app import app

# Punto de entrada para el servidor web
application = app

if __name__ == "__main__":
    application.run()