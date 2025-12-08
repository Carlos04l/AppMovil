import os
import pyodbc


config = {
    'SQL_SERVER': {
        'DRIVER': '{ODBC Driver 17 for SQL Server}',
        'SERVER': r'JUANLOZANO\SQLEXPRESS01',
        'DATABASE': 'QASMexico',
        'USERNAME': 'sa',
        'PASSWORD': '120504'
    },
    'SECRET_KEY': os.urandom(24),
    'RECAPTCHA_PUBLIC_KEY': 'TU_CLAVE_PUBLICA',
    'RECAPTCHA_PRIVATE_KEY': 'TU_CLAVE_PRIVADA',
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USE_TLS': True,
    'MAIL_USERNAME': 'tu_correo@gmail.com',
    'MAIL_PASSWORD': 'tu_contraseña_de_app'
}


def get_connection():
    """
    Crea y devuelve una conexión a SQL Server usando los datos del diccionario config.
    """
    try:
        db = config['SQL_SERVER']
        connection = pyodbc.connect(
            f"DRIVER={db['DRIVER']};"
            f"SERVER={db['SERVER']};"
            f"DATABASE={db['DATABASE']};"
            f"UID={db['USERNAME']};"
            f"PWD={db['PASSWORD']}"
        )
        print("Conexión exitosa a SQL Server")
        return connection

    except Exception as e:
        print("Error de conexión a la base de datos:", e)
        return None