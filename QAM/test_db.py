from config import get_connection

try:
    conn = get_connection()
    print("✅ Conexión exitosa a SQL Server")
    conn.close()
except Exception as e:
    print("❌ Error al conectar:", e)
