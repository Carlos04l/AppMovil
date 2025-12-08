# app.py
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file
)
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import io, csv, os

# DB connection helper - asegúrate que config.get_connection() esté bien
from config import get_connection

# Requests para consumir la API local/externa
import requests

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'clave_super_segura_2025')

# ----------------- Limpieza de datos contra inyección -----------------
def sanitize_input(text):
    """Limpia entrada para evitar XSS e inyección de código.
    Esta función es una capa adicional; las consultas deben ser siempre parametrizadas.
    """
    if text is None:
        return None
    # forzar string
    text = str(text)

    # eliminar etiquetas HTML
    text = re.sub(r'<.*?>', '', text)

    # eliminar palabra 'script' por precaución
    text = re.sub(r'(?i)script', '', text)

    # eliminar on* atributos (onmouseover, onerror, etc.)
    text = re.sub(r'(?i)on\w+\s*=\s*["\'].*?["\']', '', text)

    # quitar o neutralizar caracteres problemáticos comunes en inyecciones SQL/JS
    # NOTA: no sustituir comillas si usas consultas parametrizadas; aquí lo hacemos por seguridad visual
    blacklist = [";", "--", "`", "/*", "*/"]
    for p in blacklist:
        text = text.replace(p, "")

    # recortar y devolver
    return text.strip()

# ---------------- Configuración de sesión ----------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Cambiar a True en producción con HTTPS
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5),
    WTF_CSRF_ENABLED=True
)

# ---------------- Configuración de reCAPTCHA ----------------
# Sustituye por tus claves válidas si las tienes en producción
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY', '6LdlLAwsAAAAABBmzDBEd5q6xYH0gO4j8_lho2Bu')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY', '6LdlLAwsAAAAAMNcTkWU-7EOy7A1QWGhzvqhWNfp')

# ---------------- Formularios ----------------
class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=25)])
    email = EmailField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    role = SelectField('Rol', choices=[('Jefe', 'Jefe'), ('Inspector', 'Inspector')])
    submit = SubmitField('Registrar')

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Ingresar')


# ---------------- Utilidades ----------------
def validar_password(password):
    """Valida la fortaleza de la contraseña"""
    if password is None:
        return "Contraseña inválida."
    if len(password) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r'[A-Z]', password):
        return "Debe contener al menos una letra mayúscula."
    if not re.search(r'[a-z]', password):
        return "Debe contener al menos una letra minúscula."
    if not re.search(r'[0-9]', password):
        return "Debe contener al menos un número."
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Debe contener al menos un carácter especial."
    return None

def usuario_existe(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM Usuarios WHERE username = ?", (username,))
    r = cur.fetchone()
    conn.close()
    return r is not None

def registrar_usuario(username, email, password, role):
    conn = get_connection()
    cur = conn.cursor()
    hashed = generate_password_hash(password)
    cur.execute("INSERT INTO Usuarios (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, hashed, role))
    conn.commit()
    conn.close()

def validar_login(username, password):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password, role FROM Usuarios WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.close()
    if result and check_password_hash(result[0], password):
        return result[1]
    return None

# ---------- Manejo de inactividad (antes de cada request) ----------
@app.before_request
def verificar_inactividad():
    if 'user' in session:
        ahora = datetime.now()
        ultima = session.get('last_activity')

        if ultima is None:
            session['last_activity'] = ahora.isoformat()
            return

        # tratar si viene string ISO
        if isinstance(ultima, str):
            try:
                ultima_dt = datetime.fromisoformat(ultima.replace("Z",""))
            except Exception:
                ultima_dt = ahora
        else:
            ultima_dt = ultima

        # quitar tz si existe
        if hasattr(ultima_dt, "tzinfo") and ultima_dt.tzinfo is not None:
            ultima_dt = ultima_dt.replace(tzinfo=None)

        diferencia = (ahora - ultima_dt).total_seconds()
        if diferencia > app.permanent_session_lifetime.total_seconds():
            session.clear()
            flash('Sesión cerrada por inactividad.', 'error')
            return redirect(url_for('login'))

        session['last_activity'] = ahora.isoformat()

# ---------------- Rutas básicas ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/registrarse', methods=['GET', 'POST'])
def registrarse():
    form = RegisterForm()
    if form.validate_on_submit():
        # sanitizar valores provenientes de WTForms/usuario
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data  # contraseña no sanear porque se valida y se hashea
        role = sanitize_input(form.role.data)

        if usuario_existe(username):
            flash('El usuario ya existe.', 'error')
        else:
            error = validar_password(password)
            if error:
                flash(error, 'error')
            else:
                registrar_usuario(username, email, password, role)
                flash('Usuario registrado correctamente.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        password = form.password.data
        role = validar_login(username, password)

        if role:
            session['user'] = username
            session['role'] = role
            session['last_activity'] = datetime.now().isoformat()
            flash('Inicio de sesión exitoso.', 'success')

            if role == 'Jefe':
                return redirect(url_for('jefe_panel'))
            else:
                return redirect(url_for('inspector_dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')

    return render_template('login.html', form=form)

@app.route('/recuperar_contraseña', methods=['GET', 'POST'])
def recuperar_contraseña():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))
        # Lógica de envío de correo (si la implementas)
        flash('Si el correo está registrado, se enviaron instrucciones de recuperación.', 'info')
        return redirect(url_for('login'))
    return render_template('recuperar_contraseña.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'success')
    return redirect(url_for('login'))

# ---------- Funciones / consultas de Inspectores ----------
def obtener_inspectores(search=None, filtro_linea=None):
    conn = get_connection()
    cur = conn.cursor()
    q = "SELECT id, nombre, linea, hora_entrada, hora_salida, estado FROM Inspectores WHERE 1=1"
    params = []
    if search:
        q += " AND nombre LIKE ?"
        params.append(f"%{search}%")
    if filtro_linea:
        q += " AND linea = ?"
        params.append(filtro_linea)
    q += " ORDER BY id DESC"
    cur.execute(q, params)
    rows = cur.fetchall()
    conn.close()
    return [
        {
            'id': r[0],
            'nombre': r[1],
            'linea': r[2],
            'hora_entrada': (str(r[3])[:8] if r[3] is not None else ""),
            'hora_salida': (str(r[4])[:8] if r[4] is not None else ""),
            'estado': r[5]
        } for r in rows
    ]

def agregar_inspector(nombre, linea, hora_entrada, hora_salida, usuario):
    # sanitizar antes de insertar
    nombre = sanitize_input(nombre)
    hora_entrada = sanitize_input(hora_entrada)
    hora_salida = sanitize_input(hora_salida)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO Inspectores (nombre, linea, hora_entrada, hora_salida, creado_por)
        VALUES (?, ?, ?, ?, ?)
    """, (nombre, linea, hora_entrada, hora_salida, usuario))
    # obtener id nuevo si el driver lo provee
    try:
        new_id = cur.lastrowid
    except Exception:
        new_id = None
    conn.commit()
    # registrar historial
    try:
        cur.execute("INSERT INTO Historial (accion, objeto, objeto_id, usuario, descripcion) VALUES (?, ?, ?, ?, ?)",
                    ("Agregar", "Inspector", new_id, usuario, f"Agregado inspector {nombre} linea {linea}"))
        conn.commit()
    except Exception:
        pass
    conn.close()

def editar_inspector(id, nombre, linea, hora_entrada, hora_salida, usuario):
    nombre = sanitize_input(nombre)
    hora_entrada = sanitize_input(hora_entrada)
    hora_salida = sanitize_input(hora_salida)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE Inspectores
        SET nombre = ?, linea = ?, hora_entrada = ?, hora_salida = ?
        WHERE id = ?
    """, (nombre, linea, hora_entrada, hora_salida, id))
    conn.commit()
    try:
        cur.execute("INSERT INTO Historial (accion, objeto, objeto_id, usuario, descripcion) VALUES (?, ?, ?, ?, ?)",
                    ("Editar", "Inspector", id, usuario, f"Editado inspector {nombre} linea {linea}"))
        conn.commit()
    except Exception:
        pass
    conn.close()

def eliminar_inspector(id, usuario):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT nombre FROM Inspectores WHERE id = ?", (id,))
        r = cur.fetchone()
        nombre = r[0] if r else ''
    except Exception:
        nombre = ''
    cur.execute("DELETE FROM Inspectores WHERE id = ?", (id,))
    conn.commit()
    try:
        cur.execute("INSERT INTO Historial (accion, objeto, objeto_id, usuario, descripcion) VALUES (?, ?, ?, ?, ?)",
                    ("Eliminar", "Inspector", id, usuario, f"Eliminado inspector {nombre}"))
        conn.commit()
    except Exception:
        pass
    conn.close()

# ---------- Rutas del Jefe (UI) ----------
@app.route('/jefe/panel', methods=['GET'])
def jefe_panel():
    if 'user' not in session or session.get('role') != 'Jefe':
        flash('Acceso denegado. Debes iniciar sesión como Jefe.', 'error')
        return redirect(url_for('login'))

    search_raw = request.args.get('search', None)
    search = sanitize_input(search_raw) if search_raw else None
    filtro_linea_raw = request.args.get('linea', None)
    filtro_linea = sanitize_input(filtro_linea_raw) if filtro_linea_raw else None

    inspectores = obtener_inspectores(search=search, filtro_linea=filtro_linea)
    total = len(obtener_inspectores())
    por_linea = {}
    for i in range(2, 7):
        por_linea[i] = len(obtener_inspectores(filtro_linea=i))
    return render_template('jefe.html',
                           jefe=session.get('user'),
                           inspectores=inspectores,
                           total=total,
                           por_linea=por_linea,
                           search=search,
                           filtro_linea=filtro_linea)

@app.route('/jefe/agregar', methods=['POST'])
def jefe_agregar():
    if 'user' not in session or session.get('role') != 'Jefe':
        return redirect(url_for('login'))
    nombre = sanitize_input(request.form.get('nombre'))
    try:
        linea = int(request.form.get('linea'))
    except Exception:
        linea = None
    hora_entrada = sanitize_input(request.form.get('hora_entrada'))
    hora_salida = sanitize_input(request.form.get('hora_salida'))
    agregar_inspector(nombre, linea, hora_entrada, hora_salida, session.get('user'))
    flash('Inspector agregado correctamente.', 'success')
    return redirect(url_for('jefe_panel'))

@app.route('/jefe/editar/<int:id>', methods=['POST'])
def jefe_editar(id):
    if 'user' not in session or session.get('role') != 'Jefe':
        return redirect(url_for('login'))
    nombre = sanitize_input(request.form.get('nombre'))
    linea = int(request.form.get('linea'))
    hora_entrada = sanitize_input(request.form.get('hora_entrada'))
    hora_salida = sanitize_input(request.form.get('hora_salida'))
    editar_inspector(id, nombre, linea, hora_entrada, hora_salida, session.get('user'))
    flash('Inspector actualizado.', 'success')
    return redirect(url_for('jefe_panel'))

@app.route('/jefe/eliminar/<int:id>', methods=['POST'])
def jefe_eliminar(id):
    if 'user' not in session or session.get('role') != 'Jefe':
        return redirect(url_for('login'))
    eliminar_inspector(id, session.get('user'))
    flash('Inspector eliminado.', 'success')
    return redirect(url_for('jefe_panel'))

@app.route('/jefe/exportar_csv', methods=['GET'])
def jefe_exportar_csv():
    if 'user' not in session or session.get('role') != 'Jefe':
        return redirect(url_for('login'))
    inspectores = obtener_inspectores()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Nombre', 'Linea', 'Hora Entrada', 'Hora Salida', 'Estado'])
    for p in inspectores:
        writer.writerow([p['id'], p['nombre'], p['linea'], p['hora_entrada'], p['hora_salida'], p['estado']])
    mem = io.BytesIO()
    mem.write(si.getvalue().encode('utf-8'))
    mem.seek(0)
    si.close()
    return send_file(mem, mimetype='text/csv', download_name='inspectores.csv', as_attachment=True)

# ---------- Panel del Inspector (UI) ----------
def obtener_info_inspector_por_usuario(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, linea, hora_entrada, hora_salida, estado FROM Inspectores WHERE creado_por = ?", (username,))
    rows = cur.fetchall()
    conn.close()
    return rows

def obtener_personal_asignado_por_linea(linea):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, linea, hora_entrada, hora_salida, estado FROM Inspectores WHERE linea = ?", (linea,))
    rows = cur.fetchall()
    conn.close()
    lista = []
    for r in rows:
        lista.append({
            "id": r[0],
            "nombre": r[1],
            "linea": r[2],
            "hora_entrada": str(r[3])[:5] if r[3] is not None else "",
            "hora_salida": str(r[4])[:5] if r[4] is not None else "",
            "estado": r[5]
        })
    return lista

@app.route('/inspector')
def inspector_dashboard():
    if 'user' not in session or session.get('role') != 'Inspector':
        flash("Debes iniciar sesión como Inspector", "error")
        return redirect(url_for('login'))

    username = session['user']
    filas = obtener_info_inspector_por_usuario(username)

    if not filas:
        turno = {
            "turno": "No asignado",
            "encargada": username,
            "hora_entrada": "",
            "hora_salida": "",
            "planta": "Planta Marelli",
            "linea_produccion": "Sin asignar"
        }
        return render_template("inspector.html",
                               inspector=username,
                               turno=turno,
                               personal_asignado=[],
                               message="Aún no tienes una línea asignada.")

    fila = filas[0]
    linea = fila[2]
    turno = {
        "turno": "Asignado",
        "encargada": username,
        "hora_entrada": str(fila[3])[:5] if fila[3] is not None else "",
        "hora_salida": str(fila[4])[:5] if fila[4] is not None else "",
        "planta": "Planta Marelli",
        "linea_produccion": f"Línea {linea}"
    }
    personal = obtener_personal_asignado_por_linea(linea)
    return render_template("inspector.html",
                           inspector=username,
                           turno=turno,
                           personal_asignado=personal,
                           message=None)

# --------------------- MÓDULO DE RIESGOS (MATRIZ) ---------------------

def calcular_nivel_riesgo(probabilidad, impacto):
    """Regla simple para calcular nivel de riesgo."""
    p = (probabilidad or "").lower()
    i = (impacto or "").lower()
    # reglas sencillas
    if "alta" in p or "alto" in i:
        return "Alto"
    if "media" in p or "medio" in i:
        return "Medio"
    return "Bajo"

def obtener_riesgos():
    conn = get_connection()
    cur = conn.cursor()
    # Asumimos que en la BD la columna de mitigación se llama 'mitigacion'
    cur.execute("SELECT id, riesgo, probabilidad, impacto, mitigacion, creado_por FROM Riesgos")
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "riesgo": r[1],
            "probabilidad": r[2],
            "impacto": r[3],
            "mitigacion": r[4],
            "creado_por": r[5],
            "nivel_riesgo": calcular_nivel_riesgo(r[2], r[3])
        }
        for r in rows
    ]

def agregar_riesgo(riesgo, probabilidad, impacto, mitigacion, usuario):
    # sanitizar entradas
    riesgo = sanitize_input(riesgo)
    probabilidad = sanitize_input(probabilidad)
    impacto = sanitize_input(impacto)
    mitigacion = sanitize_input(mitigacion)

    nivel_riesgo = calcular_nivel_riesgo(probabilidad, impacto)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO Riesgos (riesgo, probabilidad, impacto, mitigacion, nivel_riesgo, creado_por)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (riesgo, probabilidad, impacto, mitigacion, nivel_riesgo, usuario))
    conn.commit()
    conn.close()


def eliminar_riesgo(id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM Riesgos WHERE id = ?", (id,))
    conn.commit()
    conn.close()

# ---------- RUTAS ----------
@app.route('/riesgos')
def riesgos_panel():
    if 'user' not in session or session.get('role') != 'Jefe':
        flash("Acceso denegado. Solo el Jefe puede ver los riesgos.", "error")
        return redirect(url_for('login'))

    lista = obtener_riesgos()
    return render_template("riesgos.html", riesgos=lista)

@app.route('/riesgos/agregar', methods=['POST'])
def riesgos_agregar():
    if 'user' not in session or session.get('role') != 'Jefe':
        flash("Acceso denegado.", "error")
        return redirect(url_for('login'))

    riesgo = request.form.get("riesgo")
    probabilidad = request.form.get("probabilidad")
    impacto = request.form.get("impacto")
    mitigacion = request.form.get("mitigacion") or request.form.get("estrategia") or request.form.get("mitigacion")  # aceptar varios nombres
    usuario = session.get("user")

    agregar_riesgo(riesgo, probabilidad, impacto, mitigacion, usuario)
    flash("Riesgo agregado correctamente.", "success")
    return redirect(url_for("riesgos_panel"))

def editar_riesgo(id, riesgo, probabilidad, impacto, mitigacion):
    riesgo = sanitize_input(riesgo)
    probabilidad = sanitize_input(probabilidad)
    impacto = sanitize_input(impacto)
    mitigacion = sanitize_input(mitigacion)

    nivel_riesgo = calcular_nivel_riesgo(probabilidad, impacto)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE Riesgos
        SET riesgo = ?, probabilidad = ?, impacto = ?, mitigacion = ?, nivel_riesgo = ?
        WHERE id = ?
    """, (riesgo, probabilidad, impacto, mitigacion, nivel_riesgo, id))
    conn.commit()
    conn.close()


@app.route('/riesgos/editar/<int:id>', methods=['GET'])
def riesgos_editar_form(id):
    if 'user' not in session or session.get('role') != 'Jefe':
        flash("Acceso denegado.", "error")
        return redirect(url_for('login'))

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, riesgo, probabilidad, impacto, mitigacion FROM Riesgos WHERE id = ?", (id,))
    r = cur.fetchone()
    conn.close()

    if not r:
        flash("Riesgo no encontrado.", "error")
        return redirect(url_for("riesgos_panel"))

    riesgo = {
        "id": r[0],
        "riesgo": r[1],
        "probabilidad": r[2],
        "impacto": r[3],
        "mitigacion": r[4]
    }

    return render_template("riesgos_editar.html", r=riesgo)

# ÚNICA ruta POST para guardar la edición del riesgo
@app.route('/riesgos/editar/<int:id>', methods=['POST'])
def riesgos_editar_guardar(id):
    if 'user' not in session or session.get('role') != 'Jefe':
        flash("Acceso denegado.", "error")
        return redirect(url_for('login'))

    riesgo = request.form.get("riesgo")
    probabilidad = request.form.get("probabilidad")
    impacto = request.form.get("impacto")
    mitigacion = request.form.get("mitigacion")

    editar_riesgo(id, riesgo, probabilidad, impacto, mitigacion)

    flash("Riesgo actualizado correctamente.", "success")
    return redirect(url_for("riesgos_panel"))

@app.route('/riesgos/eliminar/<int:id>', methods=['POST'])
def riesgos_eliminar(id):
    if 'user' not in session or session.get('role') != 'Jefe':
        flash("Acceso denegado.", "error")
        return redirect(url_for('login'))

    eliminar_riesgo(id)
    flash("Riesgo eliminado.", "success")
    return redirect(url_for("riesgos_panel"))

# ---------- Rutas legales ----------
@app.route('/terminos')
def terminos():
    return render_template('terminos.html')

@app.route('/privacidad')
def privacidad():
    return render_template('privacidad.html')

# ---------- Web Service (API) ----------
@app.route('/api/inspectores', methods=['GET'])
def api_obtener_inspectores():
    datos = obtener_inspectores()
    return jsonify(datos), 200

@app.route('/api/inspectores/<int:id>', methods=['GET'])
def api_obtener_inspector(id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, nombre, linea, hora_entrada, hora_salida, estado FROM Inspectores WHERE id = ?", (id,))
    fila = cur.fetchone()
    conn.close()
    if fila:
        return jsonify({
            "id": fila[0],
            "nombre": fila[1],
            "linea": fila[2],
            "hora_entrada": str(fila[3])[:5] if fila[3] is not None else "",
            "hora_salida": str(fila[4])[:5] if fila[4] is not None else "",
            "estado": fila[5]
        }), 200
    return jsonify({"error": "Inspector no encontrado"}), 404

# ---------- Consumir API interna ----------
@app.route('/consumir_api')
def consumir_api():
    # Si tu app corre con HTTPS autofirmado, usamos verify=False para evitar fallo SSL local
    url = "https://127.0.0.1:5000/api/inspectores"
    try:
        resp = requests.get(url, verify=False, timeout=5)
        if resp.status_code == 200:
            datos = resp.json()
            return jsonify({"mensaje": "Datos obtenidos correctamente", "inspectores": datos}), 200
        else:
            return jsonify({"error": "API devolvió status " + str(resp.status_code)}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Error al consumir API interna", "detalle": str(e)}), 500

# ---------- Ejemplo: Consumir un Web Service externo ----------
import requests
from flask import jsonify

@app.route('/api_externa')
def api_externa():
    try:
        r = requests.get("https://jsonplaceholder.typicode.com/todos/1", timeout=5)
        data = r.json()
        return jsonify({
            "mensaje": "API consumida correctamente",
            "data": data
        })
    except Exception as e:
        return jsonify({"error": "No se pudo consumir la API externa", "detalle": str(e)}), 500


# ---------- Arranque de la app ----------
if __name__ == '__main__':
    # Arrancar con SSL si existen los certificados (autofirmados)
    cert_path = os.path.join('cert', 'cert.pem')
    key_path = os.path.join('cert', 'key.pem')
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("Iniciando con SSL (certificados encontrados en cert/)")
        app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path))
    else:
        print("Iniciando sin SSL (no se encontraron certificados en cert/)")
        app.run(debug=True, host='0.0.0.0', port=5000)
