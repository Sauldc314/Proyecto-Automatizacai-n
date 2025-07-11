from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session, send_from_directory, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from netmiko import ConnectHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime
from flask_socketio import SocketIO, emit
import pandas as pd
from napalm import get_network_driver
from weasyprint import HTML
import traceback

import cryptography
import os
import json
import ssl
import re
import csv

from utils.estadistica import actualizar_estadisticas

load_dotenv()

app = Flask(__name__)

###
# bd
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24) 
app.config['SESSION_PROTECTION'] = 'strong'  # Detecta cambios sospechosos en la sesión
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Evita ataques CSRF básicos
app.config['SESSION_COOKIE_HTTPONLY'] = True
#app.config['SESSION_COOKIE_SECURE'] = True  # Usa HTTPS en producción
#app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Expira en 1 hora
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_USE_SIGNER'] = True  # Protege contra manipulación de cookies

#correo
# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') 
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME') 

db = SQLAlchemy(app)
limiter = Limiter(app)
csrf = CSRFProtect(app)
mail = Mail(app)
socketio = SocketIO(app, async_mode='eventlet')

#########################

# Tabla de roles (admin, operador, auditor, etc.)
class Rol(db.Model):
    __tablename__ = 'rol'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(20), unique=True, nullable=False)

# Usuarios
class Usuario(db.Model):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(20), unique=True, nullable=False)
    nombre = db.Column(db.String(50), nullable=False)
    apellido = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    contrasenia = db.Column(db.String(200), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    rol_id = db.Column(db.Integer, db.ForeignKey('rol.id'))

    rol = db.relationship('Rol', backref='usuarios')

class Dispositivo(db.Model):
    __tablename__ = 'dispositivo'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(15), unique=True, nullable=False)
    tipo = db.Column(db.String(30), default='cisco_ios')  # o juniper, mikrotik, etc.
    ubicacion = db.Column(db.String(100))
    username = db.Column(db.String(50))
    contrasenia = db.Column(db.String(200))  # Encriptada con Fernet
    enable_secret = db.Column(db.String(200))
    estado = db.Column(db.String(20), default="activo")  # activo, cuarentena, bloqueado
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)

class ConfiguracionBackup(db.Model):
    __tablename__ = 'configuracion_backup'
    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    contenido = db.Column(db.Text)  # Configuración pura
    fecha_backup = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))

    dispositivo = db.relationship('Dispositivo', backref='backups')
    usuario = db.relationship('Usuario')

class Enlace(db.Model):
    __tablename__ = 'enlace'
    id = db.Column(db.Integer, primary_key=True)
    origen_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    destino_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    tipo = db.Column(db.String(30))  # Ethernet, fibra, inalámbrico
    latencia = db.Column(db.Float)
    ancho_banda = db.Column(db.Float)

    origen = db.relationship('Dispositivo', foreign_keys=[origen_id])
    destino = db.relationship('Dispositivo', foreign_keys=[destino_id])

class AccesoPermitido(db.Model):
    __tablename__ = 'acceso_permitido'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))
    ip_autorizada = db.Column(db.String(45))
    mac_autorizada = db.Column(db.String(50))
    descripcion = db.Column(db.String(100))
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)

class LogActividad(db.Model):
    __tablename__ = 'log_actividad'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))
    accion = db.Column(db.String(200))
    resultado = db.Column(db.String(100))
    ip_dispositivo = db.Column(db.String(15))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

    usuario = db.relationship('Usuario')

class EscaneoVulnerabilidad(db.Model):
    __tablename__ = 'escaneo_vulnerabilidad'
    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    tipo = db.Column(db.String(50))  # Puertos, CVEs, servicios, etc.
    resultado = db.Column(db.Text)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

    dispositivo = db.relationship('Dispositivo')

class Reporte(db.Model):
    __tablename__ = 'reporte'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50))  # rendimiento, backup, alertas, etc.
    archivo = db.Column(db.String(100))  # Ruta del PDF, XLS, etc.
    fecha_generacion = db.Column(db.DateTime, default=datetime.utcnow)
    generado_por = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))

    usuario = db.relationship('Usuario')

class Alerta(db.Model):
    __tablename__ = 'alerta'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50))  # CPU alta, acceso no autorizado, error de backup, etc.
    mensaje = db.Column(db.String(200))
    nivel = db.Column(db.String(20))  # info, warning, critical
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    leido = db.Column(db.Boolean, default=False)

class TareaProgramada(db.Model):
    __tablename__ = 'tarea_programada'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    tipo = db.Column(db.String(50))  # backup, escaneo, cambio de config
    dispositivo_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    frecuencia = db.Column(db.String(50))  # diario, semanal, cada X horas
    estado = db.Column(db.String(20), default='pendiente')
    ultima_ejecucion = db.Column(db.DateTime)
    proxima_ejecucion = db.Column(db.DateTime)

    dispositivo = db.relationship('Dispositivo')

class CambioConfiguracion(db.Model):
    __tablename__ = 'cambio_configuracion'
    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey('dispositivo.id'))
    realizado_por = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    diff = db.Column(db.Text)  # Comparación entre versiones

######################33
TEMPS_FOLDER = 'temp'
os.makedirs(TEMPS_FOLDER, exist_ok=True)

BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

ROLLBACK_FOLDER = 'rollback'
os.makedirs(ROLLBACK_FOLDER, exist_ok=True)

PROPUESTAS_FOLDER = 'cicd_configs'
os.makedirs(PROPUESTAS_FOLDER, exist_ok=True)

REGLAS_FOLDER = "reglas_firewall"
os.makedirs(REGLAS_FOLDER, exist_ok=True)

SIEM_LOG_FOLDER = "siem_logs"
os.makedirs(SIEM_LOG_FOLDER, exist_ok=True)
SIEM_LOG_FILE = os.path.join(SIEM_LOG_FOLDER, "logs_sinteticos.json")


CERTS_FOLDER = "certs"
os.makedirs(CERTS_FOLDER, exist_ok=True)

NAC_DIR = "nac_data"
os.makedirs(NAC_DIR, exist_ok=True)
LISTA_BLANCA = os.path.join(NAC_DIR, "lista_blanca.json")
REGISTROS = os.path.join(NAC_DIR, "registros_actividad.json")

CUARENTENA_FOLDER = "cuarentena"
os.makedirs(CUARENTENA_FOLDER, exist_ok=True)
HISTORIAL_FILE = os.path.join(CUARENTENA_FOLDER, "historial.json")
CONFIG_FILE = os.path.join(CUARENTENA_FOLDER, "vlan_config.json")

DATA = "data"
os.makedirs(DATA, exist_ok=True)
#################################

def guardar_version(device, config_text):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{device['ip'].replace('.', '_')}_{timestamp}.txt"
    filepath = os.path.join(ROLLBACK_FOLDER, filename)
    with open(filepath, "w") as f:
        f.write(config_text)
    return filepath

def backup_config(device):
    try:
        conn = ConnectHandler(**device)
        conn.enable()
        config = conn.send_command("show running-config")
        filename = f"backup_{device['ip'].replace('.', '_')}.txt"
        filepath = os.path.join(BACKUP_FOLDER, filename)
        with open(filepath, "w") as f:
            f.write(config)
        guardar_version(device, config)
        conn.disconnect()
        return filepath, None
    except Exception as e:
        return None, str(e)

def monitor_traffic(device):
    try:
        conn = ConnectHandler(**device)
        conn.enable()
        output = conn.send_command("show interfaces", expect_string=r"#")
        conn.disconnect()
        return output, None
    except Exception as e:
        return None, str(e)

def tarea_repetitiva(device, nueva_pass):
    try:
        conn = ConnectHandler(**device)
        conn.enable()
        comandos = [
            f"username {device['username']} password {nueva_pass}",
            f"username {device['username']} secret {nueva_pass}",
        ]
        conn.send_config_set(comandos)
        conn.disconnect()
        return f"Contraseña actualizada en {device['ip']}", None
    except Exception as e:
        return None, str(e)

def aplicar_configuracion(device, path_archivo):
    if not os.path.exists(path_archivo):
        return None, "Archivo de configuración no encontrado."

    try:
        with open(path_archivo) as f:
            comandos = f.read().splitlines()

        conn = ConnectHandler(**device)
        conn.enable()
        resultado = conn.send_config_set(comandos)
        conn.disconnect()
        return resultado, None
    except Exception as e:
        return None, str(e)

def obtener_running_config(device):
    try:
        conn = ConnectHandler(**device)
        conn.enable()
        config = conn.send_command("show running-config")
        conn.disconnect()
        return config, None
    except Exception as e:
        return None, str(e)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verifica si el usuario está en la sesión
        if 'usuario_id' not in session:
            flash('Por favor, inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def cargar_json_seguro(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []  # o {} si esperas un dict
    with open(path) as f:
        return json.load(f)

########################

@app.route('/registro', methods=['GET', 'POST'])
@csrf.exempt
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        usuario_lower = usuario.lower()  # Convierte a minúsculas
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        contrasenia = request.form['contrasenia']
        confirmacion = request.form['confirmacion']

        if contrasenia != confirmacion:
            flash("Las contraseñas no coinciden", "error")
            return redirect(url_for('registro'))
        # Verificar si el usuario ya existe (ignorando mayúsculas/minúsculas)
        if Usuario.query.filter(db.func.binary(Usuario.usuario) == usuario).first():
            flash("El usuario ya existe", "error")
            return redirect(url_for('registro'))
        # Verificar si el correo ya está registrado
        if Usuario.query.filter_by(correo=correo).first():
            flash("El correo ya está registrado", "error")
            return redirect(url_for('registro'))
        # Crear nuevo usuario
        nuevo_usuario = Usuario(
            usuario=usuario_lower,
            nombre=nombre,
            apellido=apellido,
            correo=correo,
            contrasenia=generate_password_hash(contrasenia)
        )
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('¡Registro exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect('login')

    return render_template('auth/registro.html')

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
@limiter.limit("5 per minute") 
def login():
    if request.method == 'POST':
        usuario_o_correo = request.form['usuario_o_correo'].strip()  # Puede ser usuario o correo
        contrasenia = request.form['contrasenia']

        # Buscar usuario por correo o por usuario_lower
        usuario = Usuario.query.filter(
            (Usuario.correo == usuario_o_correo) | (Usuario.usuario == usuario_o_correo.lower())
        ).first()

        if usuario and check_password_hash(usuario.contrasenia, contrasenia):
            session['usuario_id'] = usuario.id_usuario
            session['usuario_usuario'] = usuario.usuario  # Guarda el usuario con formato original
            session['usuario_rol'] = usuario.rol
#            actualizar_estadisticas()
            flash('Login exitoso, Bienvenido a la plataforma de automatización de redes.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuario/Correo o contraseña incorrectos', 'danger')

    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('usuario_id', None)
    session.pop('usuario_nombre', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# --- Seguridad Automatizada ---
@app.route('/firewall_centralizado', methods=["GET", "POST"])
@login_required
@csrf.exempt
def firewall_centralizado():
    reglas = sorted(os.listdir(REGLAS_FOLDER), reverse=True)

    if request.method == "POST":
        action = request.form.get("action")  # permit o deny
        origen = request.form.get("origen")
        destino = request.form.get("destino")
        protocolo = request.form.get("protocolo")
        puerto = request.form.get("puerto")
        descripcion = request.form.get("descripcion")
        aplicar = request.form.get("aplicar")  # on si se seleccionó checkbox

        if not all([action, origen, destino, protocolo]):
            flash("Todos los campos excepto descripción son obligatorios", "error")
            return redirect(url_for("firewall_centralizado"))

        # Construir regla ACL tipo Cisco
        regla = f"{action} {protocolo} {origen} {destino} eq {puerto}  ! {descripcion or ''}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fw_regla_{timestamp}.txt"
        filepath = os.path.join(REGLAS_FOLDER, filename)

        with open(filepath, "w") as f:
            f.write(regla + "\n")

        flash(f"Regla guardada: {filename}", "success")

        if aplicar == "on":
            # Ejemplo de aplicación (se puede extender)
            try:
                ip = request.form.get("ip")
                username = request.form.get("username")
                password = request.form.get("password")
                secret = request.form.get("secret")

                device = {
                    'device_type': 'cisco_ios',
                    'ip': ip,
                    'username': username,
                    'password': password,
                    'secret': secret if secret else None,
                    'global_delay_factor': 2
                }

                conn = ConnectHandler(**device)
                conn.enable()
                resultado = conn.send_config_set([regla])
                conn.disconnect()
                flash(f"Regla aplicada exitosamente:\n{resultado}", "success")
            except Exception as e:
                flash(f"Error al aplicar regla: {str(e)}", "error")

        return redirect(url_for("firewall_centralizado"))

    return render_template("seguridad/firewall_centralizado.html", reglas=reglas)

@app.route('/siem_integrado')
@login_required
def siem_integrado():
    eventos = []

    try:
        if os.path.exists(SIEM_LOG_FILE):
            with open(SIEM_LOG_FILE) as f:
                eventos = json.load(f)
        else:
            flash("Archivo de eventos no encontrado.", "warning")
    except Exception as e:
        flash(f"Error al cargar logs SIEM: {str(e)}", "danger")

    return render_template("seguridad/siem_integrado.html", eventos=eventos)

@app.route('/exportar_siem_csv')
@login_required
def exportar_siem_csv():
    if not os.path.exists(SIEM_LOG_FILE):
        flash("No hay eventos para exportar.", "warning")
        return redirect(url_for("siem_integrado"))

    with open(SIEM_LOG_FILE, "r") as f:
        eventos = json.load(f)

    si = []
    output = csv.StringIO()
    writer = csv.DictWriter(output, fieldnames=["fecha", "tipo", "descripcion", "nivel"])
    writer.writeheader()
    for ev in eventos:
        writer.writerow(ev)

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=siem_eventos.csv"
    return response

@app.route('/webhook/siem', methods=["POST"])
@csrf.exempt  # Webhooks externos no tienen CSRF token
def webhook_siem():
    if not request.is_json:
        return {"status": "error", "message": "Formato inválido, se espera JSON"}, 400

    try:
        data = request.get_json()

        evento = {
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tipo": data.get("tipo", "Desconocido"),
            "descripcion": data.get("descripcion", "Sin descripción"),
            "nivel": data.get("nivel", "Media")
        }

        eventos = []
        if os.path.exists(SIEM_LOG_FILE):
            with open(SIEM_LOG_FILE, "r") as f:
                try:
                    eventos = json.load(f)
                except:
                    eventos = []

        eventos.insert(0, evento)
        eventos = eventos[:100]

        with open(SIEM_LOG_FILE, "w") as f:
            json.dump(eventos, f, indent=2)

        return {"status": "ok", "message": "Evento recibido correctamente"}, 200

    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@app.route('/deteccion_dispositivos_anomalos')
@login_required
def deteccion_dispositivos_anomalos():
    dispositivos_analizados = []

    try:
        with open(LISTA_BLANCA) as f:
            lista_blanca = json.load(f)

        with open(REGISTROS) as f:
            registros = json.load(f)

        # Normalizar MACs
        macs_autorizadas = {d["mac"].strip().lower(): d for d in lista_blanca}

        for r in registros:
            mac = r["mac"].strip().lower()
            autorizado = mac in macs_autorizadas
            descripcion = macs_autorizadas.get(mac, {}).get("descripcion", "Desconocido")

            dispositivos_analizados.append({
                "mac": mac,
                "ip": r.get("ip", "N/D"),
                "trafico": r.get("trafico", "0"),
                "puertos": r.get("puertos", []),
                "vlan": r.get("vlan_detectada", "N/D"),
                "descripcion": descripcion,
                "autorizado": autorizado
            })

    except Exception as e:
        flash(f"Error al cargar datos NAC: {str(e)}", "error")
#    actualizar_estadisticas()
    return render_template("seguridad/deteccion_dispositivos_anomalos.html", dispositivos=dispositivos_analizados)

@app.route("/agregar_registro_nac", methods=["POST"])
@login_required
@csrf.exempt
def agregar_registro_nac():
    try:
        nuevo = {
            "mac": request.form.get("mac").strip().lower(),
            "ip": request.form.get("ip"),
            "vlan_detectada": request.form.get("vlan"),
            "trafico": request.form.get("trafico"),
            "puertos": request.form.get("puertos").split(",")  # cadena a lista
        }

        registros = []
        if os.path.exists(REGISTROS):
            with open(REGISTROS) as f:
                registros = json.load(f)

        registros.insert(0, nuevo)

        with open(REGISTROS, "w") as f:
            json.dump(registros, f, indent=2)

        flash("Registro NAC agregado exitosamente", "success")

    except Exception as e:
        flash(f"Error al agregar registro: {str(e)}", "error")

    return redirect(url_for("deteccion_dispositivos_anomalos"))

@app.route("/agregar_lista_blanca", methods=["POST"])
@login_required
@csrf.exempt
def agregar_lista_blanca():
    try:
        nuevo = {
            "mac": request.form.get("mac").strip().lower(),
            "descripcion": request.form.get("descripcion")
        }

        lista = []
        if os.path.exists(LISTA_BLANCA):
            with open(LISTA_BLANCA) as f:
                lista = json.load(f)

        lista.insert(0, nuevo)

        with open(LISTA_BLANCA, "w") as f:
            json.dump(lista, f, indent=2)

        flash("MAC agregada a lista blanca", "success")

    except Exception as e:
        flash(f"Error al autorizar dispositivo: {str(e)}", "error")

    return redirect(url_for("deteccion_dispositivos_anomalos"))

def parse_cert_info(cert_path):
    try:
        cert = ssl._ssl._test_decode_cert(cert_path)
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', '')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', '')
        not_before = cert['notBefore']
        not_after = cert['notAfter']

        return {
            'path': cert_path,
            'issued_to': issued_to,
            'issuer': issuer,
            'not_before': datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z"),
            'not_after': datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z"),
            'valid_days': (datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days
        }
    except Exception as e:
        return {'error': str(e), 'path': cert_path}

@app.route('/gestor_certificados_tls')
@login_required
def gestor_certificados_tls():
    certificados = []
    try:
        for file in os.listdir(CERTS_FOLDER):
            if file.endswith(".pem") or file.endswith(".crt"):
                cert_path = os.path.join(CERTS_FOLDER, file)
                info = parse_cert_info(cert_path)
                certificados.append(info)
    except Exception as e:
        flash(f"Error al cargar certificados: {str(e)}", "error")

    return render_template("seguridad/gestor_certificados_tls.html", certificados=certificados)

@app.route('/subir_certificado', methods=["POST"])
@login_required
@csrf.exempt
def subir_certificado():
    file = request.files.get("cert_file")
    if not file:
        flash("No se seleccionó ningún archivo", "error")
        return redirect(url_for("gestor_certificados_tls"))

    try:
        filename = secure_filename(file.filename)
        path = os.path.join(CERTS_FOLDER, filename)
        file.save(path)
        flash(f"Certificado {filename} subido correctamente", "success")
    except Exception as e:
        flash(f"Error al subir certificado: {str(e)}", "error")

    return redirect(url_for("gestor_certificados_tls"))

@app.route('/sistema_cuarentena_automatico', methods=["GET", "POST"])
@login_required
@csrf.exempt
def sistema_cuarentena_automatico():
    historial = []
    #config = {"vlan_cuarentena": "999", "interface_prefix": "GigabitEthernet0/"}
    dispositivos_anomalos = []

    try:
        # Historial y config
        historial = cargar_json_seguro(HISTORIAL_FILE)
        config = cargar_json_seguro(CONFIG_FILE)


        # Análisis de anomalías
        with open(LISTA_BLANCA) as f:
            lista_blanca = json.load(f)
        with open(REGISTROS) as f:
            registros = json.load(f)

        macs_autorizadas = {d["mac"].lower() for d in lista_blanca}
        for r in registros:
            mac = r["mac"].lower()
            if mac not in macs_autorizadas:
                dispositivos_anomalos.append({
                    "mac": mac,
                    "ip": r["ip"],
                    "interface": r.get("interface", f"{config['interface_prefix']}1"),  # o de donde se obtenga
                    "vlan_detectada": r["vlan_detectada"],
                    "trafico": r["trafico"],
                    "puertos": r["puertos"]
                })

    except Exception as e:
        flash(f"Error cargando archivos: {str(e)}", "error")

    if request.method == "POST":
        # Cuarentena manual
        mac = request.form.get("mac")
        interface = request.form.get("interface")
        ip = request.form.get("ip")
        vlan = config.get("vlan_cuarentena", "999")
        sw_ip = request.form.get("sw_ip")
        username = request.form.get("username")
        password = request.form.get("password")

        if not mac or not interface or not sw_ip:
            flash("Datos incompletos", "error")
            return redirect(url_for("sistema_cuarentena_automatico"))

        try:
            device = {
                'device_type': 'cisco_ios',
                'ip': sw_ip,
                'username': username,
                'password': password,
            }

            conn = ConnectHandler(**device)
            conn.enable()

            cmds = [
                f"interface {interface}",
                f"switchport access vlan {vlan}",
                "shutdown",
                "no shutdown",
                "exit"
            ]
            output = conn.send_config_set(cmds)
            conn.disconnect()

            evento = {
                "mac": mac,
                "ip": ip,
                "interface": interface,
                "vlan_asignada": vlan,
                "fecha": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            historial.append(evento)
            with open(HISTORIAL_FILE, "w") as f:
                json.dump(historial, f, indent=2)

            flash(f"Dispositivo en cuarentena VLAN {vlan}", "success")
#            ok, err = actualizar_estadisticas()
#            if not ok:
#                flash(f"Error al actualizar estadísticas: {err}", "error")
        except Exception as e:
            flash(f"Error al aplicar cuarentena: {str(e)}", "error")

        return redirect(url_for("sistema_cuarentena_automatico"))

    return render_template("seguridad/sistema_cuarentena_automatico.html", historial=historial, vlan=config["vlan_cuarentena"], anomalos=dispositivos_anomalos)

# --- Automatización de Configuraciones ---
@app.route("/integracion_netmiko", methods=["GET", "POST"])
@login_required
@csrf.exempt
def integracion_netmiko():
    if request.method == "POST":
        ip = request.form.get("ip")
        username = request.form.get("username")
        password = request.form.get("password")
        secret = request.form.get("secret", "").strip()
        tarea = request.form.get("tarea")
        nueva_pass = request.form.get("nueva_pass", "").strip()

        if not ip or not username or not password:
            flash("IP, usuario y contraseña son obligatorios", "error")
            return redirect(url_for("integracion_netmiko"))

        device = {
            'device_type': 'cisco_ios',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret if secret else None,
            'global_delay_factor': 2,
            'timeout': 60,
        }

        resultado = None
        error = None
        archivo_backup = None

        if tarea == "backup":
            archivo_backup, error = backup_config(device)
            if archivo_backup:
                flash(f"Backup creado: {archivo_backup}", "success")
                return redirect(url_for("download_backup", filename=os.path.basename(archivo_backup)))
            else:
                flash(f"Error en backup: {error}", "error")

        elif tarea == "monitoreo":
            resultado, error = monitor_traffic(device)
            if error:
                flash(f"Error en monitoreo: {error}", "error")
            else:
                return render_template("automatizacion/resultado.html", resultado=resultado, dispositivo=ip, tarea=tarea)

        elif tarea == "cambiar_pass":
            if not nueva_pass:
                flash("Debe ingresar la nueva contraseña", "error")
                return redirect(url_for("integracion_netmiko"))
            mensaje, error = tarea_repetitiva(device, nueva_pass)
            if error:
                flash(f"Error al cambiar contraseña: {error}", "error")
            else:
                flash(mensaje, "success")

        else:
            flash("Tarea inválida", "error")

        return redirect(url_for("integracion_netmiko"))

    return render_template("automatizacion/integracion_ansible.html")

@app.route('/download_backup/<filename>')
@login_required
def download_backup(filename):
    return send_from_directory(BACKUP_FOLDER, filename, as_attachment=True)

@app.route('/rollback_automatico', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def rollback_automatico():
    archivos = sorted(os.listdir(ROLLBACK_FOLDER), reverse=True)

    if request.method == 'POST':
        ip = request.form.get("ip")
        username = request.form.get("username")
        password = request.form.get("password")
        secret = request.form.get("secret", "").strip()
        version = request.form.get("version")

        if not ip or not username or not password or not version:
            flash("Todos los campos son obligatorios", "error")
            return redirect(url_for('rollback_automatico'))

        device = {
            'device_type': 'cisco_ios',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret if secret else None,
            'global_delay_factor': 2,
            'timeout': 60,
        }

        # Guardar versión actual antes de aplicar rollback
        config_actual, err = obtener_running_config(device)
        if err:
            flash(f"Error al obtener configuración actual: {err}", "error")
            return redirect(url_for('rollback_automatico'))

        guardar_version(device, config_actual)

        # Aplicar rollback
        path_archivo = os.path.join(ROLLBACK_FOLDER, version)
        resultado, err = aplicar_configuracion(device, path_archivo)

        if err:
            flash(f"Error al aplicar rollback: {err}", "error")
        else:
            flash(f"Rollback aplicado con éxito desde archivo: {version}", "success")

        return redirect(url_for('rollback_automatico'))

    return render_template("automatizacion/rollback_automatico.html", versiones=archivos)

@app.route('/download_rollback/<filename>')
@login_required
def download_rollback(filename):
    return send_from_directory(ROLLBACK_FOLDER, filename, as_attachment=True)

@app.route('/control_aprobaciones_cicd', methods=["GET", "POST"])
@login_required
@csrf.exempt
def control_aprobaciones_cicd():
    if request.method == "POST":
        ip = request.form.get("ip")
        nombre = request.form.get("nombre")
        config = request.form.get("config")
        if not ip or not config:
            flash("IP y configuración propuesta son obligatorios", "error")
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{ip.replace('.', '_')}_{nombre}_{timestamp}.txt"
            filepath = os.path.join(PROPUESTAS_FOLDER, filename)
            with open(filepath, "w") as f:
                f.write(config)
            flash(f"Configuración propuesta guardada como {filename}", "success")
        return redirect(url_for("control_aprobaciones_cicd"))

    propuestas = sorted(os.listdir(PROPUESTAS_FOLDER), reverse=True)
    return render_template("automatizacion/control_aprobaciones_cicd.html", propuestas=propuestas)

@app.route('/aprobar_config/<nombre>', methods=["POST"])
@login_required
@csrf.exempt
def aprobar_config(nombre):
    path = os.path.join(PROPUESTAS_FOLDER, nombre)
    if not os.path.exists(path):
        flash("Archivo no encontrado", "error")
        return redirect(url_for("control_aprobaciones_cicd"))

    ip = request.form.get("ip")
    username = request.form.get("username")
    password = request.form.get("password")
    secret = request.form.get("secret", "").strip()

    if not ip or not username or not password:
        flash("Todos los campos del dispositivo son obligatorios.", "danger")
        return redirect(url_for("control_aprobaciones_cicd"))

    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret if secret else None,
        'global_delay_factor': 2,
        'timeout': 60,
    }

    try:
        with open(path) as f:
            comandos = f.read().splitlines()

        # Guardar configuración actual antes del cambio
        conn = ConnectHandler(**device)
        conn.enable()
        running_config = conn.send_command("show running-config")
        guardar_version(device, running_config)

        # Aplicar configuración propuesta
        resultado = conn.send_config_set(comandos)
        conn.disconnect()

        flash(f"Configuración aprobada y aplicada exitosamente.\nResultado:\n{resultado}", "success")
    except Exception as e:
        flash(f"Error al aplicar configuración: {str(e)}", "error")

    return redirect(url_for("control_aprobaciones_cicd"))

@app.route('/compatibilidad_multivendor', methods=["GET", "POST"])
@login_required
@csrf.exempt
def compatibilidad_multivendor():
    resultado = None
    error = None

    if request.method == "POST":
        vendor = request.form.get("vendor")  # Ej: ios, junos, eos, etc.
        ip = request.form.get("ip")
        username = request.form.get("username")
        password = request.form.get("password")
        secret = request.form.get("secret", "").strip()

        if not vendor or not ip or not username or not password:
            flash("Todos los campos son obligatorios", "danger")
        else:
            try:
                driver = get_network_driver(vendor)
                device = driver(hostname=ip, username=username, password=password, optional_args={'timeout': 60, 'secret': secret if secret else None})
                device.open()

                resultado = {
                    "facts": device.get_facts(),
                    "interfaces": device.get_interfaces(),
                    "config": device.get_config(),
                }

                device.close()
                flash("✅ Datos obtenidos exitosamente", "success")

            except Exception as e:
                error = f"❌ Error al conectar al dispositivo: {str(e)}"
                flash(error, "danger")
                traceback.print_exc()

    return render_template("automatizacion/compatibilidad_multivendor.html", resultado=resultado)

# --- Dashboard e Inteligencia Visual ---
@app.route('/estadisticas')
@login_required
def estadisticas():
    estadisticas_data = {}
    try:
        if os.path.exists("data/estadisticas.json") and os.path.getsize("data/estadisticas.json") > 0:
            with open("data/estadisticas.json") as f:
                estadisticas_data = json.load(f)
        else:
            flash("Archivo de estadísticas vacío o no encontrado.", "warning")
    except Exception as e:
        flash(f"Error al cargar estadísticas: {str(e)}", "error")
    
    return render_template("dashboard/estadisticas.html", data=estadisticas_data)
"""
@app.route('/estadisticas')
@login_required
def estadisticas():
    actualizado, error = actualizar_estadisticas()
    estadisticas_data = {}

    if error:
        flash(f"Error al actualizar estadísticas: {error}", "error")
    else:
        try:
            with open("data/estadisticas.json") as f:
                estadisticas_data = json.load(f)
        except Exception as e:
            flash(f"Error al cargar estadísticas: {str(e)}", "error")

    return render_template("dashboard/estadisticas2.html", data=estadisticas_data)
"""
@app.route('/alertas_tiempo_real')
@login_required
def alertas_tiempo_real():
    return render_template('dashboard/alertas_tiempo_real.html')

# Simular emisión de alerta desde backend
@app.route('/simular_alerta')
def simular_alerta():
    alerta = {
        "tipo": "Alerta NAC",
        "mensaje": "Dispositivo desconocido en VLAN crítica",
        "nivel": "alto"
    }
    socketio.emit('nueva_alerta', alerta, broadcast=True)
    return "Alerta enviada"

@app.route('/estado_red', methods=["GET", "POST"])
@login_required
@csrf.exempt
def estado_red():
    resultado = None
    error = None
    estado = {}

    if request.method == "POST":
        ip = request.form.get("ip")
        username = request.form.get("username")
        password = request.form.get("password")
        secret = request.form.get("secret")

        device = {
            'device_type': 'cisco_ios',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
            'timeout': 10
        }

        try:
            conn = ConnectHandler(**device)
            conn.enable()

            output_cpu = conn.send_command("show processes cpu")
            output_int = conn.send_command("show interfaces")
            output_ver = conn.send_command("show version")
            conn.disconnect()

            # Procesamiento básico
            cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', output_cpu)
            cpu_usage = cpu_match.group(1) if cpu_match else "N/A"

            interfaces_up = len(re.findall(r'(?<=line protocol is )up', output_int))
            interfaces_down = len(re.findall(r'(?<=line protocol is )down', output_int))

            estado = {
                "ip": ip,
                "cpu": cpu_usage,
                "int_up": interfaces_up,
                "int_down": interfaces_down,
                "raw_cpu": output_cpu[:300],
                "raw_ver": output_ver[:300]
            }

        except Exception as e:
            error = str(e)
            flash(f"Error conectando al dispositivo: {error}", "danger")

    return render_template("dashboard/estado_red.html", estado=estado)

@app.route('/topologia_dinamica', methods=["GET", "POST"])
@login_required
@csrf.exempt
def topologia_dinamica():
    nodos = []
    enlaces = []
    ip_origen = ""
    
    if request.method == "POST":
        ip = request.form.get("ip")
        username = request.form.get("username")
        password = request.form.get("password")
        secret = request.form.get("secret", "")

        device = {
            'device_type': 'cisco_ios',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
        }

        try:
            conn = ConnectHandler(**device)
            conn.enable()
            ip_origen = ip
            output = conn.send_command("show cdp neighbors detail")
            conn.disconnect()

            nodos.append({"id": ip, "label": ip, "group": "local"})

            neighbors = re.findall(r"Device ID: (.+?)\n.*?IP address: ([\d\.]+)", output, re.DOTALL)

            for nombre, ip_vecino in neighbors:
                nodos.append({"id": ip_vecino, "label": nombre, "group": "vecino"})
                enlaces.append({"from": ip, "to": ip_vecino})

        except Exception as e:
            flash(f"Error al obtener topología: {str(e)}", "danger")

    return render_template("dashboard/topologia_dinamica.html", nodos=nodos, enlaces=enlaces, origen=ip_origen)

# --- Reportes Automatizados ---
@app.route('/reportes_pdf', methods=["GET", "POST"])
@login_required
@csrf.exempt
def reportes_pdf():
    autor_id=Usuario.query.get(session['usuario_id'])
    print(autor_id)
    if request.method == "POST":
        titulo = request.form.get("titulo", "Reporte de Red")
        contenido = request.form.get("contenido", "")
#        autor = session.get("usuario_usuario")
        autor = request.form.get("autor", "Sistema")
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M")
        print(autor)
        rendered = render_template("reportes/pdf_template.html", titulo=titulo, contenido=contenido, autor=autor_id, fecha=fecha)
        output_path = f"temp/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        HTML(string=rendered).write_pdf(output_path)

        return send_file(output_path, as_attachment=True)

    return render_template("reportes/reportes_pdf.html", autor=autor_id)

@app.route('/reportes_xls', methods=["GET", "POST"])
@login_required
@csrf.exempt
def reportes_xls():
    if request.method == "POST":
        tipo = request.form.get("tipo_reporte", "resumen")
        fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reporte_{tipo}_{fecha}.xlsx"
        filepath = os.path.join("temp", filename)

        # Simulación de datos, reemplazar con datos reales según tipo
        if tipo == "backups":
            data = [
                {"IP": "192.168.1.1", "Fecha": "2025-07-09", "Archivo": "backup_192_168_1_1.txt"},
                {"IP": "192.168.1.2", "Fecha": "2025-07-09", "Archivo": "backup_192_168_1_2.txt"},
            ]
        elif tipo == "estado_red":
            data = [
                {"IP": "192.168.1.1", "CPU %": 10, "Interfaces UP": 3, "Interfaces DOWN": 1},
                {"IP": "192.168.1.2", "CPU %": 17, "Interfaces UP": 5, "Interfaces DOWN": 0},
            ]
        elif tipo == "alertas":
            data = [
                {"Hora": "10:00", "Tipo": "NAC", "Descripción": "Dispositivo sospechoso en VLAN"},
                {"Hora": "11:15", "Tipo": "Configuración", "Descripción": "Cambio no aprobado"},
            ]
        else:
            data = [{"Mensaje": "Este es un reporte de ejemplo generado exitosamente."}]

        df = pd.DataFrame(data)
        df.to_excel(filepath, index=False)

        return send_file(filepath, as_attachment=True)

    return render_template("reportes/reportes_xls.html")

@app.route('/notificaciones_programadas')
def notificaciones_programadas():
    return render_template('reportes/notificaciones_programadas.html')

@app.route('/api/backups', methods=["GET"])
@login_required
@csrf.exempt
def api_backups():
    usuario_id = session.get('usuario_id')
    usuario_nombre = session.get('usuario_nombre', 'Usuario')  # o como guardes el nombre

    backups = [
        {"ip": "192.168.1.1", "archivo": "backup_192_168_1_1.txt", "fecha": "2025-07-09"},
        {"ip": "192.168.1.2", "archivo": "backup_192_168_1_2.txt", "fecha": "2025-07-09"},
    ]
    return jsonify({"usuario_id": usuario_id, "usuario": usuario_nombre, "backups": backups})


@app.route('/api/estado_red', methods=["GET"])
@login_required
@csrf.exempt
def api_estado_red():
    estado = [
        {"ip": "192.168.1.1", "cpu": 12, "int_up": 3, "int_down": 1},
        {"ip": "192.168.1.2", "cpu": 8, "int_up": 5, "int_down": 0}
    ]
    return jsonify({"estado_red": estado})

@app.route('/api/alertas', methods=["GET"])
@login_required
@csrf.exempt
def api_alertas():
    alertas = [
        {"hora": "10:00", "tipo": "NAC", "descripcion": "MAC desconocida en VLAN 10"},
        {"hora": "11:15", "tipo": "Configuración", "descripcion": "Cambio no aprobado"},
    ]
    return jsonify({"alertas": alertas})

@app.route('/api_consultas')
def api_consultas():
    return render_template('reportes/api_consultas.html')

@app.route('/indicadores_cumplimiento', methods=["GET", "POST"])
@login_required
@csrf.exempt
def indicadores_cumplimiento():
    # Checklist base por norma
    normas = {
        "PCI-DSS": [
            "Uso de contraseñas seguras y autenticación multifactor",
            "Registro y monitoreo de accesos",
            "Segmentación de redes y controles de firewall",
        ],
        "GDPR": [
            "Consentimiento explícito para recolección de datos",
            "Acceso restringido a información personal",
            "Cifrado de datos sensibles",
        ],
        "NIST": [
            "Control de acceso lógico",
            "Planes de respuesta a incidentes",
            "Auditoría y monitoreo continuo",
        ]
    }

    cumplimiento = {}
    if request.method == "POST":
        for norma, items in normas.items():
            cumplimiento[norma] = []
            for idx, item in enumerate(items):
                clave = f"{norma}_{idx}"
                estado = request.form.get(clave) == "on"
                cumplimiento[norma].append({"descripcion": item, "cumple": estado})
        flash("Evaluación de cumplimiento registrada", "success")

    return render_template("reportes/indicadores_cumplimiento.html", normas=normas)

# --- Extras y Funcionalidades Futuras ---
@app.route('/soporte_ztna', methods=["GET"])
@login_required
@csrf.exempt
def soporte_ztna():
    usuario = session.get("usuario_usuario")
    return render_template('extras/soporte_ztna.html', usuario=usuario)

@app.route('/ia_reglas_expertas', methods=["GET", "POST"])
@login_required
@csrf.exempt
def ia_reglas_expertas():
    sugerencias = []

    if request.method == "POST":
        tipo = request.form.get("tipo_dispositivo")
        estado = request.form.get("estado_config")

        # Reglas simples de ejemplo
        if tipo == "router" and "sin_ntp" in estado:
            sugerencias.append("Configura un servidor NTP para sincronización de reloj.")
        if tipo == "switch" and "puertos_abiertos" in estado:
            sugerencias.append("Considera deshabilitar puertos no utilizados para reducir superficie de ataque.")
        if "sin_banner" in estado:
            sugerencias.append("Agrega un banner de advertencia legal en accesos remotos.")
        if tipo == "router" and "bgp_mal_configurado" in estado:
            sugerencias.append("Verifica la configuración de BGP, ASN y vecinos.")

    return render_template('extras/ia_reglas_expertas.html', sugerencias=sugerencias)

@app.route('/simulador_configuracion', methods=["GET", "POST"])
@login_required
@csrf.exempt
def simulador_configuracion():
    advertencias = []
    comandos = ""

    if request.method == "POST":
        comandos = request.form.get("comandos", "")
        lineas = comandos.strip().splitlines()

        for linea in lineas:
            l = linea.strip().lower()
            if l.startswith("username") and "secret" not in l:
                advertencias.append("El usuario debe definirse con 'secret' en lugar de 'password'.")
            if "telnet" in l:
                advertencias.append("Evita usar Telnet. Usa SSH para acceso remoto seguro.")
            if l.startswith("enable password"):
                advertencias.append("Evita 'enable password'. Usa 'enable secret' para mayor seguridad.")
            if "no service password-encryption" in l:
                advertencias.append("Activa la encriptación de contraseñas con 'service password-encryption'.")

    return render_template("extras/simulador_configuracion.html", comandos=comandos, advertencias=advertencias)

@app.route('/modo_sandbox', methods=["GET", "POST"])
@login_required
@csrf.exempt
def modo_sandbox():
    salida_simulada = ""
    comandos = ""

    # Diccionario de respuestas simuladas
    simulador = {
        "show running-config": "version 15.2\nhostname Router\ninterface Gig0/0\n ip address 192.168.1.1 255.255.255.0",
        "show ip interface brief": "Interface       IP-Address     OK? Method Status     Protocol\nGig0/0          192.168.1.1    YES manual up        up",
        "show interfaces": "GigabitEthernet0/0 is up, line protocol is up\n  Hardware is Gigabit Ethernet, address is aabb.cc00.1122"
    }

    if request.method == "POST":
        comandos = request.form.get("comandos", "")
        lines = comandos.strip().splitlines()

        resultado = []
        for cmd in lines:
            respuesta = simulador.get(cmd.strip().lower(), f"% Comando no reconocido: {cmd}")
            resultado.append(f"{cmd}\n{respuesta}")

        salida_simulada = "\n\n".join(resultado)

    return render_template("extras/modo_sandbox.html", comandos=comandos, salida_simulada=salida_simulada)

@app.route('/motor_scripting_eventos', methods=["GET", "POST"])
@login_required
@csrf.exempt
def motor_scripting_eventos():
    eventos_disponibles = [
        "Dispositivo conectado",
        "Violación de política de acceso",
        "Fallo de ping/SNMP",
        "Cambio no autorizado",
        "Login sospechoso"
    ]

    resultado = None

    if request.method == "POST":
        evento = request.form.get("evento")
        script = request.form.get("script")

        # Simulación de ejecución (no se ejecuta código real por seguridad)
        resultado = f"📝 Script asociado al evento '{evento}' ha sido registrado.\n\n📜 Código:\n{script}"

        # Aquí puedes almacenar el script en base de datos o archivo

    return render_template("extras/motor_scripting_eventos.html", eventos=eventos_disponibles, resultado=resultado)

if __name__ == "__main__":
    #socketio.run(app, debug=True, host="0.0.0.0", port=5000)
    app.run(debug=True, host='0.0.0.0')
