CREATE DATABASE if not exists noxtify;

USE noxtify;


CREATE TABLE rol (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(20) UNIQUE NOT NULL
);

CREATE TABLE usuario (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(20) UNIQUE NOT NULL,
    nombre VARCHAR(50) NOT NULL,
    apellido VARCHAR(50) NOT NULL,
    correo VARCHAR(100) UNIQUE NOT NULL,
    contrasenia VARCHAR(200) NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    rol_id INT,
    FOREIGN KEY (rol_id) REFERENCES rol(id)
);

CREATE TABLE dispositivo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL,
    ip VARCHAR(15) UNIQUE NOT NULL,
    tipo VARCHAR(30) DEFAULT 'cisco_ios',
    ubicacion VARCHAR(100),
    username VARCHAR(50),
    contrasenia VARCHAR(200),
    enable_secret VARCHAR(200),
    estado VARCHAR(20) DEFAULT 'activo',
    fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE configuracion_backup (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dispositivo_id INT,
    contenido TEXT,
    fecha_backup DATETIME DEFAULT CURRENT_TIMESTAMP,
    usuario_id INT,
    FOREIGN KEY (dispositivo_id) REFERENCES dispositivo(id),
    FOREIGN KEY (usuario_id) REFERENCES usuario(id_usuario)
);

CREATE TABLE enlace (
    id INT AUTO_INCREMENT PRIMARY KEY,
    origen_id INT,
    destino_id INT,
    tipo VARCHAR(30),
    latencia FLOAT,
    ancho_banda FLOAT,
    FOREIGN KEY (origen_id) REFERENCES dispositivo(id),
    FOREIGN KEY (destino_id) REFERENCES dispositivo(id)
);

CREATE TABLE acceso_permitido (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    ip_autorizada VARCHAR(45),
    mac_autorizada VARCHAR(50),
    descripcion VARCHAR(100),
    fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuario(id_usuario)
);

CREATE TABLE log_actividad (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    accion VARCHAR(200),
    resultado VARCHAR(100),
    ip_dispositivo VARCHAR(15),
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuario(id_usuario)
);

CREATE TABLE escaneo_vulnerabilidad (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dispositivo_id INT,
    tipo VARCHAR(50),
    resultado TEXT,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dispositivo_id) REFERENCES dispositivo(id)
);

CREATE TABLE reporte (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(50),
    archivo VARCHAR(100),
    fecha_generacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    generado_por INT,
    FOREIGN KEY (generado_por) REFERENCES usuario(id_usuario)
);

CREATE TABLE alerta (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(50),
    mensaje VARCHAR(200),
    nivel VARCHAR(20),
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    leido BOOLEAN DEFAULT FALSE
);

CREATE TABLE tarea_programada (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100),
    tipo VARCHAR(50),
    dispositivo_id INT,
    frecuencia VARCHAR(50),
    estado VARCHAR(20) DEFAULT 'pendiente',
    ultima_ejecucion DATETIME,
    proxima_ejecucion DATETIME,
    FOREIGN KEY (dispositivo_id) REFERENCES dispositivo(id)
);

CREATE TABLE cambio_configuracion (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dispositivo_id INT,
    realizado_por INT,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    diff TEXT,
    FOREIGN KEY (dispositivo_id) REFERENCES dispositivo(id),
    FOREIGN KEY (realizado_por) REFERENCES usuario(id_usuario)
);
