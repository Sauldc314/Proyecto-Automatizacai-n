import os
import json
from datetime import datetime

ESTADISTICAS_FILE = "data/estadisticas.json"
LISTA_BLANCA = "data/lista_blanca.json"
REGISTROS = "data/registros.json"
USUARIOS_LOG = "data/usuarios_log.json"  # opcional

def actualizar_estadisticas():
    try:
        # Inicializar estructuras
        if os.path.exists(ESTADISTICAS_FILE):
            with open(ESTADISTICAS_FILE) as f:
                data = json.load(f)
        else:
            data = {"usuarios": {}, "resumen": {}}

        registros = []
        if os.path.exists(REGISTROS):
            with open(REGISTROS) as f:
                registros = json.load(f)

        lista_blanca = []
        if os.path.exists(LISTA_BLANCA):
            with open(LISTA_BLANCA) as f:
                lista_blanca = json.load(f)

        # Conteo general
        total_dispositivos = len(registros)
        total_autorizados = len([
            r for r in registros
            if r["mac"].lower() in {d["mac"].lower() for d in lista_blanca}
        ])

        riesgos = {"critico": 0, "medio": 0, "bajo": 0}
        for r in registros:
            nivel = r.get("nivel_riesgo", "medio")
            if nivel == "critico":
                riesgos["critico"] += 1
            elif nivel == "medio":
                riesgos["medio"] += 1
            else:
                riesgos["bajo"] += 1

        usuarios_log = {}
        if os.path.exists(USUARIOS_LOG):
            with open(USUARIOS_LOG) as f:
                usuarios_log = json.load(f)

        # Resumen
        data["resumen"] = {
            "total_dispositivos": total_dispositivos,
            "total_autorizados": total_autorizados,
            "total_anomalos": total_dispositivos - total_autorizados,
            "riesgos": riesgos,
            "total_usuarios": len(usuarios_log)
        }

        # Detalles por usuario (si se usa logging de acciones)
        data["usuarios"] = usuarios_log

        with open(ESTADISTICAS_FILE, "w") as f:
            json.dump(data, f, indent=2)

        return True, None

    except Exception as e:
        return False, str(e)
