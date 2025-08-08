import requests

BASE_URL = "http://localhost:5000/api/dispositivos"

def menu():
    print("\n--- MENÚ CRUD DE DISPOSITIVOS ---")
    print("1. Listar todos los dispositivos")
    print("2. Consultar dispositivo por ID")
    print("3. Agregar nuevo dispositivo")
    print("4. Editar dispositivo existente")
    print("5. Eliminar dispositivo")
    print("6. Salir")

def listar_todos():
    r = requests.get(BASE_URL)
    if r.status_code == 200:
        for d in r.json():
            print(f"ID: {d['id']}, Nombre: {d['nombre']}, IP: {d['ip']}, Estado: {d['estado']}")
    else:
        print("Error al obtener dispositivos.")

def consultar_por_id():
    id = input("ID del dispositivo: ")
    r = requests.get(f"{BASE_URL}/{id}")
    if r.status_code == 200:
        d = r.json()
        print(f"\nNombre: {d['nombre']}\nIP: {d['ip']}\nUbicación: {d['ubicacion']}\nEstado: {d['estado']}")
    else:
        print("Dispositivo no encontrado.")

def agregar_dispositivo():
    print("\n--- Agregar Nuevo Dispositivo ---")
    data = {
        "nombre": input("Nombre: "),
        "ip": input("IP: "),
        "tipo": input("Tipo (ej. cisco_ios): "),
        "ubicacion": input("Ubicación: "),
        "username": input("Usuario: "),
        "contrasenia": input("Contraseña: "),
        "enable_secret": input("Enable secret: "),
        "estado": input("Estado (activo, cuarentena, bloqueado): ")
    }
    r = requests.post(BASE_URL, json=data)
    if r.status_code == 201:
        print("Dispositivo agregado con ID:", r.json()['id'])
    else:
        print("Error al agregar dispositivo:", r.text)

def editar_dispositivo():
    id = input("ID del dispositivo a editar: ")
    r = requests.get(f"{BASE_URL}/{id}")
    if r.status_code != 200:
        print("Dispositivo no encontrado.")
        return

    actual = r.json()
    print("\n--- Editar Dispositivo (presiona Enter para dejar igual) ---")
    data = {
        "nombre": input(f"Nombre [{actual['nombre']}]: ") or actual['nombre'],
        "ip": input(f"IP [{actual['ip']}]: ") or actual['ip'],
        "tipo": input(f"Tipo [{actual['tipo']}]: ") or actual['tipo'],
        "ubicacion": input(f"Ubicación [{actual['ubicacion']}]: ") or actual['ubicacion'],
        "estado": input(f"Estado [{actual['estado']}]: ") or actual['estado'],
    }

    r = requests.put(f"{BASE_URL}/{id}", json=data)
    if r.status_code == 200:
        print("Dispositivo actualizado.")
    else:
        print("Error al actualizar:", r.text)

def eliminar_dispositivo():
    id = input("ID del dispositivo a eliminar: ")
    confirm = input(f"¿Estás seguro de eliminar el dispositivo {id}? (s/n): ")
    if confirm.lower() != 's':
        print("Cancelado.")
        return

    r = requests.delete(f"{BASE_URL}/{id}")
    if r.status_code == 200:
        print("Dispositivo eliminado.")
    else:
        print("Error al eliminar:", r.text)

def main():
    while True:
        menu()
        opcion = input("Selecciona una opción: ")

        if opcion == '1':
            listar_todos()
        elif opcion == '2':
            consultar_por_id()
        elif opcion == '3':
            agregar_dispositivo()
        elif opcion == '4':
            editar_dispositivo()
        elif opcion == '5':
            eliminar_dispositivo()
        elif opcion == '6':
            print("Saliendo...")
            break
        else:
            print("Opción inválida")

if __name__ == '__main__':
    main()
