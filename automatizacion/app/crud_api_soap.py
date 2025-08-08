from zeep import Client
from zeep.exceptions import Fault

WSDL_URL = 'http://localhost:5000/soap/?wsdl'

client = Client(WSDL_URL)

def menu():
    print("\nMENÚ CRUD API SOAP (Dispositivos)")
    print("1. Crear nuevo dispositivo")
    print("2. Consultar dispositivo por ID")
    print("3. Actualizar ubicación de dispositivo")
    print("4. Eliminar dispositivo")
    print("5. Consultar todos los dispositivos ")
    print("6. Salir")

def crear_dispositivo():
    print("\nCrear nuevo dispositivo")
    nombre = input("Nombre: ")
    ip = input("IP: ")
    tipo = input("Tipo (ej. cisco_ios): ")
    ubicacion = input("Ubicación: ")

    try:
        respuesta = client.service.addDispositivo(nombre, ip, tipo, ubicacion)
        print("", respuesta)
    except Fault as f:
        print(" Error SOAP:", f)

def consultar_dispositivo():
    print("\n Consultar dispositivo por ID")
    try:
        id = int(input("ID: "))
        respuesta = client.service.getDispositivo(id)
        print("ℹ", respuesta)
    except ValueError:
        print(" ID inválido")
    except Fault as f:
        print(" Error SOAP:", f)

def actualizar_ubicacion():
    print("\n Actualizar ubicación de dispositivo")
    try:
        id = int(input("ID: "))
        nueva_ubicacion = input("Nueva ubicación: ")
        respuesta = client.service.updateUbicacion(id, nueva_ubicacion)
        print("", respuesta)
    except ValueError:
        print(" ID inválido")
    except Fault as f:
        print(" Error SOAP:", f)

def eliminar_dispositivo():
    print("\n Eliminar dispositivo por ID")
    try:
        id = int(input("ID: "))
        confirmar = input(f"¿Seguro que quieres eliminar el dispositivo {id}? (s/n): ")
        if confirmar.lower() == 's':
            respuesta = client.service.deleteDispositivo(id)
            print("", respuesta)
        else:
            print(" Cancelado.")
    except ValueError:
        print(" ID inválido")
    except Fault as f:
        print(" Error SOAP:", f)

def listar_todos():
    print("\nLista de dispositivos:")
    try:
        lista = client.service.getAllDispositivos()
        for d in lista:
            print("•", d)
    except Exception as e:
        print(" Error al obtener dispositivos:", str(e))


def main():
    while True:
        menu()
        opcion = input("Selecciona una opción: ")

        if opcion == '1':
            crear_dispositivo()
        elif opcion == '2':
            consultar_dispositivo()
        elif opcion == '3':
            actualizar_ubicacion()
        elif opcion == '4':
            eliminar_dispositivo()
        elif opcion == '5':
            listar_todos()
            
        elif opcion == '6':
            print(" Saliendo...")
            break
        else:
            print(" Opción no válida")

if __name__ == '__main__':
    main()
