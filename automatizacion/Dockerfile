# Usar la imagen oficial de Python
FROM python:3.10

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Copiar los archivos del proyecto
COPY app /app
COPY requirements.txt /app/
#sudo apt install libpangocairo-1.0-0 libpangoft2-1.0-0 libffi-dev libcairo2
# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto 5000
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]
