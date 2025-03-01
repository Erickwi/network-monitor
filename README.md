# Network Monitor

Si no se tiene los siguientes paquetes se los debe instalar:
```bash  
pip install flask scapy requests sqlite3
```

## Ejecutar la app
Se debe abrir 2 terminales y ejecutar
```bash
sudo python capture.py
```
```bash
sudo python app.py
```

## Uso
1. Abre tu navegador web y navega a http://localhost:5000    
2. Utiliza la interfaz web para iniciar y detener la captura de paquetes, generar reportes y filtrar eventos.

## Pruebas con pytest
Si no tienes pytest instalado, puedes instalarlo usando pip:
```bash
sudo pip install pytest
```

### Ejecutar las pruebas
Ve al directorio raiz del proyecto y ejecuta el comando
```bash
pytest
```

> [!NOTE]
> Para que las pruebas sean un exito se debe tener corriendo las 2 apps tanto `app.py` y `capture.py`
