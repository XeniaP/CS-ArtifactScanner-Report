# Guía de Usuario para export_report_tmas.exe

## Introducción

`export_report_tmas.exe` es una herramienta diseñada para facilitar la generación de informes basados en los resultados de análisis de vulnerabilidades y malware. Esta guía proporciona instrucciones detalladas sobre cómo ejecutar el programa y obtener los informes deseados.

## Requisitos

- Sistema Operativo Windows.
- Tener permisos adecuados para ejecutar archivos `.exe` en tu sistema.
- La ruta al archivo de resultados JSON debe ser accesible.

## Descarga e Instalación

1. Descarga `export_report_tmas.exe` desde la sección de Releases de nuestro repositorio de GitHub ([URL_DEL_REPOSITORIO](URL_DEL_REPOSITORIO)).
2. Guarda el archivo en una ubicación segura en tu sistema.

## Uso Básico

Para usar `export_report_tmas.exe`, sigue estos pasos:

1. **Abrir la Línea de Comandos (CMD) o PowerShell**:
   - Puedes hacer esto buscando "cmd" o "PowerShell" en el menú de inicio.

2. **Navegar hasta la Ubicación del Archivo**:
   - Utiliza el comando `cd` para cambiar al directorio donde está `export_report_tmas.exe`.
   - Por ejemplo: `cd path/to/directory`.

3. **Ejecutar el Comando**:
   - Escribe el siguiente comando:
     ```
     .\export_report_tmas.exe [nombre_imagen] --resultFile [ruta_al_archivo_json]
     ```
   - Reemplaza `[nombre_imagen]` con el nombre de tu imagen y `[ruta_al_archivo_json]` con la ruta completa al archivo JSON de resultados.
   - Ejemplo:
     ```
     .\export_report_tmas.exe test --resultFile d:/Github/bigDockerApp/result-eicar.json
     ```

## Parámetros del Comando

- `nombre_imagen`: Nombre descriptivo para la imagen que estás analizando.
- `--resultFile`: Indica que se utilizará un archivo de resultados existente.
- `ruta_al_archivo_json`: Ruta completa al archivo JSON que contiene los resultados del análisis.

## Salida

Al ejecutar el comando, se generará un informe basado en los datos del archivo JSON proporcionado. El informe se guardará en el mismo directorio donde se ejecuta el comando, a menos que se especifique una ruta diferente.

## Soporte

Si encuentras problemas o tienes preguntas sobre el uso de `export_report_tmas.exe`, por favor, contacta al equipo de soporte en [correo@soporte.com](mailto:correo@soporte.com).
