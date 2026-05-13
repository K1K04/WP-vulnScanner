# Prueba del Botón de Exportar

## Pasos para verificar que el botón funciona:

1. **Abre la aplicación** en tu navegador (ej: `http://localhost:8080`)

2. **Completa un escaneo**:
   - Ingresa una URL
   - Presiona "Nuevo" o "Scan"
   - Espera a que termine

3. **Presiona el botón "Exportar ▾"**
   - Debe abrirse un menú desplegable con opciones
   - Si no se abre, abre la consola (F12) y revisa si hay errores

## Diagnóstico si no funciona:

### Opción 1: Abre la consola del navegador (F12)
1. Ve a **Console** (Consola)
2. Ejecuta: `toggleExportMenu()`
3. Debe aparecer un log que diga `[Export] Menu toggled:`
4. El menú debe abrirse/cerrarse visualmente

### Opción 2: Verifica que el menú existe
En la consola, ejecuta:
```javascript
document.getElementById('exportMenu')
```
Si devuelve un elemento, está en el DOM.

### Opción 3: Verifica el estado actual
En la consola, ejecuta:
```javascript
window._debugExport()
```

Esto mostrará:
- Si `currentJobId` está definido (necesario para exportar)
- Si el menú existe en el DOM
- Si el botón está visible

## Formatos de exportación disponibles:

| Formato | Descripción |
|---------|-------------|
| PDF Técnico | Reporte detallado con vulnerabilidades |
| PDF Ejecutivo | Resumen ejecutivo sin detalles técnicos |
| Excel | Hoja de cálculo con todos los datos |
| CSV | Formato de valores separados por comas |
| JSON | Formato JSON con todos los datos |
| HTML | Página HTML autocontendida |
| Markdown | Formato Markdown para wikis |
| SARIF | GitHub Advanced Security / GitLab SAST |

## Solución rápida si nada funciona:

1. **Recarga la página**: `Ctrl+Shift+R` (recarga completa, borra cache)
2. **Limpia localStorage**:
   - Abre DevTools (F12)
   - Ve a Application → Storage → Local Storage
   - Elimina todo
   - Recarga la página

3. **Si aún no funciona**: Revisa los logs del servidor en la terminal
