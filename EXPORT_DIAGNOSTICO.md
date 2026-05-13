# Diagnóstico del Botón de Exportación

Si el botón de exportación no funciona, sigue estos pasos para diagnosticar el problema:

## Paso 1: Verificar que completaste un escaneo
- ✅ Asegúrate de que el escaneo haya COMPLETADO exitosamente
- ✅ Deberías ver "Escaneo completado" o "HECHO" en la interfaz
- ✅ No intentes exportar mientras el escaneo esté en progreso

## Paso 2: Abrir la Consola del Navegador
1. Presiona **F12** (o Cmd+Opt+I en Mac)
2. Ve a la pestaña **"Console"**

## Paso 3: Ejecutar el Diagnóstico
Copia y pega este comando en la consola:

```javascript
_debugExport()
```

Presiona Enter. Deberías ver algo como:

```
=== DIAGNÓSTICO DE EXPORTACIÓN ===
currentJobId: abc123def456
currentResult: {Object}
Botón exportar: <button...>
Botón visible: true
Menú exportar: <div...>
Menú display: none
toggleExportMenu función: function
_triggerDownload función: function
showToast función: function
_dlUrl función: function
✅ Job ID disponible - Exportación debería funcionar
```

## Paso 4: Interpretar los Resultados

### Caso 1: `currentJobId: null` o `undefined`
**Problema:** No hay escaneo activo
**Solución:** Completa un escaneo primero

### Caso 2: `Botón visible: false`
**Problema:** El botón está oculto por CSS
**Solución:** Revisar estilos CSS en `static/app.css`

### Caso 3: `Menú display: none` (pero existe)
**Problema:** El menú existe pero no se abre
**Solución:** 
- Presiona el botón y ejecuta `_debugExport()` de nuevo
- El display debería cambiar a `block` si funciona

### Caso 4: Todo se ve correcto pero el botón no responde
**Pasos adicionales:**
1. Abre la **pestaña Network** en DevTools
2. Presiona el botón de exportación
3. Busca una petición HTTP a `/scan/{jobId}/pdf` (o el formato que intentes)
4. Si no hay petición, hay un problema JavaScript
5. Si hay petición pero falla, hay un problema en el backend

## Paso 5: Verificar Errors en la Consola
Busca mensajes rojos (errors) en la consola que comiencen con:
- `[Export]`
- `[Download]`

Esos logs te dirán exactamente dónde está el problema.

## Paso 6: Probar Manualmente
Si todo parece estar bien, intenta esto en la consola:

```javascript
// Verificar que currentJobId existe
console.log('Job ID:', currentJobId);

// Intentar descargar el PDF manualmente
_triggerDownload(`/scan/${currentJobId}/pdf`, 'test.pdf');
```

## Contacto / Reporte de Bugs
Si después de estos pasos aún no funciona:
1. Toma una captura de pantalla de la consola completa
2. Ejecuta `_debugExport()` y copia el resultado
3. Abre un issue en GitHub con esta información

## Cambios Realizados (1 de mayo 2026)

✅ Corregida función `toggleExportMenu()` - mejor detección de estado
✅ Mejorados mensajes de error en todas las funciones de exportación
✅ Agregado logging detallado para debugging
✅ Mejorado `_triggerDownload()` con mejor error handling
✅ Agregada función `_debugExport()` para diagnosticar problemas
✅ Agregadas rutas backend para Markdown y SARIF
✅ Creadas funciones de generación para Markdown, SARIF y HTML

## Soportados Formatos de Exportación

| Formato | Estado | Función |
|---------|--------|---------|
| PDF Técnico | ✅ | `/scan/{id}/pdf` |
| PDF Ejecutivo | ✅ | `/scan/{id}/executive-pdf` |
| Excel | ✅ | `/scan/{id}/excel` |
| CSV | ✅ | `/scan/{id}/csv` |
| JSON | ✅ | `/scan/{id}/json` |
| HTML | ✅ | `/scan/{id}/html` |
| Markdown | ✅ | `/scan/{id}/markdown` |
| SARIF | ✅ | `/scan/{id}/sarif` |
