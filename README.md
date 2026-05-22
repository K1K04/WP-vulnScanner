#  WP-VulnScanner

> Escáner de seguridad profesional para WordPress — detección pasiva de vulnerabilidades, CVEs, plugins, temas y mucho más.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![CVEs](https://img.shields.io/badge/CVEs-1.284+-red?style=flat-square)

---

##  Características

| Módulo | Descripción |
|---|---|
|  **Detección WP** | Identifica versión, plugins, temas y configuración |
|  **BD Local CVE** | 1.284+ CVEs actualizados desde NVD, WPScan, Patchstack |
|  **EPSS scoring** | Probabilidad de explotación por CVE |
|  **CISA KEV** | Marca vulnerabilidades activamente explotadas |
|  **TLS / SSL** | Análisis completo del certificado y cifrados |
|  **CORS detection** | Detecta configuraciones incorrectas de CORS |
|  **User enumeration** | Enumeración avanzada de usuarios WordPress |
|  **Backup file scan** | Busca ficheros de backup expuestos |
|  **WooCommerce scan** | Detección específica de vulnerabilidades WooCommerce |
|  **REST API audit** | Auditoría completa de rutas y autenticación REST |
|  **GraphQL detection** | Detecta endpoints GraphQL expuestos |
|  **Shodan / DNS / WHOIS** | Reconocimiento pasivo completo |
|  **Wayback Machine** | Historial de exposición pública |
|  **AI Remediation Plan** | Plan de remediación generado por IA |
|  **AI Security Chat** | Chat con contexto completo del escaneo |
|  **Exportación** | PDF, Excel, CSV, SARIF, JSON, HTML, Markdown |
|  **Webhooks** | Alertas a Slack, Discord y Microsoft Teams |
|  **Escaneos programados** | Scheduler con expresiones cron |
|  **GDPR / PCI-DSS** | Análisis de cumplimiento normativo |
|  **Historial** | Historial de escaneos con búsqueda y comparador |

---

##  Uso rápido con Docker

La forma más sencilla de arrancar WP VulnScanner es con Docker, sin necesidad de instalar dependencias.

**Docker Hub:** [hub.docker.com/r/kiko4/wpvulnscan](https://hub.docker.com/r/kiko4/wpvulnscan)

```bash
# Descargar la imagen
docker pull kiko4/wpvulnscan

# Arrancar el contenedor
docker run -d \
  -p 5000:5000 \
  --name wpvulnscan \
  kiko4/wpvulnscan
```

Abre el navegador en `http://localhost:5000` y empieza a escanear.

### Con variables de entorno

```bash
docker run -d \
  -p 5000:5000 \
  --name wpvulnscan \
  -e WPSCAN_API_KEY=tu_api_key \
  -e OPENAI_API_KEY=tu_openai_key \
  -e SECRET_KEY=cambia_esto \
  kiko4/wpvulnscan
```

### Con docker-compose

```yaml
version: "3.9"
services:
  wpvulnscan:
    image: kiko4/wpvulnscan
    ports:
      - "5000:5000"
    environment:
      - WPSCAN_API_KEY=tu_api_key
      - OPENAI_API_KEY=tu_openai_key
      - SECRET_KEY=cambia_esto
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

```bash
docker-compose up -d
```

---

##  Instalación local

### Requisitos

- Python 3.11+
- pip
- (Opcional) WPScan, Nmap, Nikto para módulos avanzados

### Pasos

```bash
# 1. Clonar el repositorio
git clone git@github.com:K1K04/WP-vulnScanner.git
cd WP-vulnScanner

# 2. Crear entorno virtual
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
nano .env  # edita con tus API keys

# 5. Arrancar
python app.py
```

Abre `http://localhost:5000`

---

##  Configuración

Copia `.env.example` a `.env` y configura:

```env
SECRET_KEY=cambia_esto_por_algo_seguro

# API Keys opcionales (amplían la detección)
WPSCAN_API_KEY=
OPENAI_API_KEY=
SHODAN_API_KEY=

# Configuración del servidor
HOST=0.0.0.0
PORT=5000
DEBUG=false
```

---

##  Capturas

```
┌─────────────────────────────────────────┐
│  WP VulnScanner                         │
│                                         │
│  https://ejemplo.com        [ESCANEAR]  │
│                                         │
│  ✓ CISA KEV  ✓ EPSS  ✓ 1.284 CVEs      │
│  ✓ GDPR/PCI  ✓ TLS   ✓ AI Remediation  │
└─────────────────────────────────────────┘
```

---

##  Webhooks

Recibe alertas automáticas cuando un escaneo detecta vulnerabilidades críticas:

- **Slack** — mensaje con resumen y risk score
- **Discord** — embed con severidad y CVEs
- **Microsoft Teams** — card adaptativa

Configúralos en la interfaz web → Settings → Webhooks.

---

##  Formatos de exportación

Desde la interfaz, después de un escaneo puedes exportar:

| Formato | Uso |
|---|---|
| **PDF** | Informe ejecutivo para clientes |
| **Excel** | Análisis de vulnerabilidades en hoja de cálculo |
| **CSV** | Integración con otras herramientas |
| **SARIF** | Integración con GitHub Code Scanning |
| **JSON** | API / automatización |
| **HTML** | Informe autocontenido |
| **Markdown** | Documentación técnica |

---

##  Contribuir

1. Haz fork del repositorio
2. Crea una rama: `git checkout -b feature/mi-mejora`
3. Commit: `git commit -m "Añade mi mejora"`
4. Push: `git push origin feature/mi-mejora`
5. Abre un Pull Request

---

##  Aviso legal

Esta herramienta está diseñada para uso **ético y autorizado**. Úsala únicamente en sitios web sobre los que tengas permiso explícito. El autor no se responsabiliza del uso indebido.

---

## 📄 Licencia

MIT © [K1K04](https://github.com/K1K04)