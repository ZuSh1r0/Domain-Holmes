# 🔍 Domain Holmes — Herramienta OSINT

Herramienta Python para análisis integral de dominios sospechosos.
Combina múltiples APIs OSINT y verificaciones nativas para generar
un reporte visual y didáctico directamente en la terminal.

---

## 📦 Instalación

```bash
# 1. Clonar o descargar los archivos
cd Domain-Holmes/

# 2. (Recomendado) Crear entorno virtual
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
```

---

## 🔑 Configuración de API Keys

Copia el archivo de ejemplo y rellena tus claves:

```bash
cp config.ini.example config.ini
# Edita config.ini con tus claves
```

O exporta como variables de entorno:

```bash
export VIRUSTOTAL_API_KEY="tu_clave"
export ABUSEIPDB_API_KEY="tu_clave"
export URLSCAN_API_KEY="tu_clave"       # opcional
export SHODAN_API_KEY="tu_clave"
```

### Dónde obtener cada clave (todas gratuitas):

| API | URL | Límite gratuito |
|-----|-----|----------------|
| VirusTotal | https://www.virustotal.com/gui/sign-in | 500 req/día |
| AbuseIPDB | https://www.abuseipdb.com/register | 1000 req/día |
| URLScan.io | https://urlscan.io/user/signup | Sin clave funciona |
| Shodan | https://account.shodan.io/register | Búsquedas básicas |

---

## 🚀 Uso

```bash
# Análisis básico
python domain_investigator.py example.com

# Guardar reporte en JSON
python domain_investigator.py suspicious-site.xyz --json

# Pasar claves por argumento
python domain_investigator.py malicious.net \
    --vt-key TU_CLAVE_VT \
    --abuse-key TU_CLAVE_ABUSE

# Ver ayuda
python domain_investigator.py --help
```

---

## 🧩 Módulos de Análisis

### 1. 🛡️ VirusTotal
- Consulta 70+ motores antivirus y herramientas de análisis
- Muestra detecciones maliciosas, sospechosas y limpias
- Incluye reputación, categorías y votos de la comunidad

### 2. 🌐 DNS — Resolución de registros
- Registros A (IPv4), AAAA (IPv6)
- Name Servers (NS)
- Registros de correo (MX)

### 3. 📧 SPF / DKIM / DMARC
- **SPF**: Verifica si el dominio tiene política de remitentes
  autorizados. Detecta políticas peligrosas como `+all`
- **DMARC**: Verifica la política de manejo de emails no autenticados
  (`none`, `quarantine`, `reject`)
- **DKIM**: Busca selectores DKIM activos entre los más comunes
  (Google, Microsoft, Mimecast, SendGrid, etc.)

### 4. 📋 WHOIS
- Fecha de creación y antigüedad del dominio
- Registrador, país, Name Servers
- Estado del dominio (clientTransferProhibited, etc.)
- ⚠️ Dominios muy recientes (<30 días) se marcan como alto riesgo

### 5. 🔒 SSL/TLS
- Versión TLS (TLS 1.2, TLS 1.3...)
- Certificado: emisor, validez, días restantes
- Detección de certificados expirados o autofirmados
- Subject Alternative Names (SAN)

### 6. 🗺️ Geolocalización (ip-api.com — sin clave)
- País, región, ciudad y coordenadas
- ISP y organización
- Detección de servidores de hosting/VPS

### 7. 🚨 AbuseIPDB
- Score de abuso de la IP (0-100%)
- Número de reportes en los últimos 90 días
- Tipo de uso, ISP, país

### 8. 🔎 URLScan.io
- Veredicto del último escaneo público
- IP, servidor, ASN detectados en la navegación
- Número de requests y enlaces externos
- Tags de comportamiento

### 9. 🔭 Shodan
- Puertos y servicios abiertos
- Productos/versiones de software expuestos
- CVEs detectados
- Tags (honeypot, tor, cloud, vpn, etc.)

### 10. ⚠️ Risk Score
Puntuación de riesgo calculada (0-100) que pondera:
- Detecciones en VirusTotal
- Score AbuseIPDB
- Antigüedad del dominio
- Ausencia de SPF/DMARC
- Estado del certificado SSL
- Veredicto URLScan

---

## 📊 Ejemplo de salida

```
┌─────────────────────────────────────────────────────────────┐
│ ⚠️  RESUMEN DE RIESGO                                        │
│                                                             │
│  🔴 VirusTotal: 18 motores lo detectan como MALICIOSO       │
│  🔴 Dominio MUY RECIENTE: solo 3 días de antigüedad         │
│  🟠 AbuseIPDB: Score de abuso 87% (142 reportes)            │
│  🟡 Sin registro DMARC — sin política anti-spoofing         │
│                                                             │
│ Score total: 85/100                          ● CRÍTICO      │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Estructura del proyecto

```
domain_investigator/
├── domain_investigator.py   # Script principal
├── requirements.txt         # Dependencias pip
├── config.ini.example       # Plantilla de configuración
├── config.ini               # Tu configuración (NO subir a git)
└── README.md                # Esta documentación
```

---

## ⚖️ Consideraciones legales y éticas

- Esta herramienta está diseñada para **uso defensivo y de investigación**.
- Úsala únicamente para analizar dominios que tengas autorización de revisar
  o que sean de carácter público/sospechoso para fines de ciberseguridad.
- Respeta los términos de uso de cada API.
- Ninguna herramienta es 100% definitiva. **Correlaciona siempre los hallazgos.**

---

## 🔗 Recursos adicionales

- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
- [URLScan.io](https://urlscan.io)
- [Shodan](https://www.shodan.io)
- [MXToolbox](https://mxtoolbox.com)
- [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing)
- [ThreatFox (Abuse.ch)](https://threatfox.abuse.ch)
