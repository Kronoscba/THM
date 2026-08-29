#!/usr/bin/env python3
# scripts/extract_payload.py
# Extrae el payload .NET desde Win32_HardwareTelemetry.ConfigData en OBJECTS.DATA

import base64, zlib, re, sys

def extract_configdata(objects_data_path):
    with open(objects_data_path, 'rb') as f:
        data = f.read()
    # Buscar la cadena base64 de ConfigData (patrón: base64 largo sin newlines)
    matches = re.findall(rb'[A-Za-z0-9+/=]{500,}', data)
    for m in matches:
        try:
            compressed = base64.b64decode(m)
            # Probar descompresión deflate (raw)
            decompressed = zlib.decompress(compressed, -zlib.MAX_WBITS)
            if decompressed[:2] == b'MZ':  # PE header
                return decompressed
        except:
            continue
    return None

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <OBJECTS.DATA>")
        sys.exit(1)
    pe = extract_configdata(sys.argv[1])
    if pe:
        with open('payload.exe', 'wb') as f:
            f.write(pe)
        print(f'[+] Extracted {len(pe)} bytes to payload.exe')
    else:
        print('[-] No se encontró payload válido')