'use strict';
/* Descifra los archivos de la app verde que sube el celular al repo público (los .cifrado de esta carpeta).
   Uso: node descifrar.js <clave> [carpeta de salida, por defecto "app"]
   La clave (64 caracteres hexadecimales) está en configuracion.json del proyecto ("appPublica.clave") y en la tarea
   de Claude que publica la app. Sin la clave estos archivos no se pueden leer.
   Formato de cada .cifrado: "PTC1" + iv (12 bytes) + tag (16 bytes) + el archivo comprimido con gzip y cifrado con
   AES-256-GCM (el nombre del archivo va como dato autenticado). Este archivo no usa nada fuera de Node. */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

function descifrar(nombre, buf, clave) {
  if (buf.subarray(0, 4).toString('latin1') !== 'PTC1') throw new Error(`${nombre}: no es un archivo cifrado de la app`);
  const K = Buffer.from(clave, 'hex');
  const kAes = crypto.createHmac('sha256', K).update('aes').digest();
  const d = crypto.createDecipheriv('aes-256-gcm', kAes, buf.subarray(4, 16));
  d.setAAD(Buffer.from(nombre, 'utf8'));
  d.setAuthTag(buf.subarray(16, 32));
  return zlib.gunzipSync(Buffer.concat([d.update(buf.subarray(32)), d.final()]));
}

if (require.main === module) {
  const [clave, salida = 'app'] = process.argv.slice(2);
  if (!/^[0-9a-f]{64}$/i.test(clave || '')) { console.error('Falta la clave (64 caracteres hexadecimales).'); process.exit(2); }
  const origen = __dirname;
  const archivos = fs.readdirSync(origen).filter((f) => f.endsWith('.cifrado'));
  if (!archivos.length) { console.error('No hay archivos .cifrado en ' + origen); process.exit(1); }
  fs.mkdirSync(salida, { recursive: true });
  for (const f of archivos) {
    const nombre = f.slice(0, -'.cifrado'.length);
    let plano;
    try { plano = descifrar(nombre, fs.readFileSync(path.join(origen, f)), clave); } catch (e) {
      console.error(`No pude descifrar ${f}: ${/auth/i.test(e.message) ? 'la clave no corresponde' : e.message}`); process.exit(1);
    }
    fs.writeFileSync(path.join(salida, nombre), plano);
    console.log(`${nombre}: ${plano.length} bytes`);
  }
}

module.exports = { descifrar };
