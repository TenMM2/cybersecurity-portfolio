# 🛠️ Scripts propios

Herramientas pequeñas escritas por mí, pensadas como ejercicio práctico y como evidencia de código real (tu GitHub actual no tenía proyectos propios, esto lo soluciona).

## ✅ Hechos

### [`port_scanner.py`](port_scanner.py)
Escáner de puertos TCP básico (TCP connect scan) con hilos concurrentes. Entender a bajo nivel qué hace una herramienta como nmap al comprobar puertos abiertos.

```bash
python port_scanner.py <host> --ports 1-1024
```

⚠️ Solo contra hosts propios o autorizados (tu home lab, `scanme.nmap.org`, etc.).

## 💡 Ideas pendientes (de más fácil a más interesante)
2. **Parser de logs** — leer un log de autenticación (ej. `/var/log/auth.log` simulado) y detectar intentos de fuerza bruta.
3. **Comprobador de contraseñas filtradas** — comparar hashes contra una lista tipo "rockyou" (solo para laboratorio propio).
4. **Script de hardening checklist** — comprobar configuraciones básicas de seguridad en una VM (puertos abiertos, usuarios con privilegios, etc.).

Cada script debería tener su propia sección aquí (o `README.md` propio si crece) explicando qué hace y por qué lo hiciste.
