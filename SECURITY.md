# Seguridad - SafeStoreWeb (comentado)

Medidas implementadas:
- ASP.NET Identity con políticas de contraseña fuertes y bloqueo por intentos.
- CSRF protegido con antiforgery tokens en formularios POST.
- Cabeceras de seguridad (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Cookies configuradas Secure, HttpOnly y SameSite=Strict.
- EF Core para consultas parametrizadas (protección contra SQLi).
- Rate limiting básico configurado (ejemplo).
- Seed de usuario admin para pruebas (NO usar en producción).
