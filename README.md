# SafeStoreWeb - Versión comentada y segura

## Objetivo
Aplicación web de catálogo de productos con login, implementando medidas del Checklist OWASP y con código comentado para explicar cada decisión.

## Requisitos
- .NET 8 SDK
- Docker (para docker-compose)

## Ejecutar con Docker
1. `docker-compose up --build`
2. Ir a `http://localhost:5000`

## Notas importantes
- Credenciales de la base en `docker-compose.yml` y admin en `appsettings.json` son para desarrollo. NO usar en producción.
- Para producción: mover secretos a variables de entorno o un vault.
