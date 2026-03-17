# 🔍 Code Secrets Auditor

**Herramienta de auditoría de secretos en código fuente**

## Descripción técnica
Script en Python que escanea recursivamente un directorio buscando patrones de secretos (AWS, GitHub, claves SSH, contraseñas hardcodeadas).  
Ideal para:
- Hooks pre-commit
- Pipelines CI/CD
- Auditorías de repositorios legacy

**Características**:
- Sin dependencias externas (solo Python 3.6+)
- Ignora `.git`, `node_modules`, etc.
- Salida legible + opción de exportar reporte
