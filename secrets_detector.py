import argparse
import os
import re
from pathlib import Path

# Patrones de secretos (controles implementados)
PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws.*[0-9a-zA-Z/+]{40}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Private SSH Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
    "Generic Password": r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}",
}

def scan_file(file_path: Path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern in PATTERNS.items():
                    if re.search(pattern, line):
                        findings.append((line_num, name, line.strip()))
    except Exception:
        pass
    return findings

def scan_directory(directory: str):
    reports = []
    for root, dirs, files in os.walk(directory):
        # Ignorar carpetas que no interesan
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
        for file in files:
            if file.endswith(('.py', '.js', '.sh', '.env', '.txt', '.yaml', '.yml', '.json')):
                path = Path(root) / file
                findings = scan_file(path)
                if findings:
                    reports.append((str(path), findings))
    return reports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🔍 Code Secrets Auditor - Detector de secretos en código"
    )
    parser.add_argument("-d", "--directory", default=".", help="Directorio a escanear (default: actual)")
    parser.add_argument("-o", "--output", help="Archivo donde guardar el reporte")
    args = parser.parse_args()

    reports = scan_directory(args.directory)

    output = []
    if not reports:
        output.append("✅ No se encontraron secretos.")
    else:
        for path, findings in reports:
            output.append(f"\n📄 Archivo: {path}")
            for ln, name, line in findings:
                output.append(f"   └─ Línea {ln}: {name} → {line[:80]}...")

    print("\n".join(output))

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("\n".join(output))
        print(f"\n📝 Reporte guardado en: {args.output}")
