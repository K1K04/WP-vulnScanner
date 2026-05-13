                      
"""
Script de verificación: Comprueba que los cambios del botón de exportar están listos.
"""

import os
import re
import sys

def check_file_exists(path):
    """Verifica que un archivo existe"""
    if not os.path.exists(path):
        print(f"❌ FALTA: {path}")
        return False
    print(f"✅ EXISTE: {path}")
    return True

def check_function_defined(filepath, funcname):
    """Verifica que una función está definida exactamente una vez"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
                                                                
        if filepath.endswith('.py'):
            pattern = rf'def\s+{re.escape(funcname)}\s*\('
        else:       
            pattern = rf'function\s+{re.escape(funcname)}\s*\('
        
        matches = len(re.findall(pattern, content))
        if matches != 1:
            print(f"❌ FUNCIÓN {funcname} DEFINIDA {matches} VEZ(VEC) (debe ser 1)")
            return False
        print(f"✅ FUNCIÓN {funcname} definida 1 vez")
        return True
    except Exception as e:
        print(f"❌ ERROR leyendo {filepath}: {e}")
        return False

def check_string_exists(filepath, searchstr):
    """Verifica que un string existe en un archivo"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        if searchstr in content:
            print(f"✅ ENCONTRADO: {searchstr[:60]}...")
            return True
        else:
            print(f"❌ NO ENCONTRADO: {searchstr[:60]}...")
            return False
    except Exception as e:
        print(f"❌ ERROR leyendo {filepath}: {e}")
        return False

def main():
    base = "/home/kiko/Descargas/wpvulnscan-pro-v2/wpvulnscan"
    
    print("=" * 70)
    print("VERIFICACIÓN DEL FIX: BOTÓN DE EXPORTACIÓN")
    print("=" * 70)
    
    all_pass = True
    
    print("\n1. ARCHIVOS EXISTEN")
    print("-" * 70)
    all_pass &= check_file_exists(f"{base}/static/app.js")
    all_pass &= check_file_exists(f"{base}/templates/index.html")
    all_pass &= check_file_exists(f"{base}/blueprints/scan.py")
    all_pass &= check_file_exists(f"{base}/scanner/export.py")
    
    print("\n2. FUNCIONES DEFINIDAS (una sola vez cada una)")
    print("-" * 70)
    all_pass &= check_function_defined(f"{base}/static/app.js", "toggleExportMenu")
    all_pass &= check_function_defined(f"{base}/static/app.js", "closeExportMenu")
    all_pass &= check_function_defined(f"{base}/static/app.js", "downloadPDF")
    all_pass &= check_function_defined(f"{base}/static/app.js", "downloadMarkdown")
    all_pass &= check_function_defined(f"{base}/static/app.js", "downloadSARIF")
    
    print("\n3. HTML TIENE ONCLICK CORRECTO")
    print("-" * 70)
    all_pass &= check_string_exists(f"{base}/templates/index.html", 
                                     'onclick="toggleExportMenu()"')
    
    print("\n4. FUNCIONES AL INICIO DE app.js (antes de línea 70)")
    print("-" * 70)
    try:
        with open(f"{base}/static/app.js", 'r') as f:
            lines = f.readlines()
        
        toggle_line = None
        for i, line in enumerate(lines[:100], 1):
            if 'function toggleExportMenu' in line:
                toggle_line = i
                break
        
        if toggle_line and toggle_line < 70:
            print(f"✅ toggleExportMenu está en línea {toggle_line} (< 70)")
        else:
            print(f"❌ toggleExportMenu está en línea {toggle_line} (debe ser < 70)")
            all_pass = False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        all_pass = False
    
    print("\n5. NO HAY ADDEVENTLISTENER DUPLICADO")
    print("-" * 70)
    try:
        with open(f"{base}/static/app.js", 'r') as f:
            content = f.read()
        
                                                                                   
        pattern = r"\.addEventListener\s*\(\s*['\"]click['\"]\s*,\s*toggleExportMenu"
        matches = 0
        for line in content.split('\n'):
            if '//' not in line:                                  
                if re.search(pattern, line):
                    matches += 1
        
        if matches == 0:
            print(f"✅ NO hay addEventListener duplicado (correcto)")
        else:
            print(f"❌ HAY {matches} addEventListener duplicado (debe ser 0)")
            all_pass = False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        all_pass = False
    
    print("\n6. BACKEND ROUTES EXISTEN")
    print("-" * 70)
    all_pass &= check_string_exists(f"{base}/blueprints/scan.py", 
                                     '@scan_bp.route("/scan/<job_id>/markdown")')
    all_pass &= check_string_exists(f"{base}/blueprints/scan.py", 
                                     '@scan_bp.route("/scan/<job_id>/sarif")')
    
    print("\n7. BACKEND FUNCTIONS EXISTEN")
    print("-" * 70)
    all_pass &= check_function_defined(f"{base}/scanner/export.py", "generate_markdown")
    all_pass &= check_function_defined(f"{base}/scanner/export.py", "generate_sarif")
    all_pass &= check_function_defined(f"{base}/scanner/export.py", "generate_standalone_html")
    
    print("\n" + "=" * 70)
    if all_pass:
        print("✅ TODAS LAS VERIFICACIONES PASARON")
        print("=" * 70)
        print("\n🎉 El botón de exportación está listo para usar!")
        print("\nPasos para verificar en el navegador:")
        print("1. Abre: http://localhost:8080")
        print("2. Completa un escaneo")
        print("3. Presiona el botón 'Exportar ▾'")
        print("4. Debe abrirse un menú desplegable")
        print("\nSi no funciona, abre DevTools (F12) y ejecuta:")
        print("  toggleExportMenu()")
        return 0
    else:
        print("❌ ALGUNAS VERIFICACIONES FALLARON")
        print("=" * 70)
        return 1

if __name__ == '__main__':
    sys.exit(main())
