# ghidra_export.py
import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Configuración
OUTPUT_FILE = "functions.json"
MIN_CODE_LENGTH = 50  # Filtrar funciones demasiado cortas/vacías

def extract_functions():
    # 1. Preparar la interfaz del decompilador
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram) # currentProgram es una variable global en Ghidra
    monitor = ConsoleTaskMonitor()
    
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True) # True = iterar hacia adelante
    
    extracted_data = []
    
    print("Iniciando extraccion de funciones para: " + currentProgram.getName())

    for func in functions:
        # 2. Filtros
        if func.isThunk():
            continue
        if func.isExternal():
            continue
            
        # 3. Decompilar
        # Timeout de 30 segundos por función para evitar bloqueos
        results = decomp_interface.decompileFunction(func, 30, monitor)
        
        if not results.decompileCompleted():
            print("Error decompilando: " + func.getName())
            continue
            
        # 4. Obtener código Pseudo-C
        decompiled_func = results.getDecompiledFunction()
        if decompiled_func:
            c_code = decompiled_func.getC()
            
            # Filtro adicional: ignorar funciones vacías o triviales
            if not c_code or len(c_code) < MIN_CODE_LENGTH:
                continue

            # Crear objeto
            func_data = {
                "name": func.getName(),
                "address": func.getEntryPoint().toString(),
                "code": c_code
            }
            extracted_data.append(func_data)

    # 5. Guardar a JSON
    # Guardamos en el directorio actual desde donde se ejecuta el script
    output_path = os.path.abspath(OUTPUT_FILE)
    
    try:
        with open(output_path, 'w') as f:
            json.dump(extracted_data, f, indent=4)
        print("Exportacion exitosa. " + str(len(extracted_data)) + " funciones guardadas en: " + output_path)
    except Exception as e:
        print("Error escribiendo archivo JSON: " + str(e))

# Ejecutar la lógica
extract_functions()
