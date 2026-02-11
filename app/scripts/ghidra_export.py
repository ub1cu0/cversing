# ghidra_export.py
# A Ghidra script to export decompiled C functions to JSON format for C-Guessr
# Usage:
#   <ghidra_install_dir>/support/analyzeHeadless <project_dir> <project_name> -import <binary_path> -scriptPath <script_dir> -postScript ghidra_export.py <output_json_path>

import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_function_code(func, monitor):
    """Decompiles a function and returns the C code as a string."""
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    
    # Decompile
    results = decomplib.decompileFunction(func, 60, monitor)
    if not results.decompileCompleted():
        return None
        
    clang_token_group = results.getCCodeMarkup()
    if clang_token_group is None:
        return None
        
    # Simply get the C implementation
    c_code = results.getDecompiledFunction().getC()
    return c_code

def main():
    monitor = ConsoleTaskMonitor()
    functions_list = []
    
    # Get all functions
    func_iter = currentProgram.getFunctionManager().getFunctions(True)
    
    print("Starting export of functions...")
    
    count = 0
    for func in func_iter:
        # Filter thunks (functions that just jump to another)
        if func.isThunk():
            continue
            
        func_name = func.getName()
        # Export everything as requested (removed startswith(_) and size checks)

        c_code = get_function_code(func, monitor)
        
        if c_code:
            # Clean up output a bit if needed (remove comments, etc)
            # For now, we keep it raw as Ghidra outputs it
            
            function_data = {
                "id": "auto-" + func_name,
                "name": func_name,
                "difficulty": "Unknown", # Requires manual tagging or heuristic
                "description": "Auto-generated from binary",
                "code": c_code
            }
            functions_list.append(function_data)
            count += 1
            if count % 10 == 0:
                print("Processed {} functions...".format(count))

    # Output to JSON
    # 'args' is populated by Headless Analyzer arguments after the script name
    output_path = "functions_export.json"
    if len(args) > 0:
        output_path = args[0]
        
    print("Writing {} functions to {}".format(len(functions_list), output_path))
    
    with open(output_path, 'w') as f:
        json.dump(functions_list, f, indent=2)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error: " + str(e))
