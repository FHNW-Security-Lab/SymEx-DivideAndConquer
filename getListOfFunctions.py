import angr
import os, sys
import IPython

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    
    entry = getEntryFunction(project)
    printAllCalledFunctions(entry)

    IPython.embed()

    
def getListOfFunctionsInMain(project: angr.Project):
    entry_func = getEntryFunction(project)
    functions = entry_func.functions_called()
    return functions

def getListOfCalledFunctions(function: angr.knowledge_plugins.functions.function.Function): 
     functions = function.functions_called()
     #if len(functions) > 0:
     #   functions.pop()
     return functions

def getListOfAllFunctionsAddresses(project: angr.Project):
    cfg = project.analyses.CFGFast()
    functionAddresses = list(cfg.kb.functions)
    return functionAddresses

def getEntryFunction(project: angr.Project):
    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    return entry_func

def printAllCalledFunctions(entry: angr.knowledge_plugins.functions.function.Function):
    functions = getListOfCalledFunctions(entry)
    if len(functions) > 0:
        print(entry.name, "(" + str(hex(entry.addr)) + ")", "--> 0", functions)
    for f in functions: 
        printAllCalledFunctions(f)
    



if __name__ == "__main__":
    main(sys.argv)