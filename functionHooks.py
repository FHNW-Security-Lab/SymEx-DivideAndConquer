import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import angr, claripy
import sys, os
import IPython
import monkeyhex


class HookClass(angr.SimProcedure): 
    def run(self, return_values=None):
        pass

class HookClassAdd(angr.SimProcedure): 
    def run(self, return_values=None, symbolic_return=True):
        return return_values[0]

def test1(p): 
    p.hook_symbol('print1', HookClass())
    p.hook_symbol('print2', HookClass())
    p.unhook_symbol('print2')

    state = p.factory.entry_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()


def test2(p): 
    p.hook_symbol('add1', HookClassAdd(return_values=[27]))
    p.hook_symbol('add', HookClassAdd())

    p.unhook_symbol('add')

    state = p.factory.entry_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()

def getEntryFunction(project: angr.Project):
    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    return entry_func

def getListOfFunctionsInMain(project: angr.Project):
    entry_func = getEntryFunction(project)
    functions = entry_func.functions_called()
    return functions

class Hook1(angr.SimProcedure):

    def run(self):
        print("add1 hooked")
        self.state.regs.rax = claripy.BVS("ret1", 32)	
        print(self.state.regs.rax)

def test3(p):
    functions = getListOfFunctionsInMain(p)
    print(functions)
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    print(a.name, a.addr)
    p.hook(a.addr, hook=Hook1(), length=5)

    #s = p.analyses.CallingConvention(a, cfg=cfg, analyze_callsites=True)
    s = p.analyses.CallingConvention(a, analyze_callsites=True)
    print ("Analysed function header: ", s.prototype)
    print("| Size of ret:", s.prototype.returnty.with_arch(p.arch).size)

    state = p.factory.full_init_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.stashes)
    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()

#check for syscall
def test4(p):
    functions = getListOfFunctionsInMain(p)
    for f in functions:
        print(f.name, "sim_procedure?", f.is_simprocedure, "syscall?", f.is_syscall, f.is_plt) 
        #with plt and simprocedure we can catch all functions that do not need to be simulated
    IPython.embed()


def test5(p):
    #p.hook(a.addr, hook=Hook1(), length=5)
    
    #a = p.loader.find_symbol('add1')
    cfg = p.analyses.CFGFast()
    a = cfg.kb.functions['add']
    s = p.analyses.CallingConvention(a, cfg=cfg, analyze_callsites=True)
    #s = p.analyses.CallingConvention(a, analyze_callsites=True)

    print ("Analysed function header: ", s.prototype)

    IPython.embed()
    print("| Size of ret:", s.prototype.returnty.with_arch(p.arch).size)

    p.hook_symbol('add', Hook1())
    state = p.factory.full_init_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.stashes)
    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()


#test calling convention recovery
def test6(p):
    cfg = p.analyses.CFGFast()
    a = p.analyses.CompleteCallingConventions(recover_variables=True, force=True, cfg=cfg, analyze_callsites=True)
    print(a.kb.functions["add1"].prototype)
    IPython.embed()


#TODO TEST MORE HEADER DETECTION
    
def main(argv): 
    if len(argv) < 2:
        return
    prog_name = argv[1]
    p = angr.Project(prog_name, auto_load_libs=False)
    test4(p)



if __name__ == '__main__':
    main(sys.argv)