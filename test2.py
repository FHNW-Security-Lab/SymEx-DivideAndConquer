import angr, claripy
import sys

def main(argv):
    p = angr.Project("../TestProgs/test2", auto_load_libs=False)

    cfg = p.analyses.CFGFast()
    entry_func = cfg.kb.functions[p.entry]

    functions = entry_func.functions_called()
    functions = list(filter(lambda f: not f.is_syscall and not f.is_plt and not f.is_simprocedure, functions))    

    cc = p.factory.cc()

    for f in functions:
        print("Executing: ", f.name, hex(f.addr))
        state = p.factory.call_state(f.addr, cc=cc)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
        simgr = p.factory.simgr(state, save_unconstrained=True)#, veritesting=True)
        simgr.run()#until=lambda sm: len(sm.unconstrained) > 0)

        ##unhook functions
        for f in functions: 
            p.unhook(f.addr)




if __name__ == "__main__":
    main(sys.argv)