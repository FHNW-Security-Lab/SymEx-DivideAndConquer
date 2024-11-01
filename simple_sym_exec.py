import angr

p = angr.Project(
    "../TestPrograms/CADET_00001", auto_load_libs=False
)  # Program Name here, load the program
cc = p.factory.cc()

state = p.factory.entry_state()  # start at the beginning of the program
# state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
# state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
# state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())

simgr = p.factory.simgr(save_unconstrained=True)  # $, veritesting=True)
while len(simgr.unconstrained) == 0:
    simgr.step()

if len(simgr.unconstrained) > 0:
    print(
        "Found a state with unconstrained instruction pointer. This is a vulnerability"
    )
unconstrained_state = simgr.unconstrained[0]
crashing_input = unconstrained_state.posix.dumps(0)
