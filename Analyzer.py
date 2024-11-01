import gc
import logging
import sys
import time
import IPython
import claripy

import psutil

logging.getLogger("angr").setLevel(
    "CRITICAL"
)  # level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL


import angr
from angr.exploration_techniques import (
    LoopSeer,
    LengthLimiter,
    Spiller,
    MemoryWatcher,
    DFS,
    Threading,
)
from claripy.ast.bv import BV
from angr.knowledge_plugins.functions.function import Function
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from Analyser_Hook import Analyser_Hook
from Vulnerability_Analyser import Vulnerability_Analyser
from functionSummary import functionSummary

CGREEN = "\033[92m"
CRED = "\033[91m"
CEND = "\033[0m"


def create_graph(project: angr.Project):
    main = project.loader.main_object.get_symbol("main")
    start_state = project.factory.blank_state(addr=main.rebased_addr)
    cfg = project.analyses.CFGEmulated(
        fail_fast=True,
        starts=[main.rebased_addr],
        initial_state=start_state,
        normalize=True,
    )
    """
    start_state = project.factory.blank_state(addr=project.entry)
    cfg = project.analyses.CFGEmulated(
        keep_state=True, starts=[project.entry], initial_state=start_state
    )
    """
    return cfg


# TODO: For some reason when executing main it errores, possible due to no argv passed?
# TODO: Are we interested in gathering callees dynamically?
# TODO: Gather somehow preconditions of functions in order to determine if mutex?
class Analyzer:
    def __init__(self, prog_name: str, auto_load_libs=False, analyze_uncalled=False):
        self.project = angr.Project(
            prog_name, auto_load_libs=auto_load_libs, main_opts={"base_addr": 0x400000}
        )
        self.cc = self.project.factory.cc()
        self.analyze_uncalled = analyze_uncalled  # todo if enabled also analyse uncalled functions for weaknesses
        # use cfg emulated, loose _starts function but do we really need to analyse the _starts function?
        self.cfg = create_graph(self.project)
        # self.cfg = self.project.analyses.CFGFast()
        self.function_prototypes = self.project.analyses.CompleteCallingConventions(
            recover_variables=True, force=True, cfg=self.cfg, analyze_callsites=True
        )
        self.already_executed = set()
        self.potvulnfunctions = set()
        # TODO, iteratively increase looper
        self.loop_depth = 4
        self.path_limit = 40  # TODO if limiter is active, we need to have a coverage map to understand what was verified
        # self.loop_seer = LoopSeer(
        #    cfg=self.cfg, bound=self.loop_depth
        # )  # 0, limit_concrete_loops=False)
        # self.path_limiter = LengthLimiter(self.path_limit)
        # self.spiller = Spiller()
        # self.memory_watcher = MemoryWatcher()
        # self.dfs = DFS()
        # self.threading = Threading(threads=8)
        self.namecounter = 0
        self.summaries = {}

    def getListOfFunctionsInMain(self):
        entry_func = self.getEntryFunction()
        functions = entry_func.functions_called()
        return functions

    def getListOfCalledFunctions(self, function: Function):
        functions = function.functions_called()
        return functions

    def getListOfAllFunctionsAddresses(self):
        functionAddresses = list(self.cfg.kb.functions)
        return functionAddresses

    def getEntryFunction(self) -> Function:
        # test

        entry_func = self.cfg.kb.functions[
            self.project.loader.main_object.get_symbol("main").rebased_addr
        ]
        """
        entry_func = self.cfg.kb.functions[self.project.entry]
        """
        return entry_func

    def printAllCalledFunctions(
        self, entry: Function = None, exclude_sysfunc=True
    ) -> None:
        if entry is None:
            entry = self.getEntryFunction()
        functions = self.getListOfCalledFunctions(entry)
        if len(functions) > 0:
            if not exclude_sysfunc or (
                not entry.is_syscall and not entry.is_plt and not entry.is_simprocedure
            ):
                print(entry.name, "(" + str(hex(entry.addr)) + ")", "--> 0", functions)
        for f in functions:
            if exclude_sysfunc:
                if f.is_syscall or f.is_plt or f.is_simprocedure:
                    continue
            if entry.addr == f.addr:  # prevent recursion
                return
            self.printAllCalledFunctions(f, exclude_sysfunc=exclude_sysfunc)

    def mem_watcher(self, state: SimState) -> None:
        self.memory_changes.append(
            (
                state.inspect.mem_write_address,
                state.inspect.mem_write_expr,
                state.inspect.mem_write_condition,
            )
        )
        return

    def register_watcher(self, state: SimState) -> None:
        self.register_changes.append(
            (
                state.inspect.reg_write_offset,
                state.inspect.reg_write_expr,
                state.inspect.reg_write_condition,
            )
        )
        return

    # def simprodhooktest(self, state: SimState):
    #   print(state)

    def runFunctionBasedAnalysis(
        self,
        analyzer: Vulnerability_Analyser,
        entry: Function = None,
        exclude_sysfunc=True,
        stop_at_bug=False,
    ):
        if entry is None:
            entry = self.getEntryFunction()
        functions = self.getListOfCalledFunctions(entry)
        if exclude_sysfunc:
            functions = [f for f in list(functions) if f is not None]
            functions = list(
                filter(
                    lambda f: not f.is_syscall
                    and not f.is_plt
                    and not f.is_simprocedure,
                    functions,
                )
            )

        for f in functions:
            # How to deal with recursion? it knalls us um die ohren
            if entry.addr == f.addr:
                return None
            bug = self.runFunctionBasedAnalysis(
                analyzer, entry=f, exclude_sysfunc=exclude_sysfunc
            )
            if bug and stop_at_bug:
                return bug

        if entry.addr in self.already_executed:
            return

        # hook functions called by current function
        for f in functions:
            self.project.hook(
                f.addr, hook=Analyser_Hook(ret_val=self.summaries[f.addr]), length=5
            )

        # execute function symbolically
        # print("Prototype", self.function_prototypes.kb.functions[entry.addr].prototype)
        # can we do something here with static type analysis?
        prototype = self.function_prototypes.kb.functions[entry.addr].prototype
        # IPython.embed() # can i get argument register? can i use radare etc
        # TODO create argument analyzer
        # args=[]
        # for arg in prototype.args:
        #    if type(arg) == angr.sim_type.SimTypeLongLong:
        #        array = claripy.BVS('str' + str(self.namecounter), 50*8)
        #        ptr_arg = angr.PointerWrapper(array, buffer=False)
        #        args.append(ptr_arg)#claripy.BVS('name' + str(self.namecounter), 64))
        #        self.namecounter += 1
        rdi = claripy.BVS("rdi", 32)
        state = self.project.factory.call_state(entry.addr, cc=self.cc)
        state.regs.rdi = rdi
        # , args=prototype.args)
        cc_ret_reg = self.cc.return_val(
            angr.sim_type.parse_type("void *")
        )  # what is the purpose of that type?
        # possible to add type with SimMem and with_type?
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        # state.options.add(angr.sim_options.STRICT_PAGE_ACCESS)
        state.options.add(angr.sim_options.SYMBOLIC)
        state.register_plugin(
            "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc()
        )
        simgr = self.project.factory.simgr(
            state, save_unconstrained=True
        )  # , veritesting=True) # apparently veritesting makes some problems here
        # simgr.use_technique(self.loop_seer)
        # simgr.use_technique(self.path_limiter)
        # simgr.use_technique(self.spiller) #FIXME leads to crashes
        # simgr.use_technique(self.memory_watcher)
        # simgr.use_technique(self.dfs)
        print("----Symbolically execute function:", entry.name, "@", hex(entry.addr))
        memory_bp = state.inspect.b(
            "mem_write", when=angr.BP_AFTER, action=self.mem_watcher
        )
        reg_bp = state.inspect.b(
            "reg_write", when=angr.BP_AFTER, action=self.register_watcher
        )
        self.memory_changes = []
        self.register_changes = []

        # ret_sm = simgr.run()
        i = 0
        while len(simgr.active) > 0:
            i += 1
            print(
                f"Funtion: {entry.name} # Active States: {len(simgr.active)}, # Deadended States: {len(simgr.deadended)}, # Unconstrained states: {len(simgr.unconstrained)} after {i} executions",
                end="\r",
            )  # For debugging
            if (
                len(simgr.active) >= 500
                or i >= 200
                or len(simgr.deadended) >= 500
                or len(simgr.unconstrained) >= 100
            ):  # TODO find better way
                sys.stdout.flush()
                print("")
                print("Aborted due to state explosion")
                break
            ret_sm = simgr.step()
        print(
            f"Funtion: {entry.name} # Active States: {len(simgr.active)}, # Deadended States: {len(simgr.deadended)}, # Unconstrained states: {len(simgr.unconstrained)} after {i} executions",
            end="\r",
        )
        print("")
        #IPython.embed()
        # mem_before = psutil.virtual_memory().used / 10**9
        # print(f"{CGREEN} Memory usage before collect: {mem_before} GB{CEND}")
        # gc.collect()
        # mem_after = psutil.virtual_memory().used / 10**9
        # print(f"{CGREEN} Memory usage after collect: {mem_after} GB{CEND}")
        # print(f"{CGREEN} Diff: {mem_before - mem_after} GB{CEND}")
        # print("\n")
        simgr_stash_copy = []  # ret_sm._copy_stashes(deep=True)
        # simgr_stash_copy = dict(
        #    filter(lambda x: len(x[1]) > 0, simgr_stash_copy.items())
        # )
        # TODO: reduce if same values but need to consider sideeffects..
        return_expressions = self.get_return_expression(ret_sm, cc_ret_reg)

        summary = functionSummary(
            entry,
            cc_ret_reg.reg_name,
            return_expressions,
            self.memory_changes,
            self.register_changes,
            simgr_stash_copy,
            ret_symbol=None,
        )
        self.summaries[entry.addr] = summary

        state.inspect.remove_breakpoint("mem_write", bp=memory_bp)
        state.inspect.remove_breakpoint("reg_write", bp=reg_bp)
        self.already_executed.add(entry.addr)

        # unhook functions
        for f in functions:
            self.project.unhook(f.addr)

        bug = analyzer.check(ret_sm)

        if bug:
            print(
                f"{CRED}Found potential unconstrained IP in function: {entry.name}{CEND}\n"
            )  # TODO
            # TODO: Check if path is feasible
            # run with symbolic input along path and constrain it to the return values
            self.potvulnfunctions.add(entry.name)
            return bug

        return None

    # FIXME: Find proper way to construct formulas
    def get_return_expression(self, simgr: SimulationManager, cc_ret_reg) -> BV:
        ret_expr = [
            (
                deadend.regs.get(cc_ret_reg.reg_name),
                deadend.solver.true,
                deadend.solver.constraints,
            )
            for deadend in simgr.deadended
        ]
        # if self.check_if_all_concrete(ret_expr):
        #    ret_sym = claripy.BVS('ret', 64)
        #    ret_sym = ret_sym == ret_expr.pop()
        #    [ret_sym := claripy.Or(ret_sym, ret_sym == x) for x in ret_expr]
        #    return ret_sym
        # TODO: make clean
        # IPython.embed()
        if len(ret_expr) == 0:
            if len(simgr.unconstrained) != 0:
                ret_expr = [
                    (
                        deadend.regs.get(cc_ret_reg.reg_name),
                        deadend.solver.true,
                        deadend.solver.constraints,
                    )
                    for deadend in simgr.unconstrained
                ]
                acc = [x for x in ret_expr]
                # [acc := acc or x for x in ret_expr]
                return acc
            # for some reason when executing main execution errores
            # return claripy.BVS("unconstrained", 64)

        # BUG: 0x1 | 0x0 always = 0x1, not possbile to express that function may return 0 or 1..
        # acc = ret_expr.pop()
        acc = [x for x in ret_expr]  # FIXME
        return acc
