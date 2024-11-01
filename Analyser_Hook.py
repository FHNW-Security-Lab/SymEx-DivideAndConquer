import logging
import IPython

logging.getLogger("angr").setLevel(
    "CRITICAL"
)  # level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL
from functionSummary import functionSummary

import angr, claripy
from claripy.ast.bv import BV

CGREEN = "\033[92m"
CRED = "\033[91m"
CEND = "\033[0m"
enable_precondition = False  # If true use test10.c


# TODO: If inner function is unconstrained try setting IP manually
# TODO: Maybe required to check precond of each function
# TODO: Need a way to determine if function returns void... inspect callers if they inspect ret val?
class Analyser_Hook(angr.SimProcedure):
    @staticmethod
    def remove_duplicate_ret_values(
        ret_list: list[BV],
    ) -> list[BV]:
        # In future need to consider also sideeffects (same ret val but different effects)
        return list(set(ret_list))

    @staticmethod
    def filter_constraints(constraints: list, control) -> list[tuple]:
        c = []
        for constraint in constraints:
            if (
                len(list(constraint.variables)) > 1
            ):  # TODO better if statement needed if there are more than one parameters (stdin packet and scanf f.e.)
                continue
            if (
                control in list(constraint.variables)[0]
                or "rdi" in list(constraint.variables)[0]
            ):
                c.append(
                    (constraint.op, constraint.args[1])
                )  # TODO needs to be concrete arg would also be nice to resolve symbolic ones
        return c

    @staticmethod
    def check_feasability(relevant_constraints: list) -> bool:
        testvar = claripy.BVS("test", 32)
        solver = claripy.Solver()
        for c in relevant_constraints:
            if c[0] == "__ne__":
                solver.add(testvar != c[1])
            elif c[0] == "__eq__":
                solver.add(testvar == c[1])
        return solver.satisfiable()

    def run(self, ret_val: functionSummary = None):
        ret_addr = self.state.mem[self.state.regs.rsp].uint64_t.resolved
        ret_addr = ret_addr.concrete_value
        return_values = (
            ret_val.return_expr
        )  # self.remove_duplicate_ret_values(ret_list=ret_val.return_expr)

        try:
            if enable_precondition:
                feasible_succ = []
                for val in return_values:
                    s = self.state.copy()
                    s.regs.eax = val[0]

                    for constr in val[2]:
                        s.solver.add(constr)
                    control = list(self.state.regs.rdi.variables)[0]
                    test = self.filter_constraints(s.solver.constraints, control)
                    if self.check_feasability(test):
                        feasible_succ.append(s)
                    # IPython.embed()
                ret = feasible_succ.pop()  # TODO what if none is feasible
                for succ in feasible_succ:
                    self.successors.add_successor(
                        state=succ, target=ret_addr, guard=True, jumpkind="Ijk_Ret"
                    )  # get successor from function call?

                self.ret(ret.regs.rax)

            elif not enable_precondition:
                ret = return_values.pop()
                for val in return_values:
                    s = self.state.copy()
                    s.regs.eax = val[0]
                    for constr in val[2]:
                        s.solver.add(constr)
                    self.successors.add_successor(
                        state=s, target=ret_addr, guard=val[1], jumpkind="Ijk_Ret"
                    )  # get successor from function call?
                for constr in ret[2]:
                    self.state.solver.add(constr)
                self.ret(ret[0])
        except IndexError:
            self.ret(None)

        # ret_expr = ret_val.return_expr
        # currently only works unconditional writes like that...
        # for mem_write in ret_val.memory_writes:
        # print(f"Writing {mem_write[1]} to address: {mem_write[0]}")
        #    self.state.memory.store(addr=mem_write[0], data=mem_write[1])
        # print(f"{self.state.memory.load(mem_write[0], int(mem_write[1].size() / 8))}")
        # IPython.embed()

        # TODO: find all touched registers an set them to unconstrained.
        #      requires table and bottom up approach
