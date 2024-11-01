from dataclasses import dataclass
from types import NoneType
from typing import Union
import angr
import claripy
from angr.knowledge_plugins.functions.function import Function
from claripy.ast.bv import BV
from angr.sim_state import SimState


@dataclass
class functionSummary:
    f: Function
    return_reg: str
    # TODO: Not possible to create one formula that expresses all possible outcomes, change to list and
    #       check if given ret value is possible, as classic summaries do
    return_expr: list[(BV, list)]
    memory_writes: list[tuple[BV, BV, NoneType]]
    register_writes: list[tuple[Union[int, BV], BV, NoneType]]
    simgr_stash_copy: dict[str, list[SimState]]
    ret_symbol: BV
