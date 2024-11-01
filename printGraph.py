import angr
from angrutils import *
import os, sys


def main(argv):
    if len(argv) < 3:
        print(f"Usage: python3 printGraph.py <target binary> <filename graph>")
        return

    prog_name = argv[1]
    graph_file = argv[2]
    project = angr.Project(prog_name, auto_load_libs=False)
    printGraph(project, graph_file)


def printGraph(project: angr.Project, filename: str):
    """
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
    cfg.remove_fakerets()
    plot_cfg(
        cfg, filename, asminst=True, remove_imports=False, remove_path_terminator=False
    )


if __name__ == "__main__":
    main(sys.argv)
