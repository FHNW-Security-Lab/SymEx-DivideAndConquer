import angr
import os, sys

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    res = getProximityGraph(project)
    print(res)
    lres = list(res)
    print(lres)

    
def getProximityGraph(project: angr.Project):

    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    model = angr.knowledge_plugins.cfg.cfg_model.CFGModel(0)
    graph = project.analyses.Proximity(entry_func, model, 0)
    return graph.graph.nodes

if __name__ == "__main__":
    main(sys.argv)


    #create function 
    #entry_func = cfg.kb.functions[0x40117D]
    