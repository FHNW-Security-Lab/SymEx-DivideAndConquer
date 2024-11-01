import angr
import os, sys
from Analyzer import Analyzer
from Vulnerability_Analyser import Vulnerability_Analyser

import IPython


def main(argv):
    if len(argv) < 2:
        return
    a = Analyzer(argv[1], auto_load_libs=False)
    # a.printAllCalledFunctions(exclude_sysfunc=True)
    vulnerability_analyser = Vulnerability_Analyser(a.project)
    a.runFunctionBasedAnalysis(vulnerability_analyser)
    print("End")
    # print(a.getEntryFunction())
    # print(a.getListOfAllFunctionsAddresses())
    # print(a.getListOfCalledFunctions(a.function_prototypes.kb.functions["add1"]))
    # print(a.getListOfFunctionsInMain())
    # IPython.embed()


if __name__ == "__main__":
    main(sys.argv)
