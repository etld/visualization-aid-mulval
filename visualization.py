import graphviz
from tools import *

TESTCASE_NUMBER = 1

g = graphviz.Digraph(format='png')

add_clusters(g,TESTCASE_NUMBER)

vertices,arcs,vulnList,created_vuln_edges = getData(TESTCASE_NUMBER)

add_netAccess_edges(g,vertices,arcs,vulnList,created_vuln_edges)
add_nfsSemantics_edges(g,vertices,arcs,vulnList,created_vuln_edges)
add_nfsShell_edges(g,vertices,arcs,vulnList,created_vuln_edges)

g.render(filename="graph",directory='Testcase'+str(TESTCASE_NUMBER))
