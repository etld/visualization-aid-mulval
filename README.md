# Visualization aid for MulVAL attack graphs

Attack graphs can be quite difficult to seize at the beginning, especially with important network topologies. This project aims to help beginners visualize MulVAL attack graphs.
The main reference for this project is the work of *Homer et al.* in which they describe a visualization of attack graphs that overlays the attack paths on the network topology. In this project, we group machines by clusters. The attack paths are then superposed to the network topology. This allows to visualize the real path of an attacker on the network, from one machine to another, until he reaches his goal.

## How to use the scripts

In order to run properly, the scripts need the attack graph output by MulVAL in CSV format. This includes two files : *ARCS.CSV* and *VERTICES.CSV*. As we leverage the network configuration for visualization purposes, the network topology is also needed. It has to be described in the *topology.conf* file, which follows a very simple structure. Each line declares a cluster with its machines. Once this three files are put into a folder *TestcaseX*, just set the variable ```TESTCASE_NUMBER``` in *visualization.py* to the number of your testcase. The scripts can then be run using the command below (we are using Python 3.10.6) :

```
python .\visualization.py
```

You can then retrieve the simplified attack graph *graph.png* in your testcase folder.

## References

Homer, J., Varikuti, A., Ou, X., McQueen, M.A. (2008). Improving Attack Graph Visualization through Data Reduction and Attack Grouping . In: Goodall, J.R., Conti, G., Ma, KL. (eds) Visualization for Computer Security. VizSec 2008. Lecture Notes in Computer Science, vol 5210. Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-540-85933-8_7