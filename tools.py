import pandas as pd

# Reads the topology.conf file and adds the clusters to the graph
def add_clusters(g,testcaseNb):
    topologyFile = open('Testcase'+str(testcaseNb)+'/topology.conf','r')
    lines = topologyFile.readlines()
    topologyFile.close()
    i = 0
    for line in lines:
        # if the line is not a comment
        if line[0] != "#":
            with g.subgraph(name='cluster_'+str(i)) as c:
                c.attr(color='blue')
                c.node_attr['style'] = 'filled'
                j = line.find(":")
                c.attr(label=line[:j])
                machines = line[j+1:].split(",")
                # for each machine in the cluster
                for machine in machines:
                    c.node(machine)
            i+=1

# Reads the CSV files to retrieve data concerning the MulVAL attack graph and returns the necessary data structures
def getData(testcaseNb):
    vertices = pd.read_csv("Testcase"+str(testcaseNb)+"/VERTICES.CSV", header=None, names=["node","label","type","metric"])
    arcs = pd.read_csv("Testcase"+str(testcaseNb)+"/ARCS.CSV", header=None, names=["child","parent","metric"])

    vul_prolog = vertices[vertices.label.str.startswith("vulExist")]
    vulLabel = vul_prolog['label'].str.extract(r'\((\w+)\,(.*?)\)')
    vulnList = pd.DataFrame(vulLabel.values, columns=['machine', 'vuln'])
    created_vuln_edges = set()

    return vertices,arcs,vulnList,created_vuln_edges

# Adds the netAccess edges. It only takes into consideration the two rules described as 'multi-hop access' and 'direct network access' in MulVAL (see /mulval/kb/interaction_rules.P)
def add_netAccess_edges(g, vertices, arcs, vulnList, created_vuln_edges):

    netAccess = vertices[vertices.label.str.contains("direct network access") | vertices.label.str.contains("multi-hop access")]
    
    for _, row in netAccess.iterrows():
        child = row['node']
        # Gets the parent nodes, which contains notably the hacl predicate
        parents = arcs.loc[arcs.child == child, 'parent'].values

        for node in parents:
            label = vertices.loc[vertices.node == node, "label"].values[0]

            # If the label is not a hacl predicate, it is not of interest
            if label.startswith("hacl"):
                src,dst,prot,port = label[5:-1].split(",")
                # Adds the edge to the graph
                g.edge(src, dst, "netAccess on "+prot+":"+port)

                # As dst could be a new compromised machine, we have to add the vulnerabilities used on it
                if dst in vulnList['machine'].values :
                    vulns = vulnList.loc[vulnList['machine'] == dst, 'vuln'].values
                    for vuln in vulns :
                        if(vuln, dst) not in created_vuln_edges :
                            g.node(vuln, color="red")
                            g.edge(vuln, dst, "vulExists", color="red", arrowhead="dot")
                            created_vuln_edges.add((vuln, dst))

# Adds the edges described as 'NFS semantics' in MulVAL
def add_nfsSemantics_edges(g, vertices, arcs, vulnList, created_vuln_edges):
    
    nfsSemantics = vertices[vertices.label.str.contains("NFS semantics")]

    for _, row in nfsSemantics.iterrows():
        child = row['node']
        # Gets the parent nodes
        parents = arcs.loc[arcs.child == child, 'parent'].values
        
        # Retrieve the accessFile node and nfsMounted node, each of them will give important pieces of information
        accessFile = ""
        nfsMounted = ""
        for node in parents:
            label = vertices.loc[vertices.node == node, "label"].values[0]
            if label.startswith("nfsMounted"):
                nfsMounted = label
            else:
                accessFile = label
        
        client, clientPath, server, serverPath, access = nfsMounted[11:-1].split(",")

        # In a 'NFS semantics' rule, the attack can go either from the client to the server or from the server to the client.
        # By reading the accessFile predicate, we know the source of the attack
        src = accessFile[11:-1].split(",")[0]
        dst = ""
        if src == client:
            dst = server
        else :
            dst = client
        
        lbl = 'NFS Mounted'+' ('+access+')\n'+client+':'+clientPath+'\n'+server+':'+serverPath
        g.edge(src,dst,lbl)

        # As dst could be a new compromised machine, we have to add the vulnerabilities used on it
        if dst in vulnList['machine'].values :
            vulns = vulnList.loc[vulnList['machine'] == dst, 'vuln'].values
            for vuln in vulns :
                if (vuln, dst) not in created_vuln_edges :
                    g.node(vuln, color="red")
                    g.edge(vuln, dst, "vulExists", color="red", arrowhead="dot")
                    created_vuln_edges.add((vuln, dst))

def add_nfsShell_edges(g, vertices, arcs, vulnList, created_vuln_edges):

    nfsShell = vertices[vertices.label.str.contains("NFS shell")]

    for _, row in nfsShell.iterrows():
        child = row['node']
        
        # Gets the parent nodes
        parents = arcs.loc[arcs.child == child, 'parent'].values
        for node in parents:
            label = vertices.loc[vertices.node == node, "label"].values[0]

            # If the label is not a nfsExportInfo predicate, it is not of interest
            if label.startswith("nfsExportInfo"):
                server, path, access, client = label[14:-1].split(",")
                lbl = 'NFS shell'+' ('+access+')\n'+client+'\n'+server+':'+path
                g.edge(client, server, lbl)

                # As the server could be a new compromised machine, we have to add the vulnerabilities used on it
                if server in vulnList['machine'].values:
                    vulns = vulnList.loc[vulnList['machine'] == server, 'vuln'].values
                    for vuln in vulns :
                        if (vuln, server) not in created_vuln_edges :
                            g.node(vuln, color="red")
                            g.edge(vuln, server, "vulExists", color="red", arrowhead="dot")
                            created_vuln_edges.add((vuln, row.server))

