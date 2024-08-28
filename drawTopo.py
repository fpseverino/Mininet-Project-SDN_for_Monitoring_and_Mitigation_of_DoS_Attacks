import os
from mininet.log import info

def draw_topology_with_graphviz(net):
        dot_filename = "topology.dot"
        png_filename = "topology.png"

        # Open a file to write the DOT file
        with open(dot_filename, "w") as f:
            f.write("graph G {\n")
            
            # Set the DPI (Dots per Inch) for better resolution
            f.write('    graph [dpi=300, rankdir=LR];\n')
            
             # Add nodes (hosts and switches) with images and labels in HTML-like format
            # Reduced fontsize for labels
            for host in net.hosts:
                f.write(f'    {host.name} [label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">'
                        f'<TR><TD><IMG SRC="./botFiles/host.png" SCALE="TRUE"/></TD></TR>'
                        f'<TR><TD ALIGN="CENTER" PORT="label">{host.name}</TD></TR>'
                        f'</TABLE>>, shape=plaintext, width=0.2, height=0.2, fontsize=10];\n')
            for switch in net.switches:
                f.write(f'    {switch.name} [label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">'
                        f'<TR><TD><IMG SRC="./botFiles/switch.png" SCALE="TRUE"/></TD></TR>'
                        f'<TR><TD ALIGN="CENTER" PORT="label">{switch.name}</TD></TR>'
                        f'</TABLE>>, shape=plaintext, width=0.2, height=0.2, fontsize=10];\n')
                        
            # Add links
            for link in net.links:
                node1 = link.intf1.node.name
                node2 = link.intf2.node.name
                f.write(f'    {node1} -- {node2};\n')

            f.write("}\n")

        # Convert the DOT file to a PNG image using Graphviz
        os.system(f"dot -Tpng {dot_filename} -o {png_filename}")
        info(f"Topology image saved as {png_filename}\n")
