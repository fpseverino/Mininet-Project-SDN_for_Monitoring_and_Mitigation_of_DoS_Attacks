# Mininet-Project - SDN for Monitoring and Mitigation of DoS Attacks

The project consists in a Mininet Topology composed by 4 host (h1, h2, h4 as clients and h3 as a server) and 4 OVSKernelSwitch (Open vSwitch) connected to the hosts in thi way:
- h1 and h4 are connected to s1
- h2 is connected to s2
- s1 and s2 are connected to s3
- s3 is connected to s4
- h4 is connected to s4

The switch are controlled by a SDN Controller started with Ryu manager. 

![image](https://github.com/user-attachments/assets/b03861eb-1c78-471f-bc3c-3e64fda7c4be)
