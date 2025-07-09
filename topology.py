#!/usr/bin/python
import threading
import random
import time
# Import compatibility layer for Python 3.13
import distutils_compat
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController  # Controller


class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)
        info("*** Starting controller\n")
        c1 = self.net.addController("c1", controller=RemoteController)  # Controller
        c1.start()

        # definition of hosts
        info("*** Adding hosts and switches\n")
        self.h1 = self.net.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1")
        self.h2 = self.net.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2")
        self.h3 = self.net.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3")
        self.h4 = self.net.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4")
        self.h5 = self.net.addHost("h5", mac="00:00:00:00:00:05", ip="10.0.0.5")
        self.h6 = self.net.addHost("h6", mac="00:00:00:00:00:06", ip="10.0.0.6")
        self.h7 = self.net.addHost("h7", mac="00:00:00:00:00:07", ip="10.0.0.7")
        self.h8 = self.net.addHost("h8", mac="00:00:00:00:00:08", ip="10.0.0.8")
        self.h9 = self.net.addHost("h9", mac="00:00:00:00:00:09", ip="10.0.0.9")
        self.h10 = self.net.addHost("h10", mac="00:00:00:00:00:0A", ip="10.0.0.10")
        self.h11 = self.net.addHost("h11", mac="00:00:00:00:00:0B", ip="10.0.0.11")
        self.h12 = self.net.addHost("h12", mac="00:00:00:00:00:0C", ip="10.0.0.12")

        # definition of switches
        self.s1 = self.net.addSwitch("s1", cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch("s2", cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch("s3", cls=OVSKernelSwitch)
        self.s4 = self.net.addSwitch("s4", cls=OVSKernelSwitch)
        self.s5 = self.net.addSwitch("s5", cls=OVSKernelSwitch)
        self.s6 = self.net.addSwitch("s6", cls=OVSKernelSwitch)
        self.s7 = self.net.addSwitch("s7", cls=OVSKernelSwitch)
        self.s8 = self.net.addSwitch("s8", cls=OVSKernelSwitch)
        self.s9 = self.net.addSwitch("s9", cls=OVSKernelSwitch)
        self.s10 = self.net.addSwitch("s10", cls=OVSKernelSwitch)

        info("*** Adding links\n")
        self.net.addLink(self.h1, self.s1, bw=10, delay="0.0025ms")
        self.net.addLink(self.h4, self.s1, bw=10, delay="0.0025ms")
        self.s1_to_s3 = self.net.addLink(self.s1, self.s3, bw=6, delay="25ms")
        self.net.addLink(self.h2, self.s2, bw=10, delay="0.0025ms")
        self.s2_to_s3 = self.net.addLink(self.s2, self.s3, bw=6, delay="25ms")
        self.s3_to_s4 = self.net.addLink(self.s3, self.s4, bw=6, delay="25ms")
        self.net.addLink(self.s4, self.h3, bw=10, delay="0.0025ms")
        self.s3_to_s5 = self.net.addLink(self.s3, self.s5, bw=6, delay="25ms")
        self.net.addLink(self.s5, self.h5, bw=10, delay="0.0025ms")
        self.net.addLink(self.s5, self.h6, bw=10, delay="0.0025ms")
        self.s3_to_s6 = self.net.addLink(self.s3, self.s6, bw=6, delay="25ms")
        self.s6_to_s7 = self.net.addLink(self.s6, self.s7, bw=6, delay="25ms")
        self.net.addLink(self.s7, self.h7, bw=10, delay="0.0025ms")
        self.net.addLink(self.s7, self.h8, bw=10, delay="0.0025ms")
        self.s6_to_s8 = self.net.addLink(self.s6, self.s8, bw=6, delay="25ms")
        self.net.addLink(self.s8, self.h9, bw=10, delay="0.0025ms")
        self.s6_to_s9 = self.net.addLink(self.s6, self.s9, bw=6, delay="25ms")
        self.net.addLink(self.s9, self.h10, bw=10, delay="0.0025ms")
        self.s6_to_s10 = self.net.addLink(self.s6, self.s10, bw=6, delay="25ms")
        self.net.addLink(self.s10, self.h11, bw=10, delay="0.0025ms")
        self.net.addLink(self.s10, self.h12, bw=10, delay="0.0025ms")

        info("*** Starting network\n")
        self.net.build()
        self.net.start()


...
if __name__ == "__main__":

    setLogLevel("info")
    info("starting the environment\n")
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)
