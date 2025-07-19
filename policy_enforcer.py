from policy_maker import Policy
from blocklist import Blocklist

import threading, time
from queue import Queue

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

class PolicyEnforcer(threading.Thread):
    def __init__(self, controller, policy_queue: Queue, blocklist: Blocklist):
        '''
        Receives policy and enforces it
        '''
        super().__init__(daemon=True)
        self.controller = controller
        self.logger = self.controller.logger
        self.policy_q: Queue = policy_queue
        self.blocklist: Blocklist = blocklist

    def run(self):
        # Load blocklist and enforce it
        # At startup the blocklist will contain only the admin-enforced blocks
        while not self.controller.datapaths:
            time.sleep(3)
            
        for obj in self.blocklist.values():
            dpid = obj[0]
            src = obj[1]
            dst = obj[2] if obj[2] else None

            dp = self.controller.datapaths.get(dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            if dst:
                match = parser.OFPMatch(eth_src = src, eth_dst = dst)
                self.logger.info(RED + f"Flow from {src} to {dst} through switch {dpid} blocked from file" + RESET)
            else:
                match = parser.OFPMatch(eth_src = src)
                self.logger.info(RED + f"All flows from {src} through switch {dpid} blocked from file" + RESET)
            
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=1000,
                match=match,
                instructions=[],
                command=ofp.OFPFC_ADD
            )
            dp.send_msg(mod)

        while True:
            ev: Policy = self.policy_q.get()
            dpid = ev.dpid
            eth_src = ev.eth_src
            eth_dst = ev.eth_dst
            block = ev.block

            # Avoid modifying policies set from external agents
            if (dpid, eth_src, eth_dst) in self.blocklist.values(block_type="external"):
                continue

            dp = self.controller.datapaths.get(dpid)
            if not dp:
                continue

            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_src = eth_src, eth_dst = eth_dst)

            if block:
                self.logger.info(RED + f"Flusso da {eth_src} a {eth_dst} in switch {dpid} bloccato" + RESET)
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=1000,
                    match=match,
                    instructions=[],
                    command=ofp.OFPFC_ADD,
                    idle_timeout = 60,	# La regola scade dopo Xs di idle
                )
                self.blocklist.add(dpid, eth_src, eth_dst)
            else:
                self.logger.info(GREEN + f"Flusso da {eth_src} a {eth_dst} in switch {dpid} ripristinato" + RESET)
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=1000,
                    match=match,
                    command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY
                )
                self.blocklist.remove(dpid, eth_src, eth_dst)

            dp.send_msg(mod)