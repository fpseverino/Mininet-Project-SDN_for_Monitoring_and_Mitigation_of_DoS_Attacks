# Mininet Project - SDN for Monitoring and Mitigation of DoS Attacks

The project consists of a Mininet topology composed of 4 hosts (h1, h2, h3 as clients, and h4 as a server) and 4 OVSKernelSwitches (Open vSwitch) connected to the hosts in the following way:
- h1 and h3 are connected to s1
- h2 is connected to s2
- s1 and s2 are connected to s3
- s3 is connected to s4
- h4 is connected to s4

The switches are controlled by an SDN Controller executed using the Ryu manager module and Python 3.9 (`python3.9 -m ryu.cmd.manager ...`).

Host h1 is the DoS attacker. The aim of the project is to create an SDN controller with monitoring and mitigation capabilities:

- The **first version** is a low-budget solution. The controller sends a message to every switch in the datapath every ten seconds, requesting the stats of each port of the switch. After it receives all the stats, if the `rx-bytes/s` of a port is greater than the threshold, a counter is incremented by one. When this counter reaches 3, the `_lock` function adds a rule to the specific switch for that port. When the counter decreases to 1, the port is unlocked with the `_unlock` function, where the rule is deleted.

- In the **second version**, the same logic solution proposed in the first version is implemented on flows instead of ports. The `_lock` function creates a rule using the source MAC address of the attacker and also starts a thread to remove that rule after a `time.sleep(pow(7, n))`, where `n` is the number of times the MAC address was locked in that switch.

- In the **third version**, a Telegram bot is implemented to check the running topology and the switches' statistics. The bot also sends a message to the chat whenever a MAC address is locked or unlocked.

### The Topology (Second Version and Bot Telegram Version)
![image](https://github.com/user-attachments/assets/b03861eb-1c78-471f-bc3c-3e64fda7c4be)

## Install Requirements

Pull the version from the `VersionBotTelegram` branch and open the folder in a terminal. Install all Python requirements with:

```bash
pip install -r requirements.txt
