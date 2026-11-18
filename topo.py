from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01') # Legitimate Client
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # Attacker Client
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # Application Server
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04') # Centralized Logger

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = FirewallTopo()
    # Uses the native OpenFlow learning controller
    net = Mininet(topo=topo, controller=Controller, switch=OVSSwitch)
    net.start()
    CLI(net)
    net.stop()
