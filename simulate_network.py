#!/home/nav/main_project/anomalyX/.env/bin/python
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import random
import subprocess
import threading
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

def create_nsl_kdd_network():
    """
    Create network topology similar to NSL-KDD dataset
    """
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)

    # Create network elements
    c0 = net.addController('c0')
    
    # Create switches mimicking network segments
    s1 = net.addSwitch('s1')  # Internal network
    s2 = net.addSwitch('s2')  # External network

    # Create hosts with different roles
    h1 = net.addHost('h1', ip='192.168.1.10')   # Internal server
    h2 = net.addHost('h2', ip='192.168.1.11')   # Internal client
    h3 = net.addHost('h3', ip='10.0.0.100')     # External attacker
    h4 = net.addHost('h4', ip='10.0.0.101')     # External server

    # Link network elements
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(s1, s2)

    net.start()
    return net

def generate_nsl_kdd_traffic(net):
    """
    Generate traffic patterns similar to NSL-KDD dataset
    """
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    
    # Normal traffic patterns
    h2.cmd('iperf -s -p 5001 &')  # TCP server
    h1.cmd(f'iperf -c {h2.IP()} -p 5001 -t 10 &')  # Normal TCP connection
    
    # Simulate different attack types
    attack_types = [
        # DoS attack simulation
        f'hping3 -S -p 80 --flood {h4.IP()}',
        
        # Probe attack simulation
        f'nmap -sV {h1.IP()}',
        
        # R2L (Remote to Local) attack simulation
        f'hydra -L users.txt -P pass.txt {h1.IP()} ssh',
        
        # U2R (User to Root) attack simulation
        f'sqlmap -u "http://{h1.IP()}/vulnerable.php" --dbs'
    ]
    
    # Randomly select and execute some attack types
    for _ in range(2):
        h3.cmd(random.choice(attack_types))

# def packet_capture(host, output_file):
#     """
#     Capture packets on a specific host
#     """
#     interface = f"{host.name}-eth0"
    
#     print(f"Capturing packets on {interface}")
#     scapy.sniff(
#         iface=interface, 
#         prn=lambda x: x.summary(), 
#         store=1, 
#         count=500,  # Increased packet count
#         offline=output_file
#     )

def main():
    setLogLevel('info')
    net = create_nsl_kdd_network()
    
    try:
        generate_nsl_kdd_traffic(net)
        
        # Packet capture
        capture_threads = []
        hosts = ['h1', 'h2', 'h3', 'h4']
        for host_name in hosts:
            host = net.get(host_name)
            output_file = f"/tmp/{host_name}_nsl_kdd_capture.pcap"
            
            capture_thread = threading.Thread(
                target=packet_capture, 
                args=(host, output_file)
            )
            capture_thread.start()
            capture_threads.append(capture_thread)
        
        for thread in capture_threads:
            thread.join()
        
        CLI(net)
    
    finally:
        net.stop()

if __name__ == '__main__':
    main()
