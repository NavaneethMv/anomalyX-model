#!/home/nav/main_project/anomalyX/.env/bin/python

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import numpy as np
import pandas as pd

class NetworkFeatureExtractor:
    def __init__(self, time_window=2):
        self.time_window = time_window
        self.connections = defaultdict(lambda: {
            'start_time': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 0,
            'srv_count': 0,
            'packets': [],
            'flags': set(),
            'service': 'other'  # Added default service
        })
        
        self.conn_history = defaultdict(list)
        self.service_history = defaultdict(list)
        
    def get_connection_key(self, packet):
        try:
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    proto = 'tcp'
                else:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    proto = 'udp'
                return f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        except Exception as e:
            print(f"Error generating connection key: {e}")
        return None

    def get_service(self, packet):
        try:
            if TCP in packet:
                dport = packet[TCP].dport
            elif UDP in packet:
                dport = packet[UDP].dport
            else:
                return 'other'
                
            common_ports = {
                80: 'http',
                443: 'https',
                22: 'ssh',
                21: 'ftp',
                23: 'telnet',
                25: 'smtp',
                53: 'domain',
                3306: 'mysql',
                5432: 'postgresql'
            }
            return common_ports.get(dport, 'other')
        except Exception as e:
            print(f"Error determining service: {e}")
            return 'other'

    def get_flag(self, packet):
        try:
            if TCP in packet:
                flags = []
                if packet[TCP].flags.S: flags.append('S')
                if packet[TCP].flags.A: flags.append('A')
                if packet[TCP].flags.F: flags.append('F')
                if packet[TCP].flags.R: flags.append('R')
                if packet[TCP].flags.P: flags.append('P')
                return ''.join(flags)
        except Exception as e:
            print(f"Error getting flags: {e}")
        return ''

    def extract_basic_features(self, packet):
        features = {
            'duration': 0,
            'protocol_type': 'other',
            'service': 'other',
            'flag': '',
            'src_bytes': 0,
            'dst_bytes': 0
        }
        
        try:
            # Protocol type
            if TCP in packet:
                features['protocol_type'] = 'tcp'
            elif UDP in packet:
                features['protocol_type'] = 'udp'
            elif ICMP in packet:
                features['protocol_type'] = 'icmp'
                
            # Service
            features['service'] = self.get_service(packet)
            
            # Flag
            features['flag'] = self.get_flag(packet)
            
            # Bytes
            if IP in packet:
                features['src_bytes'] = len(packet)
                
        except Exception as e:
            print(f"Error extracting basic features: {e}")
            
        return features

    def extract_traffic_features(self, connection_key, current_time):
        features = {'count': 0, 'srv_count': 0}
        
        try:
            conn_data = self.connections[connection_key]
            
            # Count connections with same destination host
            same_host_count = sum(1 for t in self.conn_history[connection_key] 
                                if current_time - t <= self.time_window)
            features['count'] = same_host_count
            
            # Count connections with same service
            service = conn_data.get('service', 'other')
            same_srv_count = sum(1 for t in self.service_history[service] 
                               if current_time - t <= self.time_window)
            features['srv_count'] = same_srv_count
            
        except Exception as e:
            print(f"Error extracting traffic features: {e}")
            
        return features

    def extract_features(self, packet):
        try:
            current_time = time.time()
            connection_key = self.get_connection_key(packet)
            
            if connection_key is None:
                return None
                
            # Get basic features
            features = self.extract_basic_features(packet)
            
            # Update connection data
            conn_data = self.connections[connection_key]
            if not conn_data['start_time']:
                conn_data['start_time'] = current_time
            
            conn_data['service'] = features['service']
            conn_data['packets'].append(packet)
            
            if TCP in packet:
                conn_data['flags'].add(self.get_flag(packet))
            
            if IP in packet:
                conn_data['src_bytes'] += len(packet)
            
            # Calculate duration
            features['duration'] = current_time - conn_data['start_time']
            
            # Get traffic features
            traffic_features = self.extract_traffic_features(connection_key, current_time)
            features.update(traffic_features)
            
            # Update history
            self.conn_history[connection_key].append(current_time)
            self.service_history[features['service']].append(current_time)
            
            # Clean old history
            self.clean_old_history(current_time)
            
            return pd.Series(features)
            
        except Exception as e:
            print(f"Error in feature extraction: {e}")
            return None

    def clean_old_history(self, current_time):
        try:
            threshold = current_time - self.time_window
            
            for key in list(self.conn_history.keys()):
                self.conn_history[key] = [t for t in self.conn_history[key] if t > threshold]
                if not self.conn_history[key]:
                    del self.conn_history[key]
                    
            for key in list(self.service_history.keys()):
                self.service_history[key] = [t for t in self.service_history[key] if t > threshold]
                if not self.service_history[key]:
                    del self.service_history[key]
                    
        except Exception as e:
            print(f"Error cleaning history: {e}")

    def start_capture(self, interface="eth0", packet_count=100):
        print(f"Starting packet capture on interface {interface}")
        features_list = []
        
        def packet_callback(packet):
            try:
                if len(features_list) >= packet_count:
                    return
                
                features = self.extract_features(packet)
                if features is not None:
                    features_list.append(features)
                    print(f"Processed packet {len(features_list)}/{packet_count}", end='\r')
            except Exception as e:
                print(f"Error in packet callback: {e}")
        
        try:
            scapy.sniff(iface=interface, prn=packet_callback, count=packet_count)
        except Exception as e:
            print(f"Error during packet capture: {e}")
            
        if features_list:
            return pd.DataFrame(features_list)
        return pd.DataFrame()

if __name__ == "__main__":
    # Initialize the feature extractor
    extractor = NetworkFeatureExtractor(time_window=2)

    # Start capturing packets and extracting features
    # Replace "eth0" with your network interface name
    features_df = extractor.start_capture(interface="wlan0", packet_count=100)

    # The features_df will contain NSL-KDD style features for each packet
    print(features_df.head())