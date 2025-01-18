import re
import csv
import os
import statistics
from typing import List, Dict, Any

class PacketFeatureExtractor:
    def __init__(self):
        self.reset_flow_data()

    def reset_flow_data(self):
        """Reset all flow-related data structures."""
        self.flow_start_time = None
        self.flow_end_time = None
        self.fwd_packets = []
        self.bwd_packets = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_iat_times = []
        self.bwd_iat_times = []
        self.last_fwd_packet_time = None
        self.last_bwd_packet_time = None
        
        # Flag counters
        self.flags = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 
            'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0
        }
        
        # Other metrics
        self.total_bytes = 0
        self.init_fwd_win_bytes = None
        self.init_bwd_win_bytes = None
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.active_times = []
        self.idle_times = []

    def parse_packet(self, packet_section: str) -> Dict[str, Any]:
        """Parse individual packet and extract features."""
        features = {}
        
        # Time parsing
        time_match = re.search(r'Arrival Time: (.+)', packet_section)
        current_time = float(re.search(r'Epoch Arrival Time: ([\d.]+)', packet_section).group(1)) if time_match else None
        
        # Determine packet direction based on port
        src_port = int(re.search(r'Source Port: (\d+)', packet_section).group(1)) if re.search(r'Source Port: (\d+)', packet_section) else None
        dst_port = int(re.search(r'Destination Port: (\d+)', packet_section).group(1)) if re.search(r'Destination Port: (\d+)', packet_section) else None
        
        # Packet length
        packet_length = int(re.search(r'Frame Length: (\d+) bytes', packet_section).group(1)) if re.search(r'Frame Length: (\d+) bytes', packet_section) else 0
        
        # Flag analysis
        flags_match = re.search(r'Flags: 0x[0-9a-f]+ \(([^)]+)\)', packet_section)
        flags = flags_match.group(1) if flags_match else ''
        
        # Tracking flow start and end times
        if self.flow_start_time is None:
            self.flow_start_time = current_time
        self.flow_end_time = current_time
        
        # Classify packet as forward or backward
        is_fwd_packet = True  # Default assumption
        
        # Packet length tracking
        if is_fwd_packet:
            self.fwd_packets.append(packet_length)
            self.fwd_packet_lengths.append(packet_length)
            
            # IAT calculation for forward packets
            if self.last_fwd_packet_time is not None and current_time is not None:
                fwd_iat = current_time - self.last_fwd_packet_time
                self.fwd_iat_times.append(fwd_iat)
            self.last_fwd_packet_time = current_time
        else:
            self.bwd_packets.append(packet_length)
            self.bwd_packet_lengths.append(packet_length)
            
            # IAT calculation for backward packets
            if self.last_bwd_packet_time is not None:
                bwd_iat = current_time - self.last_bwd_packet_time
                self.bwd_iat_times.append(bwd_iat)
            self.last_bwd_packet_time = current_time
        
        # Flag counting
        flag_mappings = {
            'FIN': 'FIN', 'SYN': 'SYN', 'RST': 'RST', 
            'PSH': 'PSH', 'ACK': 'ACK', 'URG': 'URG'
        }
        
        for flag_key, flag_name in flag_mappings.items():
            if flag_key.lower() in flags.lower():
                self.flags[flag_name] += 1
        
        return features

    def calculate_flow_features(self) -> Dict[str, Any]:
        """Calculate comprehensive flow features."""
        flow_features = {}
        
        # Basic flow duration and rate calculations
        flow_duration = (self.flow_end_time - self.flow_start_time) if self.flow_start_time and self.flow_end_time else 0
        
        # Packet and byte calculations
        flow_features['Protocol'] = 6  # Default assumption as TCP
        flow_features['Flow Duration'] = flow_duration * 1000  # Convert to milliseconds
        flow_features['Total Fwd Packets'] = len(self.fwd_packets)
        flow_features['Total Backward Packets'] = len(self.bwd_packets)
        
        # Packet length features
        flow_features['Fwd Packets Length Total'] = sum(self.fwd_packet_lengths)
        flow_features['Bwd Packets Length Total'] = sum(self.bwd_packet_lengths)
        
        # Packet length statistics
        flow_features['Fwd Packet Length Max'] = max(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        flow_features['Fwd Packet Length Min'] = min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        flow_features['Fwd Packet Length Mean'] = statistics.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        flow_features['Fwd Packet Length Std'] = statistics.stdev(self.fwd_packet_lengths) if len(self.fwd_packet_lengths) > 1 else 0
        
        flow_features['Bwd Packet Length Max'] = max(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        flow_features['Bwd Packet Length Min'] = min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        flow_features['Bwd Packet Length Mean'] = statistics.mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        flow_features['Bwd Packet Length Std'] = statistics.stdev(self.bwd_packet_lengths) if len(self.bwd_packet_lengths) > 1 else 0
        
        # Flow rate calculations
        flow_features['Flow Bytes/s'] = sum(self.fwd_packet_lengths + self.bwd_packet_lengths) / max(flow_duration, 0.001)
        flow_features['Flow Packets/s'] = len(self.fwd_packets + self.bwd_packets) / max(flow_duration, 0.001)
        
        # Inter-Arrival Time (IAT) calculations
        flow_features['Flow IAT Mean'] = statistics.mean(self.fwd_iat_times + self.bwd_iat_times) if self.fwd_iat_times + self.bwd_iat_times else 0
        flow_features['Flow IAT Std'] = statistics.stdev(self.fwd_iat_times + self.bwd_iat_times) if len(self.fwd_iat_times + self.bwd_iat_times) > 1 else 0
        flow_features['Flow IAT Max'] = max(self.fwd_iat_times + self.bwd_iat_times) if self.fwd_iat_times + self.bwd_iat_times else 0
        flow_features['Flow IAT Min'] = min(self.fwd_iat_times + self.bwd_iat_times) if self.fwd_iat_times + self.bwd_iat_times else 0
        
        # Forward IAT calculations
        flow_features['Fwd IAT Total'] = sum(self.fwd_iat_times)
        flow_features['Fwd IAT Mean'] = statistics.mean(self.fwd_iat_times) if self.fwd_iat_times else 0
        flow_features['Fwd IAT Std'] = statistics.stdev(self.fwd_iat_times) if len(self.fwd_iat_times) > 1 else 0
        flow_features['Fwd IAT Max'] = max(self.fwd_iat_times) if self.fwd_iat_times else 0
        flow_features['Fwd IAT Min'] = min(self.fwd_iat_times) if self.fwd_iat_times else 0
        
        # Backward IAT calculations
        flow_features['Bwd IAT Total'] = sum(self.bwd_iat_times)
        flow_features['Bwd IAT Mean'] = statistics.mean(self.bwd_iat_times) if self.bwd_iat_times else 0
        flow_features['Bwd IAT Std'] = statistics.stdev(self.bwd_iat_times) if len(self.bwd_iat_times) > 1 else 0
        flow_features['Bwd IAT Max'] = max(self.bwd_iat_times) if self.bwd_iat_times else 0
        flow_features['Bwd IAT Min'] = min(self.bwd_iat_times) if self.bwd_iat_times else 0
        
        # Flag calculations
        flow_features['Fwd PSH Flags'] = self.flags['PSH']
        flow_features['Bwd PSH Flags'] = 0  # Not implemented in this version
        flow_features['Fwd URG Flags'] = self.flags['URG']
        flow_features['Bwd URG Flags'] = 0  # Not implemented in this version
        
        # Flag counts
        for flag in ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'CWE', 'ECE']:
            flow_features[f'{flag} Flag Count'] = self.flags[flag]
        
        # Additional packet characteristics
        all_packet_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        flow_features['Packet Length Min'] = min(all_packet_lengths) if all_packet_lengths else 0
        flow_features['Packet Length Max'] = max(all_packet_lengths) if all_packet_lengths else 0
        flow_features['Packet Length Mean'] = statistics.mean(all_packet_lengths) if all_packet_lengths else 0
        flow_features['Packet Length Std'] = statistics.stdev(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
        flow_features['Packet Length Variance'] = statistics.variance(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
        
        # Directional packet rates
        flow_features['Fwd Packets/s'] = len(self.fwd_packets) / max(flow_duration, 0.001)
        flow_features['Bwd Packets/s'] = len(self.bwd_packets) / max(flow_duration, 0.001)
        
        # Dowm/Up Ratio
        flow_features['Down/Up Ratio'] = len(self.bwd_packets) / max(len(self.fwd_packets), 1)
        
        # Average packet sizes
        flow_features['Avg Packet Size'] = sum(all_packet_lengths) / max(len(all_packet_lengths), 1)
        flow_features['Avg Fwd Segment Size'] = sum(self.fwd_packet_lengths) / max(len(self.fwd_packet_lengths), 1)
        flow_features['Avg Bwd Segment Size'] = sum(self.bwd_packet_lengths) / max(len(self.bwd_packet_lengths), 1)
        
        return flow_features

def parse_packet_file(input_file: str, output_file: str):
    """
    Parse a packet capture text file and extract comprehensive flow features.
    
    Args:
    input_file (str): Path to the input packet capture text file
    output_file (str): Path to the output CSV file
    """
    # Read the input file
    with open(input_file, 'r', encoding='utf-8') as f:
        file_contents = f.read()
    
    # Split the file into individual packet sections
    packet_sections = file_contents.split('Frame ')[1:]
    
    # Initialize feature extractor
    extractor = PacketFeatureExtractor()
    
    # Process each packet
    for packet_section in packet_sections:
        # Prepend 'Frame ' to make regex work
        packet_section = 'Frame ' + packet_section
        extractor.parse_packet(packet_section)
    
    # Calculate final flow features
    flow_features = extractor.calculate_flow_features()
    
    # Write to CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=list(flow_features.keys()))
        writer.writeheader()
        writer.writerow(flow_features)
    
    print(f"Successfully extracted features to {output_file}") 