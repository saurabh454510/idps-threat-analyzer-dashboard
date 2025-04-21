import csv
import random
from datetime import datetime

# Feature names in snake_case
features = [
    'destination_port', 'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_fwd_packets', 'total_length_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
    'bwd_packet_length_std', 'flow_bytes_per_sec', 'flow_packets_per_sec', 'flow_iat_mean',
    'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean',
    'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean',
    'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_urg_flags', 'bwd_urg_flags', 'fwd_header_length', 'bwd_header_length',
    'fwd_packets_per_sec', 'bwd_packets_per_sec', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count',
    'ack_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
    'down_up_ratio', 'average_packet_size', 'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'fwd_header_length_1', 'fwd_avg_bytes_per_bulk', 'fwd_avg_packets_per_bulk', 'fwd_avg_bulk_rate',
    'bwd_avg_bytes_per_bulk', 'bwd_avg_packets_per_bulk', 'bwd_avg_bulk_rate', 'subflow_fwd_packets',
    'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes', 'init_win_bytes_forward',
    'init_win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'active_mean',
    'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    'label'
]

def generate_normal(num_samples=100):
    data = []
    for _ in range(num_samples):
        duration = random.randint(100, 10000)  # ms
        fwd_packets = random.randint(5, 50)
        bwd_packets = random.randint(5, 50)
        fwd_length = random.randint(1000, 10000)
        bwd_length = random.randint(500, 8000)
        
        data.append({
            'destination_port': random.choice([80, 443, 22, 53, 3389]),
            'flow_duration': duration,
            'total_fwd_packets': fwd_packets,
            'total_backward_packets': bwd_packets,
            'total_length_fwd_packets': fwd_length,
            'total_length_bwd_packets': bwd_length,
            'fwd_packet_length_max': random.randint(500, 2000),
            'fwd_packet_length_min': random.randint(20, 100),
            'fwd_packet_length_mean': fwd_length/fwd_packets,
            'fwd_packet_length_std': random.randint(50, 200),
            'bwd_packet_length_max': random.randint(300, 1500) if bwd_packets > 0 else 0,
            'bwd_packet_length_min': random.randint(10, 50) if bwd_packets > 0 else 0,
            'bwd_packet_length_mean': bwd_length/bwd_packets if bwd_packets > 0 else 0,
            'bwd_packet_length_std': random.randint(20, 150) if bwd_packets > 0 else 0,
            'flow_bytes_per_sec': (fwd_length + bwd_length) * 1000 / duration,
            'flow_packets_per_sec': (fwd_packets + bwd_packets) * 1000 / duration,
            'flow_iat_mean': duration / (fwd_packets + bwd_packets),
            'flow_iat_std': random.uniform(0.1, 10),
            'flow_iat_max': random.uniform(1, 100),
            'flow_iat_min': random.uniform(0.01, 1),
            'fwd_iat_total': duration,
            'fwd_iat_mean': duration / fwd_packets,
            'fwd_iat_std': random.uniform(0.1, 10),
            'fwd_iat_max': random.uniform(1, 100),
            'fwd_iat_min': random.uniform(0.01, 1),
            'bwd_iat_total': duration if bwd_packets > 0 else 0,
            'bwd_iat_mean': duration / bwd_packets if bwd_packets > 0 else 0,
            'bwd_iat_std': random.uniform(0.1, 10) if bwd_packets > 0 else 0,
            'bwd_iat_max': random.uniform(1, 100) if bwd_packets > 0 else 0,
            'bwd_iat_min': random.uniform(0.01, 1) if bwd_packets > 0 else 0,
            'fwd_psh_flags': random.randint(0, 1),
            'bwd_psh_flags': random.randint(0, 1),
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fwd_header_length': random.randint(20, 60),
            'bwd_header_length': random.randint(20, 60),
            'fwd_packets_per_sec': fwd_packets * 1000 / duration,
            'bwd_packets_per_sec': bwd_packets * 1000 / duration if bwd_packets > 0 else 0,
            'min_packet_length': random.randint(20, 100),
            'max_packet_length': random.randint(500, 2000),
            'packet_length_mean': (fwd_length + bwd_length) / (fwd_packets + bwd_packets),
            'packet_length_std': random.randint(50, 200),
            'packet_length_variance': random.randint(2500, 40000),
            'fin_flag_count': random.randint(0, 1),
            'syn_flag_count': random.randint(0, 1),
            'rst_flag_count': 0,
            'psh_flag_count': random.randint(0, 1),
            'ack_flag_count': random.randint(1, bwd_packets) if bwd_packets > 0 else 0,
            'urg_flag_count': 0,
            'cwe_flag_count': 0,
            'ece_flag_count': 0,
            'down_up_ratio': bwd_packets / fwd_packets if fwd_packets > 0 else 0,
            'average_packet_size': (fwd_length + bwd_length) / (fwd_packets + bwd_packets),
            'avg_fwd_segment_size': fwd_length / fwd_packets,
            'avg_bwd_segment_size': bwd_length / bwd_packets if bwd_packets > 0 else 0,
            'fwd_header_length_1': random.randint(20, 60),
            'fwd_avg_bytes_per_bulk': 0,
            'fwd_avg_packets_per_bulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytes_per_bulk': 0,
            'bwd_avg_packets_per_bulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': fwd_packets,
            'subflow_fwd_bytes': fwd_length,
            'subflow_bwd_packets': bwd_packets,
            'subflow_bwd_bytes': bwd_length,
            'init_win_bytes_forward': random.choice([8192, 65535]),
            'init_win_bytes_backward': random.choice([8192, 65535]),
            'act_data_pkt_fwd': random.randint(1, fwd_packets),
            'min_seg_size_forward': random.randint(20, 60),
            'active_mean': random.uniform(1, 100),
            'active_std': random.uniform(0.1, 10),
            'active_max': random.uniform(10, 200),
            'active_min': random.uniform(0.1, 10),
            'idle_mean': random.uniform(1, 100),
            'idle_std': random.uniform(0.1, 10),
            'idle_max': random.uniform(10, 200),
            'idle_min': random.uniform(0.1, 10),
            'label': 'normal'
        })
    return data

def generate_attack(num_samples=100, attack_type='ddos'):
    data = []
    for _ in range(num_samples):
        if attack_type == 'ddos':
            port = random.choice([80, 443])
            duration = random.randint(10, 100)
            fwd_packets = random.randint(500, 5000)
            bwd_packets = random.randint(0, 10)
            fwd_length = fwd_packets * random.randint(10, 100)
            bwd_length = bwd_packets * random.randint(10, 100)
            flow_rate = (fwd_length + bwd_length) * 1000 / duration
        elif attack_type == 'portscan':
            port = random.choice([22, 3389, 445])
            duration = random.randint(50, 500)
            fwd_packets = random.randint(100, 1000)
            bwd_packets = random.randint(0, 5)
            fwd_length = fwd_packets * random.randint(20, 100)
            bwd_length = bwd_packets * random.randint(20, 100)
            flow_rate = (fwd_length + bwd_length) * 1000 / duration
        else:  # generic attack
            port = random.randint(10000, 20000)
            duration = random.randint(10, 100)
            fwd_packets = random.randint(1000, 10000)
            bwd_packets = random.randint(0, 5)
            fwd_length = fwd_packets * random.randint(5, 50)
            bwd_length = bwd_packets * random.randint(5, 50)
            flow_rate = (fwd_length + bwd_length) * 1000 / duration
        
        data.append({
            'destination_port': port,
            'flow_duration': duration,
            'total_fwd_packets': fwd_packets,
            'total_backward_packets': bwd_packets,
            'total_length_fwd_packets': fwd_length,
            'total_length_bwd_packets': bwd_length,
            'fwd_packet_length_max': random.randint(50, 500),
            'fwd_packet_length_min': random.randint(5, 20),
            'fwd_packet_length_mean': fwd_length/fwd_packets,
            'fwd_packet_length_std': random.randint(5, 50),
            'bwd_packet_length_max': random.randint(20, 200) if bwd_packets > 0 else 0,
            'bwd_packet_length_min': random.randint(2, 10) if bwd_packets > 0 else 0,
            'bwd_packet_length_mean': bwd_length/bwd_packets if bwd_packets > 0 else 0,
            'bwd_packet_length_std': random.randint(2, 20) if bwd_packets > 0 else 0,
            'flow_bytes_per_sec': flow_rate,
            'flow_packets_per_sec': (fwd_packets + bwd_packets) * 1000 / duration,
            'flow_iat_mean': duration / (fwd_packets + bwd_packets),
            'flow_iat_std': random.uniform(0.001, 0.1),
            'flow_iat_max': random.uniform(0.01, 1),
            'flow_iat_min': random.uniform(0.001, 0.01),
            'fwd_iat_total': duration,
            'fwd_iat_mean': duration / fwd_packets,
            'fwd_iat_std': random.uniform(0.001, 0.1),
            'fwd_iat_max': random.uniform(0.01, 1),
            'fwd_iat_min': random.uniform(0.001, 0.01),
            'bwd_iat_total': duration if bwd_packets > 0 else 0,
            'bwd_iat_mean': duration / bwd_packets if bwd_packets > 0 else 0,
            'bwd_iat_std': random.uniform(0.001, 0.1) if bwd_packets > 0 else 0,
            'bwd_iat_max': random.uniform(0.01, 1) if bwd_packets > 0 else 0,
            'bwd_iat_min': random.uniform(0.001, 0.01) if bwd_packets > 0 else 0,
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fwd_header_length': random.randint(20, 40),
            'bwd_header_length': random.randint(20, 40) if bwd_packets > 0 else 0,
            'fwd_packets_per_sec': fwd_packets * 1000 / duration,
            'bwd_packets_per_sec': bwd_packets * 1000 / duration if bwd_packets > 0 else 0,
            'min_packet_length': random.randint(5, 20),
            'max_packet_length': random.randint(50, 500),
            'packet_length_mean': (fwd_length + bwd_length) / (fwd_packets + bwd_packets),
            'packet_length_std': random.randint(5, 50),
            'packet_length_variance': random.randint(25, 2500),
            'fin_flag_count': 0,
            'syn_flag_count': 1 if attack_type == 'portscan' else 0,
            'rst_flag_count': 0,
            'psh_flag_count': 0,
            'ack_flag_count': random.randint(0, bwd_packets) if bwd_packets > 0 else 0,
            'urg_flag_count': 0,
            'cwe_flag_count': 0,
            'ece_flag_count': 0,
            'down_up_ratio': bwd_packets / fwd_packets if fwd_packets > 0 else 0,
            'average_packet_size': (fwd_length + bwd_length) / (fwd_packets + bwd_packets),
            'avg_fwd_segment_size': fwd_length / fwd_packets,
            'avg_bwd_segment_size': bwd_length / bwd_packets if bwd_packets > 0 else 0,
            'fwd_header_length_1': random.randint(20, 40),
            'fwd_avg_bytes_per_bulk': 0,
            'fwd_avg_packets_per_bulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytes_per_bulk': 0,
            'bwd_avg_packets_per_bulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': fwd_packets,
            'subflow_fwd_bytes': fwd_length,
            'subflow_bwd_packets': bwd_packets,
            'subflow_bwd_bytes': bwd_length,
            'init_win_bytes_forward': 8192,
            'init_win_bytes_backward': 8192 if bwd_packets > 0 else 0,
            'act_data_pkt_fwd': fwd_packets,
            'min_seg_size_forward': random.randint(5, 20),
            'active_mean': random.uniform(0.01, 1),
            'active_std': random.uniform(0.001, 0.1),
            'active_max': random.uniform(0.1, 2),
            'active_min': random.uniform(0.001, 0.1),
            'idle_mean': random.uniform(0.01, 1),
            'idle_std': random.uniform(0.001, 0.1),
            'idle_max': random.uniform(0.1, 2),
            'idle_min': random.uniform(0.001, 0.1),
            'label': attack_type if attack_type != 'generic' else 'attack'
        })
    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=features)
        writer.writeheader()
        writer.writerows(data)
    print(f"Saved {len(data)} samples to {filename}")

def main():
    # Generate datasets
    save_to_csv(generate_normal(1000), 'normal_traffic.csv')
    save_to_csv(generate_attack(500, 'ddos'), 'ddos_attacks.csv')
    save_to_csv(generate_attack(300, 'portscan'), 'portscan_attacks.csv')
    save_to_csv(generate_attack(200), 'generic_attacks.csv')
    
    # Combined dataset
    combined = generate_normal(1000) + generate_attack(500, 'ddos') + generate_attack(300, 'portscan') + generate_attack(200)
    save_to_csv(combined, 'combined_dataset.csv')

if __name__ == "__main__":
    main()
