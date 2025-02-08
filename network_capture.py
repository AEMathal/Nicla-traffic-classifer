#!/usr/bin/env python3
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import serial

# --- Configuration: Adjust as needed ---
SERIAL_PORT = '/dev/tty.usbmodem1101'      # Change to your serial port (e.g., 'COM3' on Windows or '/dev/ttyUSB0' on Linux)
BAUD_RATE = 19200         # Must match the NICLA's Serial1 baud rate
WINDOW_DURATION = 1.0     # seconds

# Open serial port (this will be used to send the feature vector)
try:
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    print(f"Opened serial port: {SERIAL_PORT} at {BAUD_RATE} baud.")
except Exception as e:
    print(f"Error opening serial port: {e}")
    ser = None

# Global aggregator for our 1-second window statistics
aggregator = {
    "packets": 0,
    "src_bytes": 0,
    "dst_bytes": 0,
    "serror_count": 0,
    "rerror_count": 0,
    "srv_http": 0,
    "srv_other": 0,
    "flag_counts": {"RSTR": 0, "S0": 0, "S1": 0, "SF": 0},
    "wrong_fragment": 0,
    "urgent": 0,
    "land": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
}

# Map common destination ports to service names.
SERVICE_MAPPING = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    53: "dns",
    25: "smtp",
    110: "pop3",
    143: "imap",
    3389: "rdp",
}

def map_tcp_flags(tcp_flags):
    # Convert the flag value to string for mapping.
    flag_str = str(tcp_flags)
    mapping = {
        "A": "SF",    # ACK → Successful connection (SF)
        "PA": "SF",   # PUSH-ACK → Data transfer (SF)
        "S": "S0",    # SYN only: connection attempt without reply (S0)
        "SA": "S1",   # SYN-ACK: connection accepted (S1)
        "R": "RSTR",  # RST: connection reset (RSTR)
        "F": "SF",    # FIN: connection termination (SF)
    }
    return mapping.get(flag_str, None)

def process_packet(packet):
    global aggregator
    if IP in packet:
        aggregator["packets"] += 1

        # Process TCP packets
        if TCP in packet:
            aggregator["tcp_packets"] += 1
            dport = packet[TCP].dport
            service = SERVICE_MAPPING.get(dport, "unknown")
            if service in ["http", "https"]:
                aggregator["srv_http"] += 1
            elif service != "unknown":
                aggregator["srv_other"] += 1

            # Use payload length as src_bytes and dst_bytes
            payload_len = len(packet[TCP].payload)
            aggregator["src_bytes"] += payload_len
            aggregator["dst_bytes"] += payload_len

            flag = packet[TCP].flags
            mapped = map_tcp_flags(flag)
            if mapped in aggregator["flag_counts"]:
                aggregator["flag_counts"][mapped] += 1

            # Mark urgent if the urgent flag (0x20) is set
            if flag & 0x20:
                aggregator["urgent"] = 1

            # Increment error counts if SYN or reset is seen
            if flag & 0x02:  # SYN flag
                aggregator["serror_count"] += 1
            if flag & 0x14:  # RST-related (adjust if needed)
                aggregator["rerror_count"] += 1

            # Land attack check: same source and destination IP and port
            if packet[IP].src == packet[IP].dst and packet[TCP].sport == packet[TCP].dport:
                aggregator["land"] = 1

            if packet[IP].frag > 0:
                aggregator["wrong_fragment"] = 1

        # Process UDP packets
        elif UDP in packet:
            aggregator["udp_packets"] += 1
            payload_len = len(packet[UDP].payload)
            aggregator["src_bytes"] += payload_len
            aggregator["dst_bytes"] += payload_len
            dport = packet[UDP].dport
            service = SERVICE_MAPPING.get(dport, "unknown")
            if service in ["http", "https"]:
                aggregator["srv_http"] += 1
            elif service != "unknown":
                aggregator["srv_other"] += 1

        # Process ICMP packets
        elif ICMP in packet:
            aggregator["icmp_packets"] += 1

def compute_features():
    global aggregator, WINDOW_DURATION
    duration = WINDOW_DURATION

    # Decide protocol type based on observed packets (TCP > UDP > ICMP)
    if aggregator["tcp_packets"] > 0:
        protocol_type = 6
    elif aggregator["udp_packets"] > 0:
        protocol_type = 17
    elif aggregator["icmp_packets"] > 0:
        protocol_type = 1
    else:
        protocol_type = 0

    # Create binary indicators for service types
    service_http = 1 if aggregator["srv_http"] > 0 else 0
    service_other = 1 if aggregator["srv_other"] > 0 else 0

    # Determine the dominant TCP flag category (if any TCP packet was seen)
    flag_RSTR = flag_S0 = flag_S1 = flag_SF = 0
    if aggregator["tcp_packets"] > 0:
        counts = aggregator["flag_counts"]
        dominant = max(counts, key=counts.get)
        if dominant == "RSTR":
            flag_RSTR = 1
        elif dominant == "S0":
            flag_S0 = 1
        elif dominant == "S1":
            flag_S1 = 1
        elif dominant == "SF":
            flag_SF = 1

    src_bytes = aggregator["src_bytes"]
    dst_bytes = aggregator["dst_bytes"]
    land = aggregator["land"]
    wrong_fragment = aggregator["wrong_fragment"]
    urgent = aggregator["urgent"]
    count = aggregator["packets"]
    srv_count = aggregator["srv_http"] + aggregator["srv_other"]
    serror_rate = (aggregator["serror_count"] / count) if count > 0 else 0.0
    rerror_rate = (aggregator["rerror_count"] / count) if count > 0 else 0.0
    same_srv_rate = 0.0  # (placeholder)
    diff_srv_rate = 0.0  # (placeholder)

    # Build the feature vector in the expected order (19 features)
    feature_vector = [
        float(duration),         # duration
        float(protocol_type),    # protocol_type
        float(service_http),     # service_http
        float(service_other),    # service_other
        float(flag_RSTR),        # flag_RSTR
        float(flag_S0),          # flag_S0
        float(flag_S1),          # flag_S1
        float(flag_SF),          # flag_SF
        float(src_bytes),        # src_bytes
        float(dst_bytes),        # dst_bytes
        float(land),             # land
        float(wrong_fragment),   # wrong_fragment
        float(urgent),           # urgent
        float(count),            # count
        float(srv_count),        # srv_count
        float(serror_rate),      # serror_rate
        float(rerror_rate),      # rerror_rate
        float(same_srv_rate),    # same_srv_rate
        float(diff_srv_rate),    # diff_srv_rate
    ]
    return feature_vector

def window_worker():
    global aggregator, WINDOW_DURATION
    while True:
        time.sleep(WINDOW_DURATION)
        feat_vec = compute_features()
        # Convert the vector to a comma-separated string.
        feat_str = ",".join(str(f) for f in feat_vec) + "\n"
        print("Sending Feature Vector:")
        print(feat_str.strip())

        # Send the feature vector over serial to the NICLA device (if available)
        if ser is not None:
            ser.write(feat_str.encode())
        
        # Reset the aggregator for the next window.
        aggregator.clear()
        aggregator.update({
            "packets": 0,
            "src_bytes": 0,
            "dst_bytes": 0,
            "serror_count": 0,
            "rerror_count": 0,
            "srv_http": 0,
            "srv_other": 0,
            "flag_counts": {"RSTR": 0, "S0": 0, "S1": 0, "SF": 0},
            "wrong_fragment": 0,
            "urgent": 0,
            "land": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
        })

# --- Serial Reader Thread: Read Classification Results from NICLA ---
def serial_reader():
    global ser
    while True:
        if ser is not None:
            try:
                line = ser.readline().decode("utf-8", errors="replace").strip()
                if line:
                    print("From NICLA:", line)
            except Exception as e:
                print("Error reading serial:", e)

def main():
    # Start the serial reader thread.
    threading.Thread(target=serial_reader, daemon=True).start()
    # Start the window worker thread.
    threading.Thread(target=window_worker, daemon=True).start()
    # Begin packet capture. This will run in the main thread.
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    main()
