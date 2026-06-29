import time
from collections import deque
from datetime import datetime, timezone
from scapy.layers.inet import IP, UDP, TCP

class DetectionEngine:
    def __init__(self, logger_instance):
        """
        Initializes the analytical detection engine.
        """
        self.logger = logger_instance

        # 1. STATEFUL SYN FLOOD TRACKER
        # Structure: { source_ip: deque([timestamp1, timestamp2, ...]) }
        self.syn_tracker = {}

        # 2. STATEFUL PORT SCAN TRACKER
        # Structure: { source_ip: { target_port: first_seen_timestamp } }
        self.port_scan_tracker = {}

        # 3. STATEFUL UDP VOLUME TRACKER
        # Structure: { source_ip: deque([timestamp1, timestamp2, ...]) }
        self.udp_tracker = {}


    def _generate_alert(self, rule_name, source_ip, dest_port, severity):
        """
        Structures and flings an enterprise-ready alert into the async log queue.
        """
        utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        alert_payload = {
            "timestamp" : utc_now.isoformat() + "Z",
            "rule_name" : rule_name,
            "source_ip" : source_ip,
            "dest_port" : int(dest_port),
            "severity"  : severity,
        }

        self.logger.alert_queue.put(alert_payload)

    def evaluate(self, packet):
        """
        Public orchestrator entry point called directly by the Ingestion Sniffer plane.
        """
        # Guard rail: Instantly drop non-IP noise traffic to save user-space CPU cycles
        if not packet.haslayer(IP):
            return

        # Fire O(1) stateless validation checks
        self._evaluate_stateless(packet)
        self._evaluate_stateful(packet)

    def _evaluate_stateless(self, packet):
        """
        Perform O(1) linear signature checking on isolated packets.
        """
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        tcp_layer = packet.getlayer(TCP) if packet.haslayer(TCP) else None

        # 1. LAND ATTACK CHECK
        if src_ip == dst_ip:
            if tcp_layer and packet[TCP].sport == packet[TCP].dport:
                self._generate_alert("Land Attack Spoofing Loop", src_ip, packet[TCP].dport, "HIGH")
                return

            elif packet.haslayer(UDP) and packet[UDP].sport == packet[UDP].dport:
                self._generate_alert("Land Attack Spoofing Loop", src_ip, packet[UDP].dport, "HIGH")
                return

        # 2. TCP XMAS SCAN CHECK
        if tcp_layer:
            # Convert Scapy flags to integer representation safely
            flags_str = str(tcp_layer.flags)

            # Bitmask 0x29 checks for FIN (0x01) | PUSH (0x08) | URG (0x20)
            if 'F' in flags_str and 'P' in flags_str and 'U' in flags_str:
                self._generate_alert("TCP XMAS Tree Scan", src_ip, int(tcp_layer.dport), "HIGH")
                return

            # LIVE PRODUCTION ALERTS TRACE WIRE: Catch unencrypted Port 80 traffic
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                self._generate_alert(
                    rule_name="Insecure Cleartext HTTP Traffic",
                    source_ip=src_ip,
                    dest_port=80,
                    severity="LOW"
                )

    def _evaluate_stateful(self, packet):
        """
        Orchestrates behavioral analysis across rolling temporal windows.
        """
        src_ip = packet[IP].src
        current_time = time.time()

        # =====================================================================
        # TARGET VECTOR 1: UDP VOLUMETRIC FLOOD TRACKING
        # =====================================================================
        if packet.haslayer(UDP):
            # 1. Initialize the deque if this is the first time we see this source IP
            if src_ip not in self.udp_tracker:
                self.udp_tracker[src_ip] = deque()

            # 2. Append the current unix timestamp to this IP's tracking deque
            self.udp_tracker[src_ip].append(current_time)

            # 3. Slide the window: while the oldest timestamp in the deque
            # is older than 5.0 seconds ago, pop it from the left side!
            while self.udp_tracker[src_ip] and self.udp_tracker[src_ip][0] < current_time - 5.0:
                self.udp_tracker[src_ip].popleft()

            # 4. Check Threshold: If the total items left in the deque exceeds 50,
            # trigger our standard self._generate_alert() with "MEDIUM" severity!
            if len(self.udp_tracker[src_ip]) == 51:
                self._generate_alert("UDP Volumetric Flood", src_ip, int(packet[UDP].dport), "MEDIUM")

        tcp_layer = packet.getlayer(TCP) if packet.haslayer(TCP) else None
        # =====================================================================
        # TARGET VECTOR 2: TCP PORT SCANNING TRACKING
        # =====================================================================
        if tcp_layer:
            dst_port = int(packet[TCP].dport)

            # 1. Initialize the port tracking deque if this is a new IP address
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = deque()

            # 2. Append the current port and timestamp as a tuple to the deque
            self.port_scan_tracker[src_ip].append((dst_port, current_time))

            # 3. Slide the Window: Evict old tuple elements where time is > 5.0 seconds ago
            while self.port_scan_tracker[src_ip] and self.port_scan_tracker[src_ip][0][1] < current_time - 5.0:
                self.port_scan_tracker[src_ip].popleft()

            # 4. Check Uniqueness and Threshold: Extract unique ports using set()
            # If unique port count hits exactly 51, trigger a "TCP Port Scan" alert!
            unique_ports = set(port for port, _ in self.port_scan_tracker[src_ip])
            if len(unique_ports) > 50:
                if not getattr(self, f"alerted_ports_{src_ip}", False):
                    self._generate_alert("TCP Port Scan", src_ip, int(packet[TCP].dport), "MEDIUM")
                    setattr(self, f"alerted_ports_{src_ip}", True)
            else:
                setattr(self, f"alerted_ports_{src_ip}", False)

        # =====================================================================
        # TARGET VECTOR 3: TCP Backlog Exhaustion Vector
        # =====================================================================
        if tcp_layer:
            flags = str(tcp_layer.flags)

            # A. If it's a raw inbound initialization request (SYN only)
            if flags == "S":
                if src_ip not in self.syn_tracker:
                    self.syn_tracker[src_ip] = deque()

                self.syn_tracker[src_ip].append(current_time)

            # B. If it's a completing handshake acknowledgement packet (ACK)
            elif "A" in flags:
                if src_ip in self.syn_tracker and self.syn_tracker[src_ip]:
                    self.syn_tracker[src_ip].popleft()

            # C. Slide the temporal window for this specific host node
            if src_ip in self.syn_tracker:
                while self.syn_tracker[src_ip] and self.syn_tracker[src_ip][0] < current_time - 5.0:
                    self.syn_tracker[src_ip].popleft()

                if len(self.syn_tracker[src_ip]) == 51:
                    self._generate_alert("TCP SYN Flood DoS", src_ip, int(packet[TCP].dport), "HIGH")

