import sys
import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

class PacketSniffer:
    def __init__(self, logger_instance, interface = "Loopback Pseudo-Interface 1", bpf_filter = "tcp or udp and not port 443"):
        """
        Initializes the live network ingestion plane.
        """
        self.logger = logger_instance
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.sniffer_thread = None

    def start(self):
        """
        Spins up a dedicated thread to execute packet capture without blocking the main program.
        """
        # Guard rail: If the thread is already active, return immediately to prevent duplicates
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return

        self.sniffer_thread = threading.Thread(target = self._run_sniff, daemon = True)
        self.sniffer_thread.start()

    def _run_sniff(self):
        """
        The continuous execution loop that commands the driver to stream
        pre-filtered packets directly into our user-space memory plane.
        """
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                store=False,
                prn=self._packet_callback
            )
        except Exception as e:
            print(f"CRITICAL: Sniffer driver loop encountered an error: {e}", file=sys.stderr)

    def _packet_callback(self, packet):
        """
        The user-space frame interceptor. Dissects protocol metadata on the fly
        and prepares data structures for downstream detection evaluation.
        """
        # 1. Check if the packet has an IP layer
        if packet.haslayer(IP):
            # Extract standard network coordinates
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # 2. Handle TCP specific layer extraction
            if packet.haslayer(TCP):
                proto = "TCP"
                # Extract destination port
                dst_port = packet[TCP].dport
                # Get the string representation of flags (e.g., "S", "SA", "RA")
                flags = packet[TCP].sprintf("%TCP.flags%")

            # 3. Handle UDP specific layer extraction
            elif packet.haslayer(UDP):
                proto = "UDP"
                dst_port = packet[UDP].dport
                flags = "N/A"   # UDP has no connection state flags
            else:
                return  # Ignore all other background IP protocols for now

            # 4. Temporary Diagnostic Print to test if it's capturing!
            print(f"[*] Ingested: {proto} | Source: {src_ip} | Target Port: {dst_port} | Flags: {flags}")