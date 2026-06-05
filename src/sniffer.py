import sys
import threading
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

class PacketSniffer:
    def __init__(self, engine_instance, interface = "Loopback Pseudo-Interface 1", bpf_filter = "tcp or udp and not port 443"):
        """
        Initializes the live network ingestion plane.
        """
        self.engine = engine_instance
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.sniffer_thread = None
        self.stop_event = threading.Event()

    def start(self):
        """
        Spins up a dedicated thread to execute packet capture without blocking the main program.
        """
        # Guard rail: If the threa  d is already active, return immediately to prevent duplicates
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return

        self.stop_event.clear()
        self.sniffer_thread = threading.Thread(target = self._run_sniff, daemon = True)
        self.sniffer_thread.start()

    def stop(self):
        """
        Signals the low-level capture loop to break execution parameters immediately.
        """
        self.stop_event.set()
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout = 1)

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
                prn=self._packet_callback,
                stop_filter = lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            print(f"CRITICAL: Sniffer driver loop encountered an error: {e}", file=sys.stderr)

    def _packet_callback(self, packet):
        """
        The user-space frame interceptor. Forwards live packet streams straight
        into the analytical engine routing architecture.
        """
        # 1. High-speed pass-through to our stateful/stateless engines
        try:
            self.engine.evaluate(packet)
        except Exception as e:
            print(f"[-] Engine parsing anomaly encountered: {e}", file=sys.stderr)

        # 2. Preserving your pristine Diagnostic Print to verify it's hunting live!
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            try:
                if packet.haslayer(TCP):
                    tcp_layer = packet.getlayer(TCP)
                    if tcp_layer:
                        flags_str = str(packet[TCP].flags) if packet[TCP].flags else "N/A"
                        print(f"[*] Ingested: TCP | Source: {src_ip} | Target Port: {packet[TCP].dport} | Flags: {flags_str}")
                elif packet.haslayer(UDP):
                    udp_layer = packet.getlayer(UDP)
                    if udp_layer:
                        print(f"[*] Ingested: UDP | Source: {src_ip} | Target Port: {packet[TCP].dport} | Flags: N/A")

            except Exception as e:
                pass

