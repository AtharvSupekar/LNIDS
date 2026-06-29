"""
LNIDS - Local Network Intrusion Detection System
Module: tests/attack_simulator.py
Description: Automated Adversary Emulation Testing Utility.
"""
import random
import sys
import time
import socket
from scapy.all import send
from scapy.layers.inet import IP, TCP, UDP

class LogColor:
    HEADER = '\033[96m\033[1m'   # Main headers and structural menus
    ALERT = '\033[95m\033[1m'# High-priority attack triggers / warnings
    SUCCESS = '\033[92m'             # Successful packet deliveries
    INFO = '\033[94m'              # Minor info/status shifts
    ENDC = '\033[0m'               # Global style reset
    BOLD = '\033[1m'               # Generic emphasis


class LNIDSAttackSimulator:
    def __init__(self):
        self.target_ip = self.detect_local_ip()

    def detect_local_ip(self):
        """
        Dynamically capture the system's local physical interface IP route.
        Fallback safely to loopback if network sockets are unreachable.
        """
        try:
            # 1. Create a raw internet socket (AF_INET = IPv4, SOCK_DGRAM = UDP)
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # 2. Pretend to connect to Google. This forces the OS to pick an active network path
            temp_socket.connect(("8.8.8.8", 80))

            # 3. Ask the socket for its own configuration info. index [0] is the IP address
            resolved_ip = temp_socket.getsockname()[0]

            # 4. Clean up and close the socket
            temp_socket.close()

            return resolved_ip
        except Exception:
            return "127.0.0.1"

    def run_menu_loop(self):
        """Orchestrates a comprehensive high-contrast interactive menu loop."""
        try:
            while True:
                print(f"\n{LogColor.HEADER}" + "=" * 60)
                print("         LNIDS OFFENSIVE ADVERSARY EMULATION SUITE      ")
                print("=" * 60 + f"{LogColor.ENDC}")
                print(f" [*] Controlled Interface Target: {LogColor.BOLD}{self.target_ip}{LogColor.ENDC}")
                print(" [-] Status: Standing by for vector selection sequence...")
                print("-" * 60)
                print(f" {LogColor.HEADER}1.{LogColor.ENDC} Execute Land Attack               [Stateless]")
                print(f" {LogColor.HEADER}2.{LogColor.ENDC} Execute TCP XMAS Tree Scan        [Stateless]")
                print(f" {LogColor.HEADER}3.{LogColor.ENDC} Execute UDP Volumetric Flood      [Stateful Window]")
                print(f" {LogColor.HEADER}4.{LogColor.ENDC} Execute TCP Port Scan Sweep       [Stateful Window]")
                print(f" {LogColor.HEADER}5.{LogColor.ENDC} Execute TCP SYN Flood DoS         [Stateful Tracker]")
                print(f" {LogColor.HEADER}6.{LogColor.ENDC} Run Full Comprehensive Suite      [All Rules]")
                print(f" {LogColor.HEADER}7.{LogColor.ENDC} Reconfigure Interface Target IP")
                print(f" {LogColor.HEADER}8.{LogColor.ENDC} Terminate Emulator Safely")
                print("-" * 60)

                choice = input(f"{LogColor.HEADER}Select Operation [1-8]: {LogColor.ENDC}").strip()

                if choice == "1":
                    self.run_land_attack()
                elif choice == "2":
                    self.run_xmas_scan()
                elif choice == "3":
                    self.run_udp_flood()
                elif choice == "4":
                    print(f"\n{LogColor.INFO}[*] Port Sweep logic coming soon...{LogColor.ENDC}")
                elif choice == "5":
                    print(f"\n{LogColor.INFO}[*] SYN Flood DoS logic coming soon...{LogColor.ENDC}")
                elif choice == "6":
                    print(f"\n{LogColor.INFO}[*] Comprehensive suite loop coming soon...{LogColor.ENDC}")
                elif choice == "7":
                    print(f"Current Destination IP: {self.target_ip}")
                    new_ip = input("\nEnter manual Destination IP Target: ").strip()
                    if new_ip:
                        self.target_ip = new_ip
                        print(f"{LogColor.SUCCESS}[+] Target successfully locked to: {self.target_ip}{LogColor.ENDC}")
                elif choice == "8":
                    print(
                        f"\n{LogColor.ALERT}[!] Shutting down simulation architecture. System clean.{LogColor.ENDC}")
                    sys.exit(0)
                else:
                    print(f"\n{LogColor.ALERT}[-] Invalid input sequence configuration.{LogColor.ENDC}")

                input(f"\nPress {LogColor.BOLD}[Enter]{LogColor.ENDC} to return to options drawer...")

        except KeyboardInterrupt:
            print(
                f"\n{LogColor.ALERT}[!] Shutting down simulation architecture. System clean.{LogColor.ENDC}")
            sys.exit(0)

    def run_land_attack(self):
        """
        MODULE A: Stateless Land Attack Spoofing Loop Emulator.
        Formulates a packet where Source == Destination across Layer 3 & Layer 4.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateless Land Attack Injection Engine...{LogColor.ENDC}")
        print(f"[*] Forging binary headers where src ({self.target_ip}) == dst ({self.target_ip})")

        # 1. Build the anomalous packet stack
        spoof_packet = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=80, dport=80, flags="S")

        try:
            # 2. Fire the packet directly into the OS network driver layer
            # verbose=False keeps Scapy from spamming the terminal with raw internal printouts
            for _ in range(3):
                send(spoof_packet, verbose=False)
                print(f"{LogColor.SUCCESS}[✓] Malformed spoofed frame successfully injected onto the live interface wires!{LogColor.ENDC}")

        except Exception as e:
            print(f"{LogColor.ALERT}[-] Transmission injection failed. {e}{LogColor.ENDC}")

    def run_xmas_scan(self):
        """
        MODULE B: Stateless TCP XMAS Tree Scan Emulator.
        Synthesizes an anomalous frame where FIN, PUSH, and URG bits are enabled.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Curated Flag Matrix Simulator...")

        # Explicitly map real-world TCP communication states
        flag_matrix = [
            # --- LEGITIMATE / BENIGN SAMPLES ---
            "S",  # Pure SYN (Connection Init)
            "A",  # Pure ACK (Handshake Ack / Keepalive)
            "SA",  # SYN-ACK (Server Response)
            "PA",  # PUSH-ACK (Active Data Streaming)
            "FA",  # FIN-ACK (Graceful Close)
            "R",  # Pure RST (Port Closed Reset)
            "RA",  # RST-ACK (Connection Rejection)
            "F",  # Pure FIN
            "P",  # Pure PSH
            "SEC",  # SYN-ECE-CWR (Congestion Handshake Negotiation)

            # --- MALICIOUS / XMAS DISRUPTIVE SAMPLES (Contains F, P, and U) ---
            "FPU",  # The Classic Core XMAS Flag Signature
            "FPUA",  # XMAS hidden inside a standard ACK packet
            "FPUS",  # XMAS trying to trigger a session initialization
            "FPUR",  # XMAS mixed with a Connection Reset
            "FPUC",  # XMAS combined with Congestion Window Controls
            "FPUE",  # XMAS combined with ECN-Echo flags
            "PAFUR",  # Shuffled order version 1
            "SFAUP",  # Shuffled order version 2
            "CWFPU",  # Advanced flag stacking anomaly
            "FSRPAUEC"  # Maximum Chaos: All 8 control switches turned on at once!
        ]

        total_variants = len(flag_matrix)
        print(f"{LogColor.INFO}[*] Loaded {total_variants} explicit flag profiles from matrix cache...")

        # User input handling block
        try:
            user_input = input("\nEnter the number of packets you want to simulate [1-99]: ").strip()
            no_of_packets = int(user_input)
            if not 1 <= no_of_packets <= 99:
                raise ValueError
        except ValueError:
            print(f"{LogColor.ALERT}[-] Invalid entry. Defaulting simulation run loop to 5 packets.{LogColor.ENDC}")
            no_of_packets = 5

        malicious_count = 0
        benign_count = 0

        for i in range(no_of_packets):
            try:
                random_sport = random.randint(32000, 64000)
                chosen_flags = random.choice(flag_matrix)

                # Step 1: Compute true boolean threat state
                is_malicious = 'F' in chosen_flags and 'P' in chosen_flags and 'U' in chosen_flags

                # Step 2: Extract plain indicators and target styles cleanly
                if is_malicious:
                    label = "MALICIOUS"
                    malicious_count += 1
                else:
                    label = "BENIGN"
                    benign_count += 1

                pkt = IP(dst = self.target_ip) / TCP(sport=random_sport, dport=80, flags=chosen_flags)
                send(pkt, verbose=False)

                status_box = f"[{LogColor.ALERT}{label:<9}{LogColor.ENDC}]"
                print(f" -> Packet [{i + 1:>2}/{no_of_packets}] {status_box} Flags: {chosen_flags:<8} | Port: {random_sport}")
                time.sleep(0.02)

            except Exception as e:
                print(f"{LogColor.ALERT}[-] Matrix runtime failure: {e}")

        print(f"\n{LogColor.SUCCESS}[✓] Curated flag sequence execution complete.")
        print(f"{LogColor.INFO} Results: Sent {malicious_count} Malicious patterns and {benign_count} Benign patterns.{LogColor.ENDC}")

    def run_udp_flood(self):
        """
        MODULE C: Stateful UDP Volumetric Flood Simulator.
        Transmits a high-speed sequence of standard UDP datagrams over the interface
        to validate sliding time window thresholds inside the brain plane.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateful UDP Volumetric Flood Simulator...")

        try:
            user_packets = input("\nEnter total UDP frames to inject (Recommend 60) [1-200]:").strip()
            no_of_packets = int(user_packets)
            if not 1 <= no_of_packets <= 200:
                raise ValueError
        except ValueError:
            print(f"{LogColor.ALERT}[-] Invalid entry. Defaulting to 60 packets.{LogColor.ENDC}")
            no_of_packets = 60

        target_port = 9999
        print(f"\n{LogColor.INFO}[*] Target Host Destination Port: {target_port}")
        print(f"{LogColor.INFO}[*] Injecting {no_of_packets} baseline datagram streams...{LogColor.ENDC}\n")

        sent_count = 0
        start_time = time.time()

        for i in range(no_of_packets):
            try:
                pkt = IP(dst=self.target_ip) / UDP(sport=54321, dport=target_port) / "LNIDS_VOLUMETRIC_FLOOD_TEST_STRING"
                send(pkt, verbose=False)
                sent_count += 1

                print(f" -> Datagram Injected [{i + 1:>3}/{no_of_packets:>3}] Port: {target_port}")
                time.sleep(0.02)

            except Exception as e:
                print(f"{LogColor.ALERT}[-] UDP Flood simulation failure: {e}")

        duration = time.time() - start_time
        print(f"\n{LogColor.SUCCESS}[✓] UDP Volumetric sequence execution complete.{LogColor.ENDC}")
        print(f"{LogColor.INFO} Results: Successfully delivered {sent_count}/{no_of_packets} packets in {duration:.3f} seconds.{LogColor.ENDC}")


if __name__ == "__main__":
    simulator = LNIDSAttackSimulator()
    simulator.run_menu_loop()