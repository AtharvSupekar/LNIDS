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
    ALERT = '\033[95m\033[1m'    # High-priority attack triggers / warnings
    SUCCESS = '\033[92m'          # Successful packet deliveries
    INFO = '\033[94m'            # Minor info/status shifts
    WARN = '\033[93m'            # Warning / validation configuration modifications
    FAIL = '\033[91m\033[1m'     # Core structural errors / runtime crashes
    ENDC = '\033[0m'             # Global style reset
    BOLD = '\033[1m'             # Generic emphasis


class LNIDSAttackSimulator:
    def __init__(self):
        self.target_ip = self.detect_local_ip()

    @staticmethod
    def detect_local_ip():
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
        except (OSError, socket.error):
            return "127.0.0.1"

    def run_menu_loop(self):
        """Orchestrates a comprehensive high-contrast interactive menu loop."""
        try:
            while True:
                print(f"\n{LogColor.HEADER}" + "=" * 60)
                print("         LNIDS OFFENSIVE ADVERSARY EMULATION SUITE      ")
                print("=" * 60 + f"{LogColor.ENDC}")
                print(f" {LogColor.INFO}[*]{LogColor.ENDC} Controlled Interface Target: {LogColor.BOLD}{self.target_ip}{LogColor.ENDC}")
                print(f" {LogColor.INFO}[-]{LogColor.ENDC} Status: Standing by for vector selection sequence...")
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
                    self.run_port_scan()
                elif choice == "5":
                    self.run_syn_flood()
                elif choice == "6":
                    self.run_comprehensive_suite(self)
                elif choice == "7":
                    self.reconfigure_target_ip()
                elif choice == "8":
                    print(f"\n{LogColor.ALERT}[!] Shutting down simulation architecture. System clean.{LogColor.ENDC}")
                    sys.exit(0)
                else:
                    print(f"\n{LogColor.FAIL}[-] Invalid input sequence configuration.{LogColor.ENDC}")

                input(f"\nPress {LogColor.BOLD}[Enter]{LogColor.ENDC} to return to options drawer...")

        except KeyboardInterrupt:
            print(f"\n{LogColor.ALERT}[!] Shutting down simulation architecture. System clean.{LogColor.ENDC}")
            sys.exit(0)

    def run_land_attack(self):
        """
        MODULE A: Stateless Land Attack Spoofing Loop Emulator.
        Formulates a packet where Source == Destination across Layer 3 & Layer 4.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateless Land Attack Injection Engine...{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Forging binary headers where src ({self.target_ip}) == dst ({self.target_ip}){LogColor.ENDC}")

        # 1. Build the anomalous packet stack
        spoof_packet = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=80, dport=80, flags="S")

        try:
            # 2. Fire the packet directly into the OS network driver layer
            # verbose=False keeps Scapy from spamming the terminal with raw internal printouts
            for _ in range(3):
                send(spoof_packet, verbose=False)
                print(f"{LogColor.SUCCESS}[+] Malformed spoofed frame successfully injected onto the live interface wires!{LogColor.ENDC}")

        except OSError as e:
            print(f"{LogColor.FAIL}[-] Transmission injection failed: {e}{LogColor.ENDC}")

    def run_xmas_scan(self):
        """
        MODULE B: Stateless TCP XMAS Tree Scan Emulator.
        Synthesizes an anomalous frame where FIN, PUSH, and URG bits are enabled.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Curated Flag Matrix Simulator...{LogColor.ENDC}")

        benign_flags = ["S", "A", "SA", "PA", "FA", "R", "RA", "F", "P", "SEC"]
        # noinspection SpellCheckingInspection
        malicious_flags = ["FPU", "FPUA", "FPUS", "FPUR", "FPUC", "FPUE", "PAFUR", "SFAUP", "CWFPU", "FSRPAUEC"]

        try:
            user_input = input("\nEnter the number of packets you want to simulate [1-99]: ").strip()
            no_of_packets = int(user_input)
        except ValueError:
            print(f"{LogColor.WARN}[!] Invalid entry. Defaulting to 10 packets.{LogColor.ENDC}")
            no_of_packets = 10

        try:
            user_pct = input("Enter target percentage for malicious packets [0-100]: ").strip()
            malicious_percent = float(user_pct)
        except ValueError:
            print(f"{LogColor.WARN}[!] Invalid entry. Defaulting to 30.0%.{LogColor.ENDC}")
            malicious_percent = 30.0

        malicious_count = 0
        benign_count = 0

        for i in range(no_of_packets):
            try:
                random_sport = random.randint(32000, 64000)
                roll = random.uniform(0.0, 100.0)

                if roll <= malicious_percent:
                    label = "MALICIOUS"
                    color_start = LogColor.ALERT
                    chosen_flags = random.choice(malicious_flags)
                    malicious_count += 1
                else:
                    label = "BENIGN"
                    color_start = LogColor.SUCCESS
                    chosen_flags = random.choice(benign_flags)
                    benign_count += 1

                pkt = IP(dst=self.target_ip) / TCP(sport=random_sport, dport=80, flags=chosen_flags)
                send(pkt, verbose=False)

                status_box = f"[{color_start}{label:<9}{LogColor.ENDC}]"
                print(f" -> Packet [{i + 1:>2}/{no_of_packets:>2}] {status_box} Flags: {chosen_flags:<8} | Port: {random_sport}")
                time.sleep(0.02)
            except OSError as e:
                print(f"{LogColor.FAIL}[-] Matrix runtime failure: {e}{LogColor.ENDC}")

        print(f"\n{LogColor.SUCCESS}[+] Curated flag sequence execution complete.{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Results: Sent {malicious_count} Malicious patterns and {benign_count} Benign patterns.{LogColor.ENDC}")


    def run_udp_flood(self):
        """
        MODULE C: Stateful UDP Volumetric Flood Simulator.
        Transmits a high-speed sequence of standard UDP datagrams over the interface
        to validate sliding time window thresholds inside the brain plane.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateful UDP Volumetric Flood Simulator...{LogColor.ENDC}")

        try:
            user_packets = input("\nEnter total UDP frames to inject (Recommend 60) [1-200]: ").strip()
            no_of_packets = int(user_packets)
            if not 1 <= no_of_packets <= 200:
                raise ValueError
        except ValueError:
            print(f"{LogColor.WARN}[!] Invalid entry. Defaulting to 60 packets.{LogColor.ENDC}")
            no_of_packets = 60

        target_port = 9999
        print(f"\n{LogColor.INFO}[*] Target Host Destination Port: {target_port}{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Injecting {no_of_packets} baseline datagram streams...{LogColor.ENDC}\n")

        sent_count = 0
        start_time = time.time()

        for i in range(no_of_packets):
            try:
                pkt = IP(dst=self.target_ip) / UDP(sport=54321, dport=target_port) / "LNIDS_VOLUMETRIC_FLOOD_TEST_STRING"
                send(pkt, verbose=False)
                sent_count += 1

                print(f" {LogColor.SUCCESS}[+]{LogColor.ENDC} Datagram Injected [{i + 1:>3}/{no_of_packets:>3}] Port: {target_port}")
                time.sleep(0.02)

            except OSError as e:
                print(f"{LogColor.FAIL}[-] UDP Flood simulation failure: {e}{LogColor.ENDC}")

        duration = time.time() - start_time
        print(f"\n{LogColor.SUCCESS}[+] UDP Volumetric sequence execution complete.{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Results: Successfully delivered {sent_count}/{no_of_packets} packets in {duration:.3f} seconds.{LogColor.ENDC}")


    def run_port_scan(self):
        """
        MODULE D: Stateful TCP Port Scan Sweep Emulator.
        Sweeps target ports across a sequential spectrum to validate
        the behavioral set threshold and testing the alert suppression gates.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateful TCP Port Scan Sweep...{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Target Destination: {self.target_ip}{LogColor.ENDC}")

        try:
            # 1. Gather configuration parameters dynamically
            port_count_in = input("Enter number of ports to sweep (Recommend > 50 to test trigger) [1-500]: ").strip()
            total_ports = int(port_count_in) if port_count_in.isdigit() else 60

            start_port_in = input("Enter starting destination port [1-65535, default 1000]: ").strip()
            start_port = int(start_port_in) if start_port_in.isdigit() else 1000

            # Determine scanning sequence mode
            print(f"\nScan Modes:\n {LogColor.INFO}[1]{LogColor.ENDC} Linear Sweep (Sequential)\n {LogColor.INFO}[2]{LogColor.ENDC} Stealth Shuffle (Randomized)")
            mode_choice = input("Select Scan Mode [1-2, default 1]: ").strip()

            # 2. Build the port array based on selection
            port_sequence = list(range(start_port, start_port + total_ports))
            if mode_choice == "2":
                random.shuffle(port_sequence)
                print(f"{LogColor.INFO}[*] Stealth Shuffle active. Scrambling port array vectors...{LogColor.ENDC}")
            else:
                print(f"{LogColor.INFO}[*] Linear Sweep active. Processing sequential ports...{LogColor.ENDC}")

            start_time = time.time()

            # 3. Transmission loop
            for idx, port in enumerate(port_sequence, 1):
                if port > 65535 or port < 1:
                    continue

                scan_packet = IP(dst=self.target_ip) / TCP(sport=12435, dport=port, flags="S")
                send(scan_packet, verbose=False)
                time.sleep(0.01)  # Micro-pacing delay to prevent kernel drop limits

                print(f"  {LogColor.SUCCESS}[+]{LogColor.ENDC} Scan Packet [{idx:>3}/{total_ports:>3}] | Target Port: {port:<5}")

            duration = time.time() - start_time
            print(f"\n{LogColor.SUCCESS}[+] TCP Port Scan Sweep completed!{LogColor.ENDC}")
            print(f"    {LogColor.INFO}[*]{LogColor.ENDC} Metrics: Successfully struck {total_ports} ports in {duration:.3f} seconds.")

        except OSError as e:
            print(f"\n{LogColor.FAIL}[-] Scan runtime failure: {e}{LogColor.ENDC}")


    def run_syn_flood(self):
        """
        MODULE E: Stateful TCP SYN Flood DoS Emulator.
        Injects a rapid burst of half-open SYN connection frames to
        validate host system backlog tracker limits.
        """
        print(f"\n{LogColor.ALERT}[!] Initializing Stateful TCP SYN Flood DoS Engine...{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Target Destination Host: {self.target_ip}{LogColor.ENDC}")

        try:
            packet_in = input("Enter total number of SYN frames to flood (Recommend 65) [1-200]: ").strip()
            total_packets = int(packet_in) if packet_in.isdigit() else 65
            if not (1 <= total_packets <= 200):
                total_packets = 65

            target_port_in = input("Enter open service port to target [default: 135]: ").strip()
            target_port = int(target_port_in) if target_port_in.isdigit() else 135
            if not (1 <= target_port <= 65535):
                target_port = 135
                print(f"{LogColor.WARN}[!] Port number is out of range. Defaulting to Port 135...{LogColor.ENDC}")

            print(f"{LogColor.INFO}[*] Flooding {total_packets} pure SYN frames to port {target_port}...{LogColor.ENDC}")
            start_time = time.time()

            for i in range(total_packets):
                syn_packet = IP(dst=self.target_ip) / TCP(sport=44533, dport=target_port, flags="S")

                send(syn_packet, verbose=False)
                time.sleep(0.01)

                print(f"  {LogColor.SUCCESS}[+]{LogColor.ENDC} SYN Frame Delivered [{i + 1:>3}/{total_packets:>3}] | Target Port: {target_port}")

            duration = time.time() - start_time
            print(f"\n{LogColor.SUCCESS}[+] SYN Flood simulation loop complete!{LogColor.ENDC}")
            print(f"    {LogColor.INFO}[*]{LogColor.ENDC} Metrics: Dispatched {total_packets} half-open vectors in {duration:.3f} seconds.")

        except OSError as e:
            print(f"\n{LogColor.FAIL}[-] DoS engine crash: {e}{LogColor.ENDC}")

    @staticmethod
    def run_comprehensive_suite(self):
        """
        MODULE F: Full Automated Attack Vector Campaign.
        Fires all implemented attack signatures and behavioral patterns sequentially
        to stress-test multi-threaded ingestion and alert pipeline endurance.
        """
        print(f"\n{LogColor.ALERT}============================================================")
        print(f"       LAUNCHING FULL COMPREHENSIVE ATTACK SUITE CAMPAIGN     ")
        print(f"============================================================{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Target Destination: {self.target_ip}{LogColor.ENDC}")
        print("[*] Commencing automated execution sequence...")

        # Phase 1: Stateless Anomalies
        print(f"\n{LogColor.BOLD}[Phase 1/5] Triggering Stateless Land Attack...{LogColor.ENDC}")
        # Locally simulating land attack parameters by altering the packet delivery loop
        try:
            land_pkt = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=12435, dport=12435, flags="S")
            send(land_pkt, verbose=False)
            print("  -> Land Attack footprint sent.")
        except Exception as e:
            print(f"  [-] Failed: {e}")

        time.sleep(1.0)

        print(f"\n{LogColor.BOLD}[Phase 2/5] Triggering Stateless TCP XMAS Scan...{LogColor.ENDC}")
        try:
            xmas_pkt = IP(dst=self.target_ip) / TCP(sport=12435, dport=80, flags="FPU")
            send(xmas_pkt, verbose=False)
            print("  -> XMAS Scan footprint sent.")
        except Exception as e:
            print(f"  [-] Failed: {e}")

        time.sleep(1.0)

        # Phase 2: Stateful Behavioral Sweeps and Floods
        print(f"\n{LogColor.BOLD}[Phase 3/5] Launching High-Velocity UDP Volumetric Flood...{LogColor.ENDC}")
        # Automatically injects 70 packets to cross the >50 threshold cleanly
        for i in range(70):
            send(IP(dst=self.target_ip) / UDP(sport=12435, dport=9999), verbose=False)
        print("  -> 70 UDP packets dispatched.")

        time.sleep(1.0)

        print(f"\n{LogColor.BOLD}[Phase 4/5] Launching Randomized TCP Port Scan Sweep...{LogColor.ENDC}")
        # Sweep 60 unique ports randomly to cross the unique port threshold
        ports = list(range(2000, 2060))
        random.shuffle(ports)
        for p in ports:
            send(IP(dst=self.target_ip) / TCP(sport=12435, dport=p, flags="S"), verbose=False)
            time.sleep(0.005)
        print("  -> 60 unique port probes delivered.")

        time.sleep(1.0)

        print(f"\n{LogColor.BOLD}[Phase 5/5] Launching High-Velocity TCP SYN Flood DoS...{LogColor.ENDC}")
        # Flood 70 packets to a single port to validate the updated velocity engine
        for _ in range(70):
            send(IP(dst=self.target_ip) / TCP(sport=12435, dport=8888, flags="S"), verbose=False)
            time.sleep(0.005)
        print("  -> 70 single-port SYN connection requests delivered.")

        print(f"\n{LogColor.SUCCESS}[✓] All automated attack vector campaigns executed successfully!{LogColor.ENDC}")
        print(f"{LogColor.INFO}[*] Inspect your alerts.json log to verify the alert metrics.{LogColor.ENDC}")

        input(f"\nPress {LogColor.BOLD}[Enter]{LogColor.ENDC} to return to options drawer...")

    @staticmethod
    def is_valid_ipv4(ip_str):
        """
        Internal validation helper. Uses OS socket primitives
        to verify a string conforms strictly to IPv4 decimal notation.
        """
        try:
            # socket.inet_aton throws an OSError if the string isn't a valid IP
            socket.inet_aton(ip_str)
            return True
        except OSError:
            return False

    def reconfigure_target_ip(self):
        """
        MODULE G: Secure Target IP Reconfiguration.
        Gathers manual user input and routes it through socket validation bounds.
        """
        print(f"\n{LogColor.INFO}[*] Current Destination IP: {self.target_ip}{LogColor.ENDC}")
        new_ip = input("Enter new Destination IP: ").strip()

        if not new_ip:
            print(f"{LogColor.WARN}[!] Input empty. Keeping current target.{LogColor.ENDC}")
            return

        if self.is_valid_ipv4(new_ip):
            self.target_ip = new_ip
            print(f"{LogColor.SUCCESS}[+] Target Successfully locked to: {self.target_ip}{LogColor.ENDC}")
        else:
            print(f"{LogColor.FAIL}[-]{LogColor.BOLD} Critical Validation Error: '{new_ip}' is not a valid IPv4 address!{LogColor.ENDC}")


if __name__ == "__main__":
    simulator = LNIDSAttackSimulator()
    simulator.run_menu_loop()


# flag_matrix = [
#             # --- LEGITIMATE / BENIGN SAMPLES ---
#             "S",  # Pure SYN (Connection Init)
#             "A",  # Pure ACK (Handshake Ack / Keepalive)
#             "SA",  # SYN-ACK (Server Response)
#             "PA",  # PUSH-ACK (Active Data Streaming)
#             "FA",  # FIN-ACK (Graceful Close)
#             "R",  # Pure RST (Port Closed Reset)
#             "RA",  # RST-ACK (Connection Rejection)
#             "F",  # Pure FIN
#             "P",  # Pure PSH
#             "SEC",  # SYN-ECE-CWR (Congestion Handshake Negotiation)
#
#             # --- MALICIOUS / XMAS DISRUPTIVE SAMPLES (Contains F, P, and U) ---
#             "FPU",  # The Classic Core XMAS Flag Signature
#             "FPUA",  # XMAS hidden inside a standard ACK packet
#             "FPUS",  # XMAS trying to trigger a session initialization
#             "FPUR",  # XMAS mixed with a Connection Reset
#             "FPUC",  # XMAS combined with Congestion Window Controls
#             "FPUE",  # XMAS combined with ECN-Echo flags
#             "PAFUR",  # Shuffled order version 1
#             "SFAUP",  # Shuffled order version 2
#             "CWFPU",  # Advanced flag stacking anomaly
#             "FSRPAUEC"  # Maximum Chaos: All 8 control switches turned on at once!
#         ]