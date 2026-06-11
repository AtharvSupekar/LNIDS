"""
LNIDS - Local Network Intrusion Detection System
Module: tests/attack_simulator.py
Description: Automated Adversary Emulation Testing Utility.
"""
import sys
import time
import socket
from scapy.all import send
from scapy.layers.inet import IP, TCP, UDP

class LogColor:
    CYAN_BOLD = '\033[96m\033[1m'   # Main headers and structural menus
    MAGENTA_BOLD = '\033[95m\033[1m'# High-priority attack triggers / warnings
    GREEN = '\033[92m'             # Successful packet deliveries
    BLUE = '\033[94m'              # Minor info/status shifts
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
        while True:
            print(f"\n{LogColor.CYAN_BOLD}" + "=" * 60)
            print("         LNIDS OFFENSIVE ADVERSARY EMULATION SUITE      ")
            print("=" * 60 + f"{LogColor.ENDC}")
            print(f" [*] Controlled Interface Target: {LogColor.BOLD}{self.target_ip}{LogColor.ENDC}")
            print(" [-] Status: Standing by for vector selection sequence...")
            print("-" * 60)
            print(f" {LogColor.CYAN_BOLD}1.{LogColor.ENDC} Execute Land Attack               [Stateless]")
            print(f" {LogColor.CYAN_BOLD}2.{LogColor.ENDC} Execute TCP XMAS Tree Scan        [Stateless]")
            print(f" {LogColor.CYAN_BOLD}3.{LogColor.ENDC} Execute UDP Volumetric Flood      [Stateful Window]")
            print(f" {LogColor.CYAN_BOLD}4.{LogColor.ENDC} Execute TCP Port Scan Sweep       [Stateful Window]")
            print(f" {LogColor.CYAN_BOLD}5.{LogColor.ENDC} Execute TCP SYN Flood DoS         [Stateful Tracker]")
            print(f" {LogColor.CYAN_BOLD}6.{LogColor.ENDC} Run Full Comprehensive Suite      [All Rules]")
            print(f" {LogColor.CYAN_BOLD}7.{LogColor.ENDC} Reconfigure Interface Target IP")
            print(f" {LogColor.CYAN_BOLD}8.{LogColor.ENDC} Terminate Emulator Safely")
            print("-" * 60)

            choice = input(f"{LogColor.CYAN_BOLD}Select Operation [1-8]: {LogColor.ENDC}").strip()

            if choice == "1":
                self.run_land_attack()
            elif choice == "2":
                print(f"\n{LogColor.BLUE}[*] XMAS Tree logic coming soon...{LogColor.ENDC}")
            elif choice == "3":
                print(f"\n{LogColor.BLUE}[*] UDP Volumetric logic coming soon...{LogColor.ENDC}")
            elif choice == "4":
                print(f"\n{LogColor.BLUE}[*] Port Sweep logic coming soon...{LogColor.ENDC}")
            elif choice == "5":
                print(f"\n{LogColor.BLUE}[*] SYN Flood DoS logic coming soon...{LogColor.ENDC}")
            elif choice == "6":
                print(f"\n{LogColor.BLUE}[*] Comprehensive suite loop coming soon...{LogColor.ENDC}")
            elif choice == "7":
                new_ip = input("\nEnter manual Destination IP Target: ").strip()
                if new_ip:
                    self.target_ip = new_ip
                    print(f"{LogColor.GREEN}[+] Target successfully locked to: {self.target_ip}{LogColor.ENDC}")
            elif choice == "8":
                print(
                    f"\n{LogColor.MAGENTA_BOLD}[!] Shutting down simulation architecture. System clean.{LogColor.ENDC}")
                sys.exit(0)
            else:
                print(f"\n{LogColor.MAGENTA_BOLD}[-] Invalid input sequence configuration.{LogColor.ENDC}")

            input(f"\nPress {LogColor.BOLD}[Enter]{LogColor.ENDC} to return to options drawer...")


    def run_land_attack(self):
        """
        MODULE A: Stateless Land Attack Spoofing Loop Emulator.
        Formulates a packet where Source == Destination across Layer 3 & Layer 4.
        """
        print(f"\n{LogColor.MAGENTA_BOLD}[!] Initializing Stateless Land Attack Injection Engine...{LogColor.ENDC}")
        print(f" [*] Forging binary headers where src ({self.target_ip}) == dst ({self.target_ip})")

        # 1. Build the anomalous packet stack
        spoof_packet = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=80, dport=80, flags="S")

        try:
            # 2. Fire the packet directly into the OS network driver layer
            # verbose=False keeps Scapy from spamming the terminal with raw internal printouts
            send(spoof_packet, verbose=False)
            print(f"{LogColor.GREEN}[✓] Malformed spoofed frame successfully injected onto the live interface wires!{LogColor.ENDC}")

        except Exception as e:
            print(f"{LogColor.MAGENTA_BOLD}[-] Transmission injection failed. {e}{LogColor.ENDC}")




if __name__ == "__main__":
    simulator = LNIDSAttackSimulator()
    simulator.run_menu_loop()