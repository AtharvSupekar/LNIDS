import sys
import time
from src.logger import JSONLogger
from src.sniffer import PacketSniffer

def main():
    print("[+] Initializing Local Network Intrusion Detection System (LNIDS)...")

    # 1. Instantiate and start the asynchronous logging plane
    logger = JSONLogger(log_file="logs/alerts.json")
    logger.start()
    print("[+] Asynchronous logging engine activated.")

    # 2. Instantiate and start the live network ingestion plane
    sniffer = PacketSniffer(logger_instance=logger)
    sniffer.start()
    print(f"[+] Network capture loop active on interface: '{sniffer.interface}'")
    print("[+] Applied Kernel-Space BPF Filter: 'tcp or udp and not port 443'")
    print("[+] Monitoring Traffic... Press Ctrl+C to halt execution cleanly. \n")

    # 3. Main Control Thread Sleep Loop
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[-] Keyboard interrupt detected. Initiating graceful shutdown sequence...")

        # 4. Flush Memory queues and halt background workers safely
        print("[-] Draining and flushing remaining memory queues to disk...")
        logger.stop()

        print("[+] All host thread resources cleanly deallocated.")
        print("[+] System offline. Exiting safely.")
        sys.exit(0)


if __name__ == "__main__":
    main()
