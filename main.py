import sys
import time
from src.logger import JSONLogger
from src.engine import DetectionEngine
from src.sniffer import PacketSniffer

def main():
    print("================================================================================")
    print("                     LNIDS: LOCAL NETWORK INTRUSION DETECTION SYSTEM            ")
    print("================================================================================")
    print("[*] Launching system components...")

    # 1. Instantiate and start the asynchronous logging plane
    logger = JSONLogger()
    logger.start()
    print("[+] Asynchronous logging engine active (Output target: logs/alerts.json)")

    # 2. Instantiate the Analytical Engine, passing it the logger reference
    engine = DetectionEngine(logger_instance=logger)
    print("[+] Analytical Engine Brain Plane mapped successfully.")

    # 3. Instantiate and start the live network ingestion plane
    sniffer = PacketSniffer(engine_instance=engine)
    sniffer.start()
    print("[+] Ingestion Sniffer active. Kernel BPF Filter compiled.")
    print("[*] LNIDS fully operational. Monitoring loopback traffic... (Ctrl+C to exit)")
    print("--------------------------------------------------------------------------------")

    # 4. Main Control Thread Sleep Loop
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n--------------------------------------------------------------------------------")
        print("[!] KeyboardInterrupt caught. Initiating clean system shutdown...")

        print("[*] Releasing kernel driver ingestion hooks...")
        sniffer.stop()

        # Flush Memory queues and halt background workers safely
        print("[*] Draining and flushing remaining memory queues to disk...")
        logger.stop()

        print("[+] All host thread resources cleanly deallocated.")
        print("[+] System offline. Exiting safely.")
        print("================================================================================")
        sys.exit(0)


if __name__ == "__main__":
    main()
