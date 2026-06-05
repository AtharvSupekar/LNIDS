import json
import os
import queue
import shutil
import sys
import threading
from datetime import datetime

class JSONLogger:
    def __init__(self, max_queue_size=1000):
        """
        Initializes the asynchronous logging subsystem.
        """
        # 1. Save the file path as instance attribute for easy access throughout.
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(base_dir, "logs")
        self.log_file = os.path.join(self.log_dir, "alerts.json")

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # 2. Instantiate a bounded, thread-safe queue using max_queue_size
        # Note this is a blocking queue - so it blocks producers when full (to prevent over-allocation) and consumers when empty
        self.alert_queue = queue.Queue(maxsize=max_queue_size)

        # 3. Initialize a boolean flag to track if the consumer thread is active
        self.running = False

        # 4. Set up a placeholder attribute for our background worker thread
        self.worker_thread = None

    def _worker(self):
        """
        The background consumer loop that continuously drains the queue
        and writes alerts to the local disk (file(s)) safely.
        """
        try:
            # Open the active log file descriptor in append/read mode
            f = open(self.log_file, "a+", encoding="utf-8")
        except OSError as e:
            print(f"CRITICAL: Failed to open alert log channel: {e}", file=sys.stderr)
            return

        # Explicitly cap the active log file at 10 MB to protect disk footprint
        max_bytes = 1024 * 100

        while self.running or not self.alert_queue.empty():
            try:
                # 1. Attempt to pop an alert from the queue with a 1.0 second timeout
                alert = self.alert_queue.get(timeout=1)

                # Ensure 'timestamp' key exists in the incoming alert dictionary
                if "timestamp" not in alert:
                    # Inject an ISO 8601 string (e.g., "2026-05-30T22:23:18.123456")
                    alert["timestamp"] = datetime.now().isoformat()
                json_str = json.dumps(alert) + "\n"

                # 2. Check if file has reached its specified limit - If yes, create new one
                try:
                    # Evaluate active log file size constraints before committing data
                    f.seek(0, os.SEEK_END)
                    if f.tell() + len(json_str) > max_bytes:
                        f.close()
                        self._rotate_to_archive()
                        # Re-open a brand new, empty active alert file layer
                        f = open(self.log_file, "a+", encoding="utf-8")

                    # Write the entry to the disk buffer and flush instantly
                    f.write(json_str)
                    f.flush()

                except OSError as e:
                    print(f"CRITICAL: Log rotation failed due to OS Error: {e}", file=sys.stderr)

                # 3. Let the queue know the item has been fully processed
                self.alert_queue.task_done()


            except queue.Empty:
                # This block triggers every second if no traffic is coming in.
                # It allows the loop to check if self.running became False so it can exit.
                continue

        f.close()

    def _rotate_to_archive(self):
        """
        Moves the current log file to a dedicated archive directory with an accurate
        forensic timestamp to protect history files from automated deletion.
        """
        archive_dir = os.path.join(os.path.dirname(self.log_file), 'archive')
        if not os.path.exists(archive_dir):
            os.makedirs(archive_dir)

        # Generate a distinct filename based on the exact moment of rotation
        timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archived_filename = f"alerts_{timestamp_str}.json"
        archive_path = os.path.join(archive_dir, archived_filename)

        # Programmatically shift the file location
        if os.path.exists(self.log_file):
            try:
                shutil.move(self.log_file, archive_path)
            except OSError:
                pass

    def start(self):
        """
        Spins up the background thread to begin processing alerts asynchronously.
        """
        # Safety guard: Don't allow multiple worker threads to spawn accidental duplicates
        if self.running:
            return
        self.running = True

        # 1. Instantiate threading.Thread.
        #    Target our private self._worker method, and explicitly pass daemon=True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)

        # 2. Begin the thread execution
        self.worker_thread.start()

    def stop(self):
        """
        Gracefully flushes remaining items in the queue and halts the background worker.
        """
        if not self.running:
            return
        # 1. Block and wait until every single item currently in the queue has completed processing.
        self.running = False

        try:
            self.alert_queue.join()
        except Exception:
            pass

        if self.worker_thread:
            self.worker_thread.join(timeout=1)

