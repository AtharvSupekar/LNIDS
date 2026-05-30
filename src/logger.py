import json
import os
import queue
import threading
from datetime import datetime

class JSONLogger:
    def __init__(self, log_file="logs/alerts.json", max_queue_size=1000):
        """
        Initializes the asynchronous logging subsystem.
        """
        # 1. Save the file path as instance attribute for easy access throughout.
        self.log_file = log_file

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
        # Ensure the log directory actually exists on disk
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        while self.running:
            try:
                # 1. Attempt to pop an alert from the queue with a 1.0 second timeout
                alert = self.alert_queue.get(timeout=1)

                # 2. Open self.log_file in append mode ('a') and write the alert as a JSON string
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps(alert) + '\n')

                # 3. Let the queue know the item has been fully processed
                self.alert_queue.task_done()


            except queue.Empty:
                # This block triggers every second if no traffic is coming in.
                # It allows the loop to check if self.running became False so it can exit.
                continue

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
        self.alert_queue.join()

        self.running = False

        if self.worker_thread:
            self.worker_thread.join()
