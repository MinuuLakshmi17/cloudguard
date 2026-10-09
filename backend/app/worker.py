import time
from .jobs import work_once
if __name__ == "__main__":
    while True:
        try:
            work_once(block=5)
        except Exception as exc:
            print(f"worker error: {exc}", flush=True)
            time.sleep(2)
