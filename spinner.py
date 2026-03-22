import sys
import threading
import time

class Spinner:
    """
    Animated terminal spinner shown during API requests.
 
    Uses a background thread to animate independently of the main thread
    so it keeps spinning even while blocking I/O (like httpx requests) runs.
 
    Usage:
        with Spinner("Authenticating"):
            result = api_client.login(username, password)
 
        with Spinner("Saving credentials"):
            api_client.add_vault_entry(...)
    """
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    _INTERVAL = 0.08   # seconds between frames
    
    def __init__(self, message: str = "Loading"):
        self.message = message
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        
    def _spin(self) -> None:
        """Background thread target — writes frames until stop is signalled."""
        frame_index = 0
        while not self._stop_event.is_set():
            frame = self._FRAMES[frame_index % len(self._FRAMES)]
            
            sys.stdout.write(f"\r  {frame}  {self.message}...")
            sys.stdout.flush()
            frame_index += 1
            time.sleep(self._INTERVAL)
            
    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        
    def stop(self, final_message: str | None = None) -> None:
        """
        Stop the spinner and optionally print a final status message.
 
        Args:
            final_message: Shown after the spinner stops. If None, the
                           spinner line is cleared with no replacement.
        """
        self._stop_event.set()
        if self._thread:
            self._thread.join()
            
        # clear the spinner line completely
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()
        
        if final_message:
            print(final_message)
        
    
    def __enter__(self) -> "Spinner":
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exec_tb) -> None:
        self.stop()
        return False
         