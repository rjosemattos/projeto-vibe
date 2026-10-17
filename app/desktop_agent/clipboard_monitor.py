"""Real-time Clipboard Monitor and Active Chat Interceptor for the Windows Desktop Agent."""

import threading
import time
from typing import Callable, Optional, Tuple

from app.core.logging import get_logger
from app.desktop_agent.service import DesktopSanitizeResult, DesktopSanitizerService
from app.desktop_agent.win32_bridge import Win32Bridge

logger = get_logger(__name__)


class ClipboardGuardMonitor:
    """Monitors clipboard changes and orchestrates active chat prompt sanitization."""

    def __init__(
        self,
        service: DesktopSanitizerService,
        bridge: Win32Bridge,
        on_sanitized_event: Optional[Callable[[DesktopSanitizeResult, str], None]] = None,
        on_window_change: Optional[Callable[[str, bool], None]] = None,
        poll_interval_sec: float = 0.25,
    ):
        self.service = service
        self.bridge = bridge
        self.on_sanitized_event = on_sanitized_event
        self.on_window_change = on_window_change
        self.poll_interval_sec = poll_interval_sec

        self.enabled: bool = True
        self.auto_clipboard: bool = True

        self._last_observed_hash: str = ""
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._action_lock = threading.RLock()

    def start(self) -> None:
        """Starts the background clipboard and active-window monitoring thread."""
        if self._running:
            return
        self._running = True
        # Snapshot initial clipboard hash so startup doesn't unexpectedly overwrite old clipboard
        initial_text = self.bridge.get_clipboard_text()
        if initial_text:
            self._last_observed_hash = self.service.compute_text_hash(initial_text)

        self._thread = threading.Thread(
            target=self._monitor_loop, name="ClipboardGuardThread", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stops the background monitoring thread."""
        self._running = False

    def inspect_clipboard_once(self) -> Optional[DesktopSanitizeResult]:
        """Performs a single check-and-sanitize cycle on the current system clipboard."""
        if not self.enabled or not self.auto_clipboard:
            return None

        with self._action_lock:
            current_text = self.bridge.get_clipboard_text()
            if not current_text or not current_text.strip():
                return None

            current_hash = self.service.compute_text_hash(current_text)
            if current_hash == self._last_observed_hash:
                return None

            self._last_observed_hash = current_hash

            if self.service.is_already_sanitized(current_text):
                return None

            result = self.service.sanitize_prompt(current_text)
            if result.changed:
                self._last_observed_hash = result.sanitized_hash
                self.bridge.set_clipboard_text(result.sanitized_text)
                if self.on_sanitized_event:
                    self.on_sanitized_event(result, "AUTO_CLIPBOARD")
            return result

    def sanitize_active_chat_now(self) -> Optional[DesktopSanitizeResult]:
        """Captures text from the active AI chat input box (Ctrl+A, Ctrl+C), sanitizes, and pastes back (Ctrl+V)."""
        with self._action_lock:
            captured_result: Optional[DesktopSanitizeResult] = None

            def _sanitize_callback(raw_text: str) -> Tuple[str, bool]:
                nonlocal captured_result
                captured_result = self.service.sanitize_prompt(raw_text)
                self._last_observed_hash = captured_result.sanitized_hash
                return captured_result.sanitized_text, captured_result.changed

            self.bridge.capture_and_replace_active_chat(_sanitize_callback)

            if captured_result and self.on_sanitized_event:
                self.on_sanitized_event(captured_result, "ACTIVE_CHAT_HOTKEY")

            return captured_result

    def _monitor_loop(self) -> None:
        """Background daemon loop checking clipboard and active foreground window."""
        last_title = ""
        while self._running:
            try:
                title, is_ai = self.bridge.poll_active_window()
                if title != last_title:
                    last_title = title
                    if self.on_window_change:
                        self.on_window_change(title, is_ai)

                if self.enabled and self.auto_clipboard:
                    self.inspect_clipboard_once()
            except Exception as exc:
                logger.error("Error in ClipboardGuardMonitor loop: %s", type(exc).__name__)

            time.sleep(self.poll_interval_sec)

