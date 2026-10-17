"""Windows Win32 API Bridge for Global Hotkeys, Clipboard, and Active AI Chat Interception.

Uses Python's built-in `ctypes` to interface directly with `user32.dll` and `kernel32.dll`
on Windows, requiring zero external C++ compilation while providing graceful fallbacks
for automated testing on Linux/macOS.
"""

import ctypes
import sys
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from app.core.logging import get_logger

logger = get_logger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Win32 Constants
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_NOREPEAT = 0x4000

WM_HOTKEY = 0x0312
WM_QUIT = 0x0012

VK_CONTROL = 0x11
VK_SHIFT = 0x10
VK_MENU = 0x12  # Alt
VK_A = 0x41
VK_C = 0x43
VK_V = 0x56
VK_S = 0x53
VK_E = 0x45
VK_H = 0x48

KEYEVENTF_KEYUP = 0x0002

# Known AI Chat & Workspace keywords for smart window detection
AI_CHAT_INDICATORS = (
    "chatgpt",
    "claude",
    "gemini",
    "copilot",
    "deepseek",
    "perplexity",
    "openai",
    "anthropic",
    "mistral",
    "poe",
    "cursor",
    "visual studio code",
    "vscode",
    "slack",
    "teams",
    "discord",
    "whatsapp",
    "chrome",
    "edge",
    "firefox",
    "brave",
    "opera",
)


class Win32Bridge:
    """Native Windows OS integration for clipboard, active window tracking, and hotkeys."""

    def __init__(
        self,
        fallback_get_clipboard: Optional[Callable[[], str]] = None,
        fallback_set_clipboard: Optional[Callable[[str], None]] = None,
    ):
        self._fallback_get = fallback_get_clipboard
        self._fallback_set = fallback_set_clipboard
        self._clipboard_lock = threading.RLock()
        self.last_external_hwnd: int = 0
        self.last_external_title: str = "Aguardando janela de Chat IA..."
        self._own_window_titles = {"Prompt Sanitizer", "Prompt Sanitizer — Regras Confidenciais"}

        if IS_WINDOWS:
            self.user32 = ctypes.windll.user32
            self.kernel32 = ctypes.windll.kernel32
            self._configure_win32_signatures()
        else:
            self.user32 = None
            self.kernel32 = None

    def _configure_win32_signatures(self) -> None:
        """Sets ctypes argtypes and restypes for 64-bit Windows pointer safety."""
        if not IS_WINDOWS:
            return
        self.kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        self.kernel32.GlobalAlloc.restype = ctypes.c_void_p

        self.kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        self.kernel32.GlobalLock.restype = ctypes.c_void_p

        self.kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        self.kernel32.GlobalUnlock.restype = ctypes.c_bool

        self.kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
        self.kernel32.GlobalSize.restype = ctypes.c_size_t

        self.user32.GetClipboardData.argtypes = [ctypes.c_uint]
        self.user32.GetClipboardData.restype = ctypes.c_void_p

        self.user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        self.user32.SetClipboardData.restype = ctypes.c_void_p

    # ------------------------------------------------------------------
    # Clipboard Operations
    # ------------------------------------------------------------------

    def get_clipboard_text(self) -> str:
        """Reads Unicode text from the system clipboard safely."""
        with self._clipboard_lock:
            if not IS_WINDOWS:
                if self._fallback_get:
                    try:
                        return self._fallback_get() or ""
                    except Exception:
                        return ""
                return ""

            # Retry loop in case another app briefly holds the clipboard lock
            for _ in range(5):
                if self.user32.OpenClipboard(None):
                    try:
                        if not self.user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                            return ""
                        handle = self.user32.GetClipboardData(CF_UNICODETEXT)
                        if not handle:
                            return ""
                        ptr = self.kernel32.GlobalLock(handle)
                        if not ptr:
                            return ""
                        try:
                            text = ctypes.wstring_at(ptr)
                            return text or ""
                        finally:
                            self.kernel32.GlobalUnlock(handle)
                    finally:
                        self.user32.CloseClipboard()
                time.sleep(0.015)
            return ""

    def set_clipboard_text(self, text: str) -> bool:
        """Writes Unicode text to the system clipboard safely."""
        with self._clipboard_lock:
            if not IS_WINDOWS:
                if self._fallback_set:
                    try:
                        self._fallback_set(text)
                        return True
                    except Exception:
                        return False
                return False

            encoded_bytes = (text + "\0").encode("utf-16-le")
            byte_count = len(encoded_bytes)

            for _ in range(5):
                if self.user32.OpenClipboard(None):
                    try:
                        self.user32.EmptyClipboard()
                        h_mem = self.kernel32.GlobalAlloc(GMEM_MOVEABLE, byte_count)
                        if not h_mem:
                            return False
                        ptr = self.kernel32.GlobalLock(h_mem)
                        if not ptr:
                            return False
                        try:
                            ctypes.memmove(ptr, encoded_bytes, byte_count)
                        finally:
                            self.kernel32.GlobalUnlock(h_mem)

                        if not self.user32.SetClipboardData(CF_UNICODETEXT, h_mem):
                            return False
                        return True
                    finally:
                        self.user32.CloseClipboard()
                time.sleep(0.015)
            return False

    # ------------------------------------------------------------------
    # Foreground Window Detection & Focus Management
    # ------------------------------------------------------------------

    def poll_active_window(self) -> Tuple[str, bool]:
        """Polls the currently focused Windows application and detects if it is an AI chat.

        Returns:
            Tuple[str, bool]: (window_title, is_ai_chat_context)
        """
        if not IS_WINDOWS:
            return (self.last_external_title, True)

        hwnd = self.user32.GetForegroundWindow()
        if not hwnd:
            return (self.last_external_title, self.is_ai_context(self.last_external_title))

        length = self.user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return (self.last_external_title, self.is_ai_context(self.last_external_title))

        buf = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value.strip()

        if title and not any(own in title for own in self._own_window_titles):
            self.last_external_hwnd = hwnd
            self.last_external_title = title

        return (self.last_external_title, self.is_ai_context(self.last_external_title))

    @staticmethod
    def is_ai_context(title: str) -> bool:
        """Returns True if the window title matches known browsers, IDEs, or AI chats."""
        if not title:
            return False
        lower = title.lower()
        return any(keyword in lower for keyword in AI_CHAT_INDICATORS)

    def restore_external_window_focus(self) -> bool:
        """Restores keyboard focus to the last active AI chat window before sending keystrokes."""
        if not IS_WINDOWS or not self.last_external_hwnd:
            return False
        try:
            self.user32.SetForegroundWindow(self.last_external_hwnd)
            time.sleep(0.06)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # In-Place Active Chat Box Sanitization (Ctrl+A -> Ctrl+C -> Sanitize -> Ctrl+V)
    # ------------------------------------------------------------------

    def _release_modifiers(self) -> None:
        """Ensures Ctrl, Shift, and Alt keys are logically released before synthesizing shortcuts."""
        if not IS_WINDOWS:
            return
        for vk in (VK_CONTROL, VK_SHIFT, VK_MENU):
            self.user32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)
        time.sleep(0.02)

    def _send_ctrl_key(self, vk_code: int) -> None:
        """Synthesizes Ctrl + <vk_code> on Windows."""
        if not IS_WINDOWS:
            return
        self.user32.keybd_event(VK_CONTROL, 0, 0, 0)
        self.user32.keybd_event(vk_code, 0, 0, 0)
        time.sleep(0.015)
        self.user32.keybd_event(vk_code, 0, KEYEVENTF_KEYUP, 0)
        self.user32.keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0)

    def capture_and_replace_active_chat(
        self, sanitize_fn: Callable[[str], Tuple[str, bool]]
    ) -> Optional[str]:
        """Captures text from the focused AI chat input box, sanitizes it, and pastes it back.

        Args:
            sanitize_fn: Callback taking raw text and returning (sanitized_text, changed).

        Returns:
            The sanitized text if operation succeeded, or None.
        """
        if IS_WINDOWS:
            self.restore_external_window_focus()
            self._release_modifiers()

            # 1. Select all text inside the active chat input box (Ctrl+A) and copy (Ctrl+C)
            self._send_ctrl_key(VK_A)
            time.sleep(0.04)
            self._send_ctrl_key(VK_C)
            time.sleep(0.07)

        raw_text = self.get_clipboard_text()
        if not raw_text or not raw_text.strip():
            return None

        sanitized_text, _ = sanitize_fn(raw_text)
        self.set_clipboard_text(sanitized_text)

        if IS_WINDOWS:
            time.sleep(0.03)
            # 2. Paste sanitized prompt directly over the selected chat input (Ctrl+V)
            self._send_ctrl_key(VK_V)

        return sanitized_text


class GlobalHotkeyListener:
    """Registers system-wide Windows hotkeys using Win32 RegisterHotKey."""

    HOTKEY_SANITIZE_CHAT = 101  # Ctrl + Shift + S
    HOTKEY_TOGGLE_AGENT = 102   # Ctrl + Shift + E
    HOTKEY_TOGGLE_HUD = 103     # Ctrl + Shift + H

    def __init__(
        self,
        on_sanitize_chat: Callable[[], None],
        on_toggle_agent: Callable[[], None],
        on_toggle_hud: Callable[[], None],
    ):
        self.on_sanitize_chat = on_sanitize_chat
        self.on_toggle_agent = on_toggle_agent
        self.on_toggle_hud = on_toggle_hud
        self._thread: Optional[threading.Thread] = None
        self._thread_id: Optional[int] = None
        self._running = False

    def start(self) -> None:
        """Starts the background Win32 message loop for global hotkeys."""
        if not IS_WINDOWS or self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._win32_hotkey_loop, name="Win32HotkeyThread", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stops the global hotkey message loop cleanly."""
        self._running = False
        if IS_WINDOWS and self._thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
            except Exception:
                pass

    def _win32_hotkey_loop(self) -> None:
        """Native Win32 thread message loop handling WM_HOTKEY events."""
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        self._thread_id = kernel32.GetCurrentThreadId()

        modifiers = MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT
        bindings: Dict[int, Callable[[], None]] = {
            self.HOTKEY_SANITIZE_CHAT: self.on_sanitize_chat,
            self.HOTKEY_TOGGLE_AGENT: self.on_toggle_agent,
            self.HOTKEY_TOGGLE_HUD: self.on_toggle_hud,
        }

        user32.RegisterHotKey(None, self.HOTKEY_SANITIZE_CHAT, modifiers, VK_S)
        user32.RegisterHotKey(None, self.HOTKEY_TOGGLE_AGENT, modifiers, VK_E)
        user32.RegisterHotKey(None, self.HOTKEY_TOGGLE_HUD, modifiers, VK_H)

        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", ctypes.c_void_p),
                ("message", ctypes.c_uint),
                ("wParam", ctypes.c_size_t),
                ("lParam", ctypes.c_ssize_t),
                ("time", ctypes.c_uint),
                ("pt_x", ctypes.c_long),
                ("pt_y", ctypes.c_long),
            ]

        msg = MSG()
        try:
            while self._running:
                res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if res <= 0 or msg.message == WM_QUIT:
                    break
                if msg.message == WM_HOTKEY:
                    hotkey_id = int(msg.wParam)
                    callback = bindings.get(hotkey_id)
                    if callback:
                        try:
                            callback()
                        except Exception as exc:
                            logger.error("Error in hotkey callback: %s", type(exc).__name__)
        finally:
            for hk_id in bindings:
                user32.UnregisterHotKey(None, hk_id)

