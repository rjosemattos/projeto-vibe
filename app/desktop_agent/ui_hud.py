"""Windows Desktop Floating HUD (Always-on-Top), System Tray, and Native CRUD Manager.

Built with Tkinter + Win32 native ctypes and optional `pystray`/`Pillow` for the Windows
System Tray icon, providing a modern dark corporate interface that floats alongside AI chats.
"""

import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional
from uuid import UUID

from app.core.logging import get_logger
from app.desktop_agent import autostart
from app.desktop_agent.clipboard_monitor import ClipboardGuardMonitor
from app.desktop_agent.service import DesktopSanitizeResult, DesktopSanitizerService
from app.desktop_agent.win32_bridge import GlobalHotkeyListener, IS_WINDOWS, Win32Bridge
from app.models.response import SeverityLevel
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk


logger = get_logger(__name__)

# Color Palette (Corporate Dark Navy / Cyber Theme)
BG_DARK = "#0b1120"
BG_CARD = "#131c31"
BG_INPUT = "#080d1a"
BORDER_COLOR = "#1e2d4d"
TEXT_PRIMARY = "#f8fafc"
TEXT_MUTED = "#94a3b8"
ACCENT_BLUE = "#38bdf8"
ACCENT_INDIGO = "#6366f1"
COLOR_SUCCESS = "#10b981"
COLOR_WARNING = "#f59e0b"
COLOR_DANGER = "#f43f5e"


class RulesManagerWindow(tk.Toplevel):
    """Native desktop window for CRUD management of confidential terms."""

    def __init__(self, parent: tk.Misc, service: DesktopSanitizerService, on_rules_changed: Callable[[], None]):
        super().__init__(parent)
        self.service = service
        self.on_rules_changed = on_rules_changed
        self.editing_rule_id: Optional[UUID] = None

        self.title("Prompt Sanitizer — Regras Confidenciais (CRUD)")
        self.geometry("680x500")
        self.minsize(520, 380)
        self.configure(bg=BG_DARK)
        self.attributes("-topmost", True)
        self.resizable(True, True)

        self._build_ui()
        self._refresh_table()

    def _build_ui(self) -> None:
        # Header
        header = tk.Frame(self, bg=BG_CARD, padx=16, pady=12, highlightthickness=1, highlightbackground=BORDER_COLOR)
        header.pack(fill=tk.X, padx=12, pady=(12, 8))

        tk.Label(
            header,
            text="🔐 Gestão de Termos Confidenciais (AES-256-GCM + Blind Index)",
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Termos nunca são salvos em texto claro. A listagem exibe apenas prévias mascaradas.",
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(2, 0))

        # Form Frame
        form = tk.Frame(self, bg=BG_CARD, padx=16, pady=12, highlightthickness=1, highlightbackground=BORDER_COLOR)
        form.pack(fill=tk.X, padx=12, pady=4)

        row1 = tk.Frame(form, bg=BG_CARD)
        row1.pack(fill=tk.X, pady=(0, 8))

        # Term input
        left_col = tk.Frame(row1, bg=BG_CARD)
        left_col.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        tk.Label(left_col, text="Termo Sensível (ex: CESAR):", bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.term_var = tk.StringVar()
        self.term_entry = tk.Entry(
            left_col,
            textvariable=self.term_var,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=ACCENT_BLUE,
            font=("Segoe UI", 10),
        )
        self.term_entry.pack(fill=tk.X, ipady=5, pady=(2, 0))

        # Tag input
        right_col = tk.Frame(row1, bg=BG_CARD)
        right_col.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        tk.Label(right_col, text="Tag de Substituição (ex: [COMPANY_SENSITIVE]):", bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.tag_var = tk.StringVar()
        self.tag_entry = tk.Entry(
            right_col,
            textvariable=self.tag_var,
            bg=BG_INPUT,
            fg=ACCENT_BLUE,
            insertbackground=TEXT_PRIMARY,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=ACCENT_BLUE,
            font=("Consolas", 10, "bold"),
        )
        self.tag_entry.pack(fill=tk.X, ipady=5, pady=(2, 0))

        # Options & Buttons row
        row2 = tk.Frame(form, bg=BG_CARD)
        row2.pack(fill=tk.X, pady=(4, 0))

        self.case_var = tk.BooleanVar(value=False)
        self.word_var = tk.BooleanVar(value=True)

        tk.Checkbutton(
            row2,
            text="Case-Sensitive (Maiúsc./Minúsc.)",
            variable=self.case_var,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY,
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=(0, 12))

        tk.Checkbutton(
            row2,
            text="Apenas Palavra Inteira",
            variable=self.word_var,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY,
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT)

        self.save_btn = tk.Button(
            row2,
            text="➕ Cadastrar Regra",
            command=self._on_save_clicked,
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=14,
            pady=5,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        self.save_btn.pack(side=tk.RIGHT)

        self.cancel_edit_btn = tk.Button(
            row2,
            text="Cancelar Edição",
            command=self._reset_form,
            bg="#334155",
            fg=TEXT_PRIMARY,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            font=("Segoe UI", 9),
            cursor="hand2",
        )

        # Table Frame
        table_frame = tk.Frame(self, bg=BG_CARD, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER_COLOR)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 12))

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Dark.Treeview",
            background=BG_INPUT,
            foreground=TEXT_PRIMARY,
            fieldbackground=BG_INPUT,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Dark.Treeview.Heading",
            background="#1e293b",
            foreground=ACCENT_BLUE,
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map("Dark.Treeview", background=[("selected", "#0369a1")])

        columns = ("masked", "tag", "case", "word")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Dark.Treeview")
        self.tree.heading("masked", text="Termo (Mascarado)")
        self.tree.heading("tag", text="Tag de Substituição")
        self.tree.heading("case", text="Case-Sensitive")
        self.tree.heading("word", text="Palavra Inteira")

        self.tree.column("masked", width=140, anchor="w")
        self.tree.column("tag", width=220, anchor="w")
        self.tree.column("case", width=110, anchor="center")
        self.tree.column("word", width=110, anchor="center")

       

        # Bottom Actions
        actions = tk.Frame(table_frame, bg=BG_CARD, pady=6)
        actions.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Button(
            actions,
            text="✏️ Editar Regra Selecionada",
            command=self._on_edit_selected,
            bg="#1e293b",
            fg=ACCENT_BLUE,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            actions,
            text="🗑️ Excluir Selecionada",
            command=self._on_delete_selected,
            bg="#4c0519",
            fg="#fb7185",
            relief=tk.FLAT,
            padx=12,
            pady=4,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        ).pack(side=tk.LEFT)

        tk.Button(
            actions,
            text="📥 Importar",
            command=self._on_import_clicked,
            bg="#1e293b",
            fg=ACCENT_BLUE,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        tk.Button(
            actions,
            text="📤 Exportar",
            command=self._on_export_clicked,
            bg="#1e293b",
            fg=ACCENT_BLUE,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        ).pack(side=tk.RIGHT, padx=(0, 8))

        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        
    def _refresh_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        rules = self.service.list_rules()
        for r in rules:
            self.tree.insert(
                "",
                tk.END,
                iid=str(r.id),
                values=(
                    r.masked_term,
                    r.replacement_tag,
                    "Sim" if r.case_sensitive else "Não",
                    "Sim" if r.match_whole_word else "Não",
                ),
            )

    def _reset_form(self) -> None:
        self.editing_rule_id = None
        self.term_var.set("")
        self.tag_var.set("")
        self.case_var.set(False)
        self.word_var.set(True)
        self.save_btn.configure(text="➕ Cadastrar Regra", bg="#0284c7")
        self.cancel_edit_btn.pack_forget()

    def _on_save_clicked(self) -> None:
        term = self.term_var.get().strip()
        tag = self.tag_var.get().strip()
        case_s = self.case_var.get()
        whole_w = self.word_var.get()

        try:
            if self.editing_rule_id is None:
                self.service.create_rule(
                    term=term,
                    replacement_tag=tag,
                    case_sensitive=case_s,
                    match_whole_word=whole_w,
                )
            else:
                self.service.update_rule(
                    rule_id=self.editing_rule_id,
                    term=term if term else None,
                    replacement_tag=tag if tag else None,
                    case_sensitive=case_s,
                    match_whole_word=whole_w,
                )
            self._reset_form()
            self._refresh_table()
            self.on_rules_changed()
        except Exception as exc:
            messagebox.showerror("Erro de Validação", str(exc), parent=self)

    def _on_edit_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Seleção", "Selecione uma regra na tabela para editar.", parent=self)
            return
        rule_id_str = selected[0]
        values = self.tree.item(rule_id_str, "values")
        self.editing_rule_id = UUID(rule_id_str)
        self.term_var.set("")  # Never populate raw term back into entry; optional to change
        self.tag_var.set(values[1])
        self.case_var.set(values[2] == "Sim")
        self.word_var.set(values[3] == "Sim")
        self.save_btn.configure(text="💾 Atualizar Regra (Deixe termo vazio p/ manter)", bg="#059669")
        self.cancel_edit_btn.pack(side=tk.RIGHT, padx=(0, 8))

    def _on_delete_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Seleção", "Selecione uma regra na tabela para excluir.", parent=self)
            return
        rule_id = UUID(selected[0])
        masked, tag, *_ = self.tree.item(selected[0], "values")
        confirmed = messagebox.askyesno(
            "Excluir regra",
            f"Deseja excluir a regra abaixo?\n\nTermo: {masked}\nTag: {tag}\n\n"
            "Esta ação não pode ser desfeita.",
            icon="warning",
            parent=self,
        )
        if not confirmed:
            return
        self.service.delete_rule(rule_id)
        if self.editing_rule_id == rule_id:
            self._reset_form()
        self._refresh_table()
        self.on_rules_changed()

    BACKUP_FILETYPES = [("Backup do Prompt Sanitizer", "*.psbackup")]

    def _on_export_clicked(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Exportar regras",
            defaultextension=".psbackup",
            filetypes=self.BACKUP_FILETYPES,
        )
        if not path:
            return
        password = simpledialog.askstring(
            "Senha do backup",
            "Crie uma senha para o backup (mínimo 8 caracteres):",
            show="*",
            parent=self,
        )
        if not password:
            return
        confirmation = simpledialog.askstring(
            "Senha do backup", "Repita a senha:", show="*", parent=self
        )
        if confirmation != password:
            messagebox.showerror("Exportar regras", "As senhas não conferem.", parent=self)
            return
        try:
            count = self.service.export_rules(Path(path), password)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Exportar regras", str(exc), parent=self)
            return
        messagebox.showinfo("Exportar regras", f"{count} regra(s) exportada(s).", parent=self)

    def _on_import_clicked(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Importar regras", filetypes=self.BACKUP_FILETYPES
        )
        if not path:
            return
        password = simpledialog.askstring(
            "Senha do backup", "Senha do backup:", show="*", parent=self
        )
        if not password:
            return
        try:
            imported, skipped = self.service.import_rules(Path(path), password)
        except (ValueError, RulesStoreError) as exc:
            messagebox.showerror("Importar regras", str(exc), parent=self)
            return
        self._refresh_table()
        self.on_rules_changed()
        messagebox.showinfo(
            "Importar regras",
            f"{imported} regra(s) importada(s); "
            f"{skipped} ignorada(s) por já existirem ou serem inválidas.",
            parent=self,
        )


class PromptSanitizerDesktopApp:
    """Main controller for the Always-on-Top HUD, System Tray Icon, and Real-Time Interceptors."""

    def __init__(self, service: Optional[DesktopSanitizerService] = None, start_hidden: bool = False):
        self.service = service or DesktopSanitizerService()
        self.root = tk.Tk()
        self.root.title("Prompt Sanitizer")
        self.root.configure(bg=BG_DARK)
        self.root.attributes("-topmost", True)
        self.root.resizable(True, True)

        # Position HUD in bottom-right of primary screen (clamped to small displays)
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        hud_w = min(390, max(300, screen_w - 40))
        hud_h = min(345, max(280, screen_h - 100))
        self.root.minsize(min(hud_w, 340), min(hud_h, 300))
        self.root.maxsize(max(hud_w, 700), max(hud_h, 600))
        pos_x = max(0, screen_w - hud_w - 28)
        pos_y = max(0, screen_h - hud_h - 75)
        self.root.geometry(f"{hud_w}x{hud_h}+{pos_x}+{pos_y}")

        # Thread-safe UI event queue
        self._ui_queue: queue.Queue[Callable[[], None]] = queue.Queue()

        # Bridge & Monitor
        self.bridge = Win32Bridge(
            fallback_get_clipboard=self._tk_get_clipboard,
            fallback_set_clipboard=self._tk_set_clipboard,
        )
        self.monitor = ClipboardGuardMonitor(
            service=self.service,
            bridge=self.bridge,
            on_sanitized_event=self._schedule_sanitized_notification,
            on_window_change=self._schedule_window_change,
        )
        self.hotkeys = GlobalHotkeyListener(
            on_sanitize_chat=self._trigger_sanitize_active_chat,
            on_toggle_agent=self._schedule_toggle_agent,
            on_toggle_hud=self._schedule_toggle_hud,
        )

        self._rules_window: Optional[RulesManagerWindow] = None
        self._hud_visible = True
        self._tray_icon = None

        self._build_hud_ui()
        self._setup_system_tray()

        # Background mode: run only from the tray (the HUD stays reachable via tray or Ctrl+Shift+H).
        # Without a tray icon the HUD is kept visible so the agent can always be reached.
        if start_hidden and self._tray_icon is not None:
            self.root.withdraw()
            self._hud_visible = False

    # ------------------------------------------------------------------
    # Tkinter Clipboard Fallbacks (for non-Win32 environments)
    # ------------------------------------------------------------------

    def _tk_get_clipboard(self) -> str:
        try:
            return self.root.clipboard_get()
        except Exception:
            return ""

    def _tk_set_clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # HUD Interface Construction
    # ------------------------------------------------------------------

    def _build_hud_ui(self) -> None:
        main_frame = tk.Frame(
            self.root,
            bg=BG_DARK,
            padx=12,
            pady=10,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Top Header Bar
        top_row = tk.Frame(main_frame, bg=BG_DARK)
        top_row.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            top_row,
            text="🛡️ PROMPT SANITIZER",
            bg=BG_DARK,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT)

        self.status_pill = tk.Label(
            top_row,
            text="● ATIVO (ON)",
            bg="#064e3b",
            fg="#34d399",
            padx=8,
            pady=2,
            font=("Segoe UI", 8, "bold"),
        )
        self.status_pill.pack(side=tk.RIGHT)

        # 2. Active Window Context Indicator
        ctx_card = tk.Frame(
            main_frame,
            bg=BG_CARD,
            padx=10,
            pady=6,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        ctx_card.pack(fill=tk.X, pady=(0, 8))

        self.window_label = tk.Label(
            ctx_card,
            text="🎯 Janela Ativa: Monitorando chats de IA...",
            bg=BG_CARD,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        )
        self.window_label.pack(fill=tk.X)

        # 3. Primary Controls (Toggle ON/OFF + Active Chat Clean Button)
        controls_frame = tk.Frame(main_frame, bg=BG_DARK)
        controls_frame.pack(fill=tk.X, pady=(0, 8))

        self.toggle_btn = tk.Button(
            controls_frame,
            text="🟢 Proteção Automática: LIGADA (Ctrl+Shift+E)",
            command=self.toggle_agent_state,
            bg="#059669",
            fg="#ffffff",
            activebackground="#047857",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            pady=6,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        self.toggle_btn.pack(fill=tk.X, pady=(0, 6))

        self.clean_chat_btn = tk.Button(
            controls_frame,
            text="⚡ Limpar Campo do Chat Ativo (Ctrl+Shift+S)",
            command=self._trigger_sanitize_active_chat,
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            pady=6,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        self.clean_chat_btn.pack(fill=tk.X)

        # 4. Telemetry & Last Action Feedback Box
        telemetry_card = tk.Frame(
            main_frame,
            bg=BG_CARD,
            padx=10,
            pady=8,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        telemetry_card.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        stats_row = tk.Frame(telemetry_card, bg=BG_CARD)
        stats_row.pack(fill=tk.X, pady=(0, 4))

        self.stats_label = tk.Label(
            stats_row,
            text="Prompts protegidos: 0  |  Dados ocultados: 0",
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=("Segoe UI", 8, "bold"),
        )
        self.stats_label.pack(side=tk.LEFT)

        self.rules_count_label = tk.Label(
            stats_row,
            text=f"Regras CRUD: {len(self.service.list_rules())}",
            bg=BG_CARD,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 8, "bold"),
        )
        self.rules_count_label.pack(side=tk.RIGHT)

        self.event_banner = tk.Label(
            telemetry_card,
            text="Copie qualquer texto (Ctrl+C) ou pressione Ctrl+Shift+S dentro do ChatGPT, Claude ou Copilot para higienizar em tempo real.",
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            font=("Segoe UI", 8),
            wraplength=340,
            justify=tk.LEFT,
            padx=8,
            pady=6,
            anchor="w",
        )
        self.event_banner.pack(fill=tk.BOTH, expand=True)
        # Keep banner text wrapping in sync with the (resizable) HUD width
        telemetry_card.bind(
            "<Configure>",
            lambda e: self.event_banner.configure(wraplength=max(120, e.width - 40)),
        )

        # 5. Footer Buttons (CRUD & Hide to Tray)
        footer_row = tk.Frame(main_frame, bg=BG_DARK)
        footer_row.pack(fill=tk.X)

        tk.Button(
            footer_row,
            text="🔐 Termos Confidenciais (CRUD)",
            command=self.open_rules_manager,
            bg="#1e293b",
            fg=ACCENT_BLUE,
            activebackground="#334155",
            activeforeground=ACCENT_BLUE,
            relief=tk.FLAT,
            padx=10,
            pady=4,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        ).pack(side=tk.LEFT)

        tk.Button(
            footer_row,
            text="🗕 Ocultar HUD (Ctrl+Shift+H)",
            command=self.toggle_hud_visibility,
            bg="#1e293b",
            fg=TEXT_MUTED,
            activebackground="#334155",
            activeforeground=TEXT_PRIMARY,
            relief=tk.FLAT,
            padx=10,
            pady=4,
            font=("Segoe UI", 8),
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        # Local keybindings when HUD itself is focused
        self.root.bind("<Control-Shift-S>", lambda _: self._trigger_sanitize_active_chat())
        self.root.bind("<Control-Shift-s>", lambda _: self._trigger_sanitize_active_chat())
        self.root.bind("<Control-Shift-E>", lambda _: self.toggle_agent_state())
        self.root.bind("<Control-Shift-e>", lambda _: self.toggle_agent_state())

    # ------------------------------------------------------------------
    # System Tray Icon (Windows Notification Area)
    # ------------------------------------------------------------------

    def _setup_system_tray(self) -> None:
        """Initializes Windows System Tray icon if pystray and Pillow are available."""
        try:
            import pystray
            from PIL import Image, ImageDraw

            def _create_shield_image(active: bool) -> "Image.Image":
                img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
                draw = ImageDraw.Draw(img)
                fill_color = (16, 185, 129, 255) if active else (100, 116, 139, 255)
                outline_color = (56, 189, 248, 255) if active else (148, 163, 184, 255)
                # Shield polygon
                points = [(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)]
                draw.polygon(points, fill=fill_color, outline=outline_color)
                return img

            self._create_tray_image = _create_shield_image

            menu = pystray.Menu(
                pystray.MenuItem(
                    "Alternar Proteção (ON/OFF)",
                    lambda icon, item: self._schedule_toggle_agent(),
                ),
                pystray.MenuItem(
                    "Limpar Chat Ativo (Ctrl+Shift+S)",
                    lambda icon, item: self._trigger_sanitize_active_chat(),
                ),
                pystray.MenuItem(
                    "Mostrar / Ocultar HUD",
                    lambda icon, item: self._schedule_toggle_hud(),
                    default=True,
                ),
                pystray.MenuItem(
                    "Regras Confidenciais (CRUD)",
                    lambda icon, item: self._ui_queue.put(self.open_rules_manager),
                ),
                pystray.MenuItem(
                    "Iniciar com o Windows",
                    lambda icon, item: self._toggle_autostart(),
                    checked=lambda item: autostart.is_enabled(),
                    visible=autostart.IS_WINDOWS,
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    "Encerrar Prompt Sanitizer",
                    lambda icon, item: self._ui_queue.put(self.shutdown),
                ),
            )

            self._tray_icon = pystray.Icon(
                "PromptSanitizer",
                _create_shield_image(True),
                "Prompt Sanitizer — Ativo (ON)",
                menu,
            )
            threading.Thread(target=self._tray_icon.run, name="SystemTrayThread", daemon=True).start()
        except Exception:
            # pystray is optional; HUD works standalone if not installed
            self._tray_icon = None

    # ------------------------------------------------------------------
    # State & Event Handlers
    # ------------------------------------------------------------------

    def toggle_agent_state(self) -> None:
        """Toggles real-time sanitization ON or OFF."""
        self.monitor.enabled = not self.monitor.enabled
        is_on = self.monitor.enabled

        if is_on:
            self.status_pill.configure(text="● ATIVO (ON)", bg="#064e3b", fg="#34d399")
            self.toggle_btn.configure(
                text="🟢 Proteção Automática: LIGADA (Ctrl+Shift+E)",
                bg="#059669",
                activebackground="#047857",
            )
            self.event_banner.configure(
                text="Proteção em tempo real ATIVADA. Qualquer dado sensível copiado será sanitizado automaticamente.",
                fg="#34d399",
            )
        else:
            self.status_pill.configure(text="○ PAUSADO (OFF)", bg="#1e293b", fg=TEXT_MUTED)
            self.toggle_btn.configure(
                text="⚪ Proteção Automática: PAUSADA (Ctrl+Shift+E)",
                bg="#475569",
                activebackground="#334155",
            )
            self.event_banner.configure(
                text="Proteção automática em pausa. Pressione Ctrl+Shift+E ou clique acima para reativar.",
                fg=TEXT_MUTED,
            )

        if self._tray_icon and hasattr(self, "_create_tray_image"):
            try:
                self._tray_icon.icon = self._create_tray_image(is_on)
                self._tray_icon.title = f"Prompt Sanitizer — {'Ativo (ON)' if is_on else 'Pausado (OFF)'}"
            except Exception:
                pass

    def _toggle_autostart(self) -> None:
        """Registers/unregisters the agent to start silently in the tray at Windows logon."""
        try:
            autostart.set_enabled(not autostart.is_enabled())
        except OSError as exc:
            logger.error("Could not change start-with-Windows setting: %s", type(exc).__name__)
        if self._tray_icon:
            try:
                self._tray_icon.update_menu()
            except Exception:
                pass

    def toggle_hud_visibility(self) -> None:
        """Shows or hides the floating HUD window."""
        if self._hud_visible:
            self.root.withdraw()
            self._hud_visible = False
        else:
            self.root.deiconify()
            self.root.attributes("-topmost", True)
            self._hud_visible = True

    def open_rules_manager(self) -> None:
        """Opens the CRUD Rules Manager window."""
        if self._rules_window and self._rules_window.winfo_exists():
            self._rules_window.lift()
            self._rules_window.focus_force()
            return
        self._rules_window = RulesManagerWindow(
            self.root,
            self.service,
            on_rules_changed=self._update_rules_counter,
        )

    def _update_rules_counter(self) -> None:
        count = len(self.service.list_rules())
        self.rules_count_label.configure(text=f"Regras CRUD: {count}")

    def _trigger_sanitize_active_chat(self) -> None:
        """Runs active chat box capture & replacement in a short worker thread to avoid blocking UI."""
        threading.Thread(
            target=self.monitor.sanitize_active_chat_now,
            name="ActiveChatSanitizeWorker",
            daemon=True,
        ).start()

    def _schedule_sanitized_notification(self, result: DesktopSanitizeResult, source: str) -> None:
        self._ui_queue.put(lambda: self._render_sanitized_result(result, source))

    def _schedule_window_change(self, title: str, is_ai: bool) -> None:
        self._ui_queue.put(lambda: self._render_window_title(title, is_ai))

    def _schedule_toggle_agent(self) -> None:
        self._ui_queue.put(self.toggle_agent_state)

    def _schedule_toggle_hud(self) -> None:
        self._ui_queue.put(self.toggle_hud_visibility)

    def _render_window_title(self, title: str, is_ai: bool) -> None:
        short_title = title[:38] + "..." if len(title) > 38 else title
        prefix = "🟢 Chat/App IA:" if is_ai else "🎯 Janela:"
        color = "#34d399" if is_ai else ACCENT_BLUE
        self.window_label.configure(text=f"{prefix} {short_title}", fg=color)

    def _render_sanitized_result(self, result: DesktopSanitizeResult, source: str) -> None:
        self.stats_label.configure(
            text=f"Prompts protegidos: {self.service.total_prompts_protected}  |  "
                 f"Dados ocultados: {self.service.total_entities_redacted}"
        )

        origin_label = "Chat Ativo" if source == "ACTIVE_CHAT_HOTKEY" else "Clipboard Auto"
        if not result.changed:
            self.event_banner.configure(
                text=f"✅ [{result.timestamp} • {origin_label}] Nenhum dado sensível encontrado. Prompt seguro!",
                bg="#06281e",
                fg="#a7f3d0",
            )
            return

        if result.risk_level in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            banner_bg = "#2a1215"
            banner_fg = "#fecdd3"
        elif result.risk_level == SeverityLevel.MEDIUM:
            banner_bg = "#261a06"
            banner_fg = "#fef08a"
        else:
            banner_bg = "#06281e"
            banner_fg = "#a7f3d0"

        self.event_banner.configure(
            text=f"🛡️ [{result.timestamp} • {origin_label}] {result.summary_badge}",
            bg=banner_bg,
            fg=banner_fg,
        )

    def _process_ui_queue(self) -> None:
        while not self._ui_queue.empty():
            try:
                task = self._ui_queue.get_nowait()
                task()
            except Exception as exc:
                logger.error("UI queue task error: %s", type(exc).__name__)
        self.root.after(100, self._process_ui_queue)

    def run(self) -> None:
        """Starts background monitors, global hotkeys, and enters the Tkinter mainloop."""
        self.monitor.start()
        self.hotkeys.start()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.root.after(100, self._process_ui_queue)
        self.root.mainloop()

    def shutdown(self) -> None:
        """Gracefully stops background threads, unregisters hotkeys, and closes the app."""
        self.monitor.stop()
        self.hotkeys.stop()
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
        self.root.destroy()

