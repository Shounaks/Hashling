import gi
import os
import threading
import requests
import hashlib
import base64
import keyring

from gi.repository import GObject, GLib, Gtk, Adw, Gio, Gdk
from utils import calculate_hash, calculate_text_hash, show_error
from attacks import dictionary_attack, rainbow_table_attack, on_crack_success


class PreferencesDialog(Adw.PreferencesWindow):
    def __init__(self, parent, **kwargs):
        super().__init__(transient_for=parent, **kwargs)
        self.set_title("API Key Settings")
        self.set_default_size(600, 200)
        self.parent = parent

        self.api_entry = Gtk.PasswordEntry(show_peek_icon=True, placeholder_text="Enter VirusTotal API Key",
                                           hexpand=True)
        try:
            api_key = keyring.get_password("HashApp", "virustotal")
            self.api_entry.set_text(api_key or "")
        except Exception:
            pass

        save_btn = Gtk.Button(label="Save", css_classes=["suggested-action"], margin_top=12)
        save_btn.connect("clicked", self.on_save)
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup()
        group.add(self.api_entry)
        group.add(save_btn)
        page.add(group)
        self.add(page)

    def on_save(self, button):
        api_key = self.api_entry.get_text()
        try:
            keyring.set_password("HashApp", "virustotal", api_key)
            self.close()
        except Exception as e:
            dialog = Adw.MessageDialog(transient_for=self.parent, heading="Error", body=f"Failed to save key: {str(e)}")
            dialog.add_response("ok", "OK")
            dialog.present()


class HashHexWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_title("Hashling - Artistic Edition")
        self.set_default_size(600, 600)
        self.file_path = None
        self.hex_file_path = None
        self.updating = False
        self.encoding = "utf-8"
        self.hash_history = []
        self.ntlm_hash = None
        self.ntlm_result_label = None

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(main_box)
        header_bar = Adw.HeaderBar()
        main_box.append(header_bar)
        self.notebook = Gtk.Notebook()
        main_box.append(self.notebook)

        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Settings")
        menu = Gio.Menu()
        menu.append("Preferences", "app.preferences")
        popover = Gtk.PopoverMenu()
        popover.set_menu_model(menu)
        menu_btn.set_popover(popover)
        header_bar.pack_end(menu_btn)

        self.create_calculate_tab()
        self.create_hex_tab()
        self.create_recovery_tab()
        self.create_realtime_tab()
        self.create_compare_tab()
        self.create_crack_ntlm_tab()
        self.create_base64_tab()

    def create_calculate_tab(self):
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, margin_top=12, margin_bottom=12, margin_start=12,
                              margin_end=12, spacing=12)
        self.file_entry = Gtk.Entry(placeholder_text="Select a file...", hexpand=True, editable=False)
        file_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select File")
        file_button.connect("clicked", self.on_file_clicked)
        file_row = Gtk.Box(spacing=6)
        file_row.append(self.file_entry)
        file_row.append(file_button)
        content_box.append(file_row)
        content_box.append(Gtk.Separator())

        self.algorithms = [("MD5", True), ("SHA1", True), ("SHA256", True), ("SHA384", True), ("SHA512", True),
                           ("ADLER32", True), ("CRC32", True), ("RIPEMD160", hasattr(hashlib, 'ripemd160'))]
        grid = Gtk.Grid(column_spacing=12, row_spacing=6)
        grid.attach(Gtk.Label(label="Enabled"), 0, 0, 1, 1)
        grid.attach(Gtk.Label(label="Algorithm"), 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Hash Value"), 2, 0, 1, 1)
        grid.attach(Gtk.Label(label="VirusTotal"), 3, 0, 1, 1)
        grid.attach(Gtk.Separator(), 0, 1, 4, 1)

        self.hash_entries = {}
        row = 2
        for algo, available in self.algorithms:
            if not available:
                continue
            check = Gtk.CheckButton(active=True)
            grid.attach(check, 0, row, 1, 1)
            label = Gtk.Label(label=algo)
            grid.attach(label, 1, row, 1, 1)
            entry = Gtk.Entry(editable=False, hexpand=True)
            grid.attach(entry, 2, row, 1, 1)
            vt_button = Gtk.Button(icon_name="globe-symbolic", tooltip_text="Check VirusTotal", sensitive=False)
            vt_button.connect("clicked", self.on_vt_clicked, entry)
            grid.attach(vt_button, 3, row, 1, 1)
            self.hash_entries[algo] = (check, entry, vt_button)
            row += 1

        scrolled = Gtk.ScrolledWindow(vexpand=True)
        scrolled.set_child(grid)
        content_box.append(scrolled)
        self.generate_button = Gtk.Button(label="Generate Selected Hashes", sensitive=False,
                                          css_classes=["suggested-action"])
        self.generate_button.connect("clicked", self.on_generate_clicked)
        content_box.append(self.generate_button)

        history_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        history_box.add_css_class("hash-history")
        history_label = Gtk.Label(label="Hash History")
        history_label.set_halign(Gtk.Align.START)
        history_box.append(history_label)
        self.history_listbox = Gtk.ListBox()
        self.history_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        history_scroll = Gtk.ScrolledWindow(vexpand=True)
        history_scroll.set_child(self.history_listbox)
        history_box.append(history_scroll)
        content_box.append(history_box)

        self.notebook.append_page(content_box, Gtk.Label(label="Calculate"))

    def create_hex_tab(self):
        hex_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                          margin_start=12, margin_end=12)
        toolbar = Gtk.Box(spacing=6)
        open_btn = Gtk.Button(label="Open", tooltip_text="Open File")
        open_btn.connect("clicked", self.on_hex_open_clicked)
        save_btn = Gtk.Button(label="Save", tooltip_text="Save File")
        save_btn.connect("clicked", self.on_hex_save_clicked)
        toolbar.append(open_btn)
        toolbar.append(save_btn)
        encoding_store = Gtk.StringList.new(["utf-8", "utf-16"])
        self.encoding_combo = Gtk.DropDown(model=encoding_store)
        self.encoding_combo.set_selected(0)
        self.encoding_combo.connect("notify::selected", self.on_encoding_changed)
        toolbar.append(self.encoding_combo)
        hex_box.append(toolbar)

        self.input_view = Gtk.TextView()
        self.input_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.input_view.set_monospace(True)
        input_scroll = Gtk.ScrolledWindow(vexpand=True)
        input_scroll.set_child(self.input_view)
        hex_box.append(input_scroll)

        self.hex_view = Gtk.TextView()
        self.hex_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.hex_view.set_monospace(True)
        self.hex_view.set_editable(True)
        hex_scroll = Gtk.ScrolledWindow(vexpand=True)
        hex_scroll.set_child(self.hex_view)
        hex_box.append(hex_scroll)

        self.input_view.get_buffer().connect("changed", self.on_input_changed)
        self.hex_view.get_buffer().connect("changed", self.on_hex_changed)
        self.input_view.get_buffer().connect("mark-set", self.on_cursor_moved)
        self.hex_view.get_buffer().connect("mark-set", self.on_cursor_moved)

        self.notebook.append_page(hex_box, Gtk.Label(label="Hex Editor"))

    def create_realtime_tab(self):
        realtime_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                               margin_start=12, margin_end=12)
        algo_store = Gtk.StringList.new([algo for algo, available in self.algorithms if available])
        self.algo_dropdown = Gtk.DropDown(model=algo_store)
        self.algo_dropdown.set_selected(0)
        algo_label = Gtk.Label(label="Select Hash Algorithm:")
        algo_box = Gtk.Box(spacing=6)
        algo_box.append(algo_label)
        algo_box.append(self.algo_dropdown)
        realtime_box.append(algo_box)

        self.realtime_text_view = Gtk.TextView()
        self.realtime_text_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.realtime_text_view.set_monospace(True)
        text_scroll = Gtk.ScrolledWindow(vexpand=True)
        text_scroll.set_child(self.realtime_text_view)
        realtime_box.append(text_scroll)

        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        separator.add_css_class("custom-separator")
        realtime_box.append(separator)

        self.hash_label = Gtk.Label(label="Hash: (Enter text to compute hash)")
        self.hash_label.set_halign(Gtk.Align.START)
        realtime_box.append(self.hash_label)

        self.realtime_text_view.get_buffer().connect("changed", self.on_realtime_text_changed)
        self.algo_dropdown.connect("notify::selected", self.on_algo_changed)

        self.notebook.append_page(realtime_box, Gtk.Label(label="Real-time Hash"))

    def create_compare_tab(self):
        compare_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                              margin_start=12, margin_end=12)
        self.file1_entry = Gtk.Entry(placeholder_text="Select first file...", hexpand=True, editable=False)
        file1_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select First File")
        file1_button.connect("clicked", self.on_file1_clicked)
        file1_row = Gtk.Box(spacing=6)
        file1_row.append(self.file1_entry)
        file1_row.append(file1_button)
        compare_box.append(file1_row)

        self.file2_entry = Gtk.Entry(placeholder_text="Select second file...", hexpand=True, editable=False)
        file2_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select Second File")
        file2_button.connect("clicked", self.on_file2_clicked)
        file2_row = Gtk.Box(spacing=6)
        file2_row.append(self.file2_entry)
        file2_row.append(file2_button)
        compare_box.append(file2_row)

        self.compare_button = Gtk.Button(label="Compare MD5 Hashes", sensitive=False, css_classes=["suggested-action"])
        self.compare_button.connect("clicked", self.on_compare_clicked)
        compare_box.append(self.compare_button)

        self.compare_result_label = Gtk.Label(label="Select two files to compare")
        self.compare_result_label.set_halign(Gtk.Align.START)
        compare_box.append(self.compare_result_label)

        self.notebook.append_page(compare_box, Gtk.Label(label="Compare Hashes"))

    def create_crack_ntlm_tab(self):
        crack_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                            margin_start=12, margin_end=12, vexpand=True)
        hash_box = Gtk.Box(spacing=6)
        self.ntlm_hash_entry = Gtk.Entry(placeholder_text="Enter NTLM Hash (32 hex chars)...", hexpand=True,
                                         editable=True)
        self.ntlm_hash_entry.set_can_focus(True)
        self.ntlm_hash_entry.connect("changed", self.on_ntlm_hash_changed)
        hash_box.append(self.ntlm_hash_entry)
        crack_box.append(hash_box)

        self.attack_notebook = Gtk.Notebook()
        self.attack_notebook.set_vexpand(True)
        self.create_dictionary_tab()
        self.create_rainbow_tab()
        crack_box.append(self.attack_notebook)

        self.ntlm_result_label = Gtk.Label(label="Enter a valid NTLM hash and select an attack method")
        self.ntlm_result_label.set_halign(Gtk.Align.START)
        self.ntlm_result_label.set_valign(Gtk.Align.END)
        crack_box.append(self.ntlm_result_label)

        self.notebook.append_page(crack_box, Gtk.Label(label="Crack NTLM"))

    def create_dictionary_tab(self):
        dict_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, vexpand=True)
        wordlist_box = Gtk.Box(spacing=6)
        self.wordlist_entry = Gtk.Entry(placeholder_text="Select wordlist file...", hexpand=True, editable=False)
        wordlist_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select Wordlist")
        wordlist_button.connect("clicked", self.on_wordlist_clicked)
        wordlist_box.append(self.wordlist_entry)
        wordlist_box.append(wordlist_button)
        dict_box.append(wordlist_box)

        self.dict_start_button = Gtk.Button(label="Start Dictionary Attack", sensitive=False,
                                            css_classes=["suggested-action"])
        self.dict_start_button.connect("clicked", self.on_dict_start_clicked)
        dict_box.append(self.dict_start_button)

        self.attack_notebook.append_page(dict_box, Gtk.Label(label="Dictionary"))

    def create_rainbow_tab(self):
        rainbow_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, vexpand=True)
        rainbow_file_box = Gtk.Box(spacing=6)
        self.rainbow_entry = Gtk.Entry(placeholder_text="Select rainbow table file...", hexpand=True, editable=False)
        rainbow_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select Rainbow Table")
        rainbow_button.connect("clicked", self.on_rainbow_clicked)
        rainbow_file_box.append(self.rainbow_entry)
        rainbow_file_box.append(rainbow_button)
        rainbow_box.append(rainbow_file_box)

        self.rainbow_start_button = Gtk.Button(label="Start Rainbow Table Attack", sensitive=False,
                                               css_classes=["suggested-action"])
        self.rainbow_start_button.connect("clicked", self.on_rainbow_start_clicked)
        rainbow_box.append(self.rainbow_start_button)

        self.attack_notebook.append_page(rainbow_box, Gtk.Label(label="Rainbow"))

    def create_base64_tab(self):
        base64_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                             margin_start=12, margin_end=12)
        mode_store = Gtk.StringList.new(["Encode", "Decode"])
        self.mode_dropdown = Gtk.DropDown(model=mode_store)
        self.mode_dropdown.set_selected(0)
        mode_label = Gtk.Label(label="Select Mode:")
        mode_box = Gtk.Box(spacing=6)
        mode_box.append(mode_label)
        mode_box.append(self.mode_dropdown)
        base64_box.append(mode_box)

        input_label = Gtk.Label(label="Input Text:")
        input_label.set_halign(Gtk.Align.START)
        base64_box.append(input_label)
        self.base64_input_view = Gtk.TextView()
        self.base64_input_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.base64_input_view.set_monospace(True)
        input_scroll = Gtk.ScrolledWindow(vexpand=True)
        input_scroll.set_child(self.base64_input_view)
        base64_box.append(input_scroll)

        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        separator.add_css_class("custom-separator")
        base64_box.append(separator)

        self.output_label = Gtk.Label(label="Base64 Output:")
        self.output_label.set_halign(Gtk.Align.START)
        base64_box.append(self.output_label)
        self.base64_output_view = Gtk.TextView()
        self.base64_output_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.base64_output_view.set_monospace(True)
        self.base64_output_view.set_editable(False)
        output_scroll = Gtk.ScrolledWindow(vexpand=True)
        output_scroll.set_child(self.base64_output_view)
        base64_box.append(output_scroll)

        self.base64_input_view.get_buffer().connect("changed", self.on_base64_input_changed)
        self.mode_dropdown.connect("notify::selected", self.on_mode_changed)

        self.notebook.append_page(base64_box, Gtk.Label(label="Base64"))

    def on_base64_input_changed(self, buffer):
        try:
            start, end = buffer.get_bounds()
            text = buffer.get_text(start, end, False)
            mode = self.mode_dropdown.get_model().get_string(self.mode_dropdown.get_selected())

            if not text:
                self.base64_output_view.get_buffer().set_text("")
                return

            if mode == "Encode":
                encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
                self.base64_output_view.get_buffer().set_text(encoded)
            else:
                decoded = base64.b64decode(text).decode('utf-8', errors='replace')
                self.base64_output_view.get_buffer().set_text(decoded)
        except Exception as e:
            self.base64_output_view.get_buffer().set_text(f"Error: {str(e)}")

    def on_mode_changed(self, dropdown, param):
        mode = dropdown.get_model().get_string(dropdown.get_selected())
        self.output_label.set_text("Base64 Output:" if mode == "Encode" else "Plaintext Output:")
        self.on_base64_input_changed(self.base64_input_view.get_buffer())

    def on_ntlm_hash_changed(self, entry):
        self.ntlm_hash = entry.get_text().strip()
        is_valid = bool(self.ntlm_hash and len(self.ntlm_hash) == 16 and all(
            c in '0123456789abcdefABCDEF' for c in self.ntlm_hash))  # Not 32 because we want only LM Hash
        has_wordlist = hasattr(self, 'wordlist_path') and os.path.isfile(self.wordlist_path)
        has_rainbow = hasattr(self, 'rainbow_path') and os.path.isfile(self.rainbow_path)
        self.dict_start_button.set_sensitive(is_valid and has_wordlist)
        self.rainbow_start_button.set_sensitive(is_valid and has_rainbow)

    def on_wordlist_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.wordlist_path = file.get_path()
                    self.wordlist_entry.set_text(self.wordlist_path)
                    is_valid = bool(self.ntlm_hash and len(self.ntlm_hash) == 16 and all(
                        c in '0123456789abcdefABCDEF' for c in self.ntlm_hash))
                    self.dict_start_button.set_sensitive(is_valid and os.path.isfile(self.wordlist_path))
            except Exception as e:
                show_error(self, f"Error selecting wordlist: {e}")

        dialog = Gtk.FileDialog(title="Select Wordlist File")
        dialog.open(self, None, on_response)

    def on_rainbow_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.rainbow_path = file.get_path()
                    self.rainbow_entry.set_text(self.rainbow_path)
                    is_valid = bool(self.ntlm_hash and len(self.ntlm_hash) == 32 and all(
                        c in '0123456789abcdefABCDEF' for c in self.ntlm_hash))
                    self.rainbow_start_button.set_sensitive(is_valid and os.path.isfile(self.rainbow_path))
            except Exception as e:
                show_error(self, f"Error selecting rainbow table: {e}")

        dialog = Gtk.FileDialog(title="Select Rainbow Table File")
        dialog.open(self, None, on_response)

    def on_dict_start_clicked(self, button):
        if not self.ntlm_hash or not self.wordlist_path or not os.path.isfile(self.wordlist_path):
            show_error(self, "Invalid hash or wordlist")
            return
        self.ntlm_result_label.set_text("Cracking... (This may take time)")
        self.ntlm_result_label.remove_css_class("success-text")
        threading.Thread(target=dictionary_attack, args=(self, self.ntlm_hash, self.wordlist_path), daemon=True).start()

    def on_rainbow_start_clicked(self, button):
        if not self.ntlm_hash or not self.rainbow_path or not os.path.isfile(self.rainbow_path):
            show_error(self, "Invalid hash or rainbow table")
            return
        self.ntlm_result_label.set_text("Looking up... (This may take time)")
        self.ntlm_result_label.remove_css_class("success-text")
        threading.Thread(target=rainbow_table_attack, args=(self, self.ntlm_hash, self.rainbow_path),
                         daemon=True).start()

    def on_file1_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.file1_path = file.get_path()
                    self.file1_entry.set_text(self.file1_path)
                    self.update_compare_button()
            except Exception as e:
                show_error(self, f"Error selecting first file: {e}")

        dialog = Gtk.FileDialog(title="Select First File")
        dialog.open(self, None, on_response)

    def on_file2_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.file2_path = file.get_path()
                    self.file2_entry.set_text(self.file2_path)
                    self.update_compare_button()
            except Exception as e:
                show_error(self, f"Error selecting second file: {e}")

        dialog = Gtk.FileDialog(title="Select Second File")
        dialog.open(self, None, on_response)

    def update_compare_button(self):
        self.compare_button.set_sensitive(
            hasattr(self, 'file1_path') and hasattr(self, 'file2_path') and os.path.isfile(
                self.file1_path) and os.path.isfile(self.file2_path))

    def on_compare_clicked(self, button):
        try:
            if not (os.path.isfile(self.file1_path) and os.path.isfile(self.file2_path)):
                show_error(self, "One or both files are invalid")
                return
            hash1 = calculate_hash("MD5", self.file1_path)
            hash2 = calculate_hash("MD5", self.file2_path)
            result = "MD5 hashes match!" if hash1 == hash2 else "MD5 hashes do not match"
            self.compare_result_label.set_text(result)
            self.compare_result_label.remove_css_class("error-text" if hash1 == hash2 else "success-text")
            self.compare_result_label.add_css_class("success-text" if hash1 == hash2 else "error-text")
        except Exception as e:
            show_error(self, f"Error comparing hashes: {e}")
            self.compare_result_label.set_text("Error occurred")
            self.compare_result_label.remove_css_class("success-text")
            self.compare_result_label.add_css_class("error-text")

    def on_realtime_text_changed(self, buffer):
        try:
            start, end = buffer.get_bounds()
            text = buffer.get_text(start, end, False)
            algo = self.algo_dropdown.get_model().get_string(self.algo_dropdown.get_selected())
            self.hash_label.set_text(
                f"Hash: {calculate_text_hash(text, algo)}" if text else "Hash: (Enter text to compute hash)")
        except Exception as e:
            self.hash_label.set_text(f"Error: {str(e)}")

    def on_algo_changed(self, dropdown, param):
        try:
            buffer = self.realtime_text_view.get_buffer()
            start, end = buffer.get_bounds()
            text = buffer.get_text(start, end, False)
            algo = dropdown.get_model().get_string(dropdown.get_selected())
            self.hash_label.set_text(
                f"Hash: {calculate_text_hash(text, algo)}" if text else "Hash: (Enter text to compute hash)")
        except Exception as e:
            self.hash_label.set_text(f"Error: {str(e)}")

    def on_hex_open_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.hex_file_path = file.get_path()
                    with open(self.hex_file_path, 'rb') as f:
                        content = f.read()
                    text = content.decode(self.encoding, errors='replace')
                    self.input_view.get_buffer().set_text(text)
            except Exception as e:
                show_error(self, f"Error opening file: {e}")

        dialog = Gtk.FileDialog(title="Open File")
        dialog.open(self, None, on_response)

    def on_hex_save_clicked(self, button):
        if not self.hex_file_path:
            def on_response(dialog, result):
                try:
                    file = dialog.save_finish(result)
                    if file:
                        self.hex_file_path = file.get_path()
                        self.save_hex_content()
                except Exception as e:
                    show_error(self, f"Error saving file: {e}")

            dialog = Gtk.FileDialog(title="Save File")
            dialog.save(self, None, on_response)
        else:
            self.save_hex_content()

    def save_hex_content(self):
        try:
            buffer = self.input_view.get_buffer()
            start, end = buffer.get_bounds()
            text = buffer.get_text(start, end, False)
            with open(self.hex_file_path, 'wb') as f:
                f.write(text.encode(self.encoding, errors='replace'))
        except Exception as e:
            show_error(self, f"Error saving file: {e}")

    def on_encoding_changed(self, combo, param):
        self.encoding = combo.get_model().get_string(combo.get_selected())
        if self.hex_file_path:
            try:
                with open(self.hex_file_path, 'rb') as f:
                    content = f.read()
                text = content.decode(self.encoding, errors='replace')
                self.input_view.get_buffer().set_text(text)
            except Exception as e:
                show_error(self, f"Error applying encoding: {e}")

    def create_recovery_tab(self):
        recovery_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                               margin_start=12, margin_end=12)
        source_box = Gtk.Box(spacing=6)
        self.source_entry = Gtk.Entry(placeholder_text="Select source file...", editable=False)
        source_btn = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select Source")
        source_btn.connect("clicked", self.on_source_clicked)
        source_box.append(self.source_entry)
        source_box.append(source_btn)
        recovery_box.append(source_box)

        target_box = Gtk.Box(spacing=6)
        self.target_entry = Gtk.Entry(placeholder_text="Select target location...", editable=False)
        target_btn = Gtk.Button(icon_name="folder-open-symbolic", tooltip_text="Select Target")
        target_btn.connect("clicked", self.on_target_clicked)
        target_box.append(self.target_entry)
        target_box.append(target_btn)
        recovery_box.append(target_box)

        self.run_button = Gtk.Button(label="Run Recovery", sensitive=False, css_classes=["suggested-action"])
        self.run_button.connect("clicked", self.on_run_clicked)
        recovery_box.append(self.run_button)

        self.notebook.append_page(recovery_box, Gtk.Label(label="Recovery"))

    def on_source_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.source_path = file.get_path()
                    self.source_entry.set_text(self.source_path)
                    self.update_run_button()
            except Exception as e:
                show_error(self, f"Error selecting source: {e}")

        dialog = Gtk.FileDialog(title="Select Source File")
        dialog.open(self, None, on_response)

    def on_target_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.select_folder_finish(result)
                if file:
                    self.target_path = file.get_path()
                    self.target_entry.set_text(self.target_path)
                    self.update_run_button()
            except Exception as e:
                show_error(self, f"Error selecting target: {e}")

        dialog = Gtk.FileDialog(title="Select Target Folder")
        dialog.select_folder(self, None, on_response)

    def update_run_button(self):
        self.run_button.set_sensitive(hasattr(self, 'source_path') and hasattr(self, 'target_path'))

    def on_run_clicked(self, button):
        import subprocess
        try:
            cmd = f"echo {self.source_path} {self.target_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                dialog = Adw.MessageDialog(transient_for=self, heading="Success",
                                           body="Recovery completed successfully", css_classes=["success"])
                dialog.add_response("ok", "OK")
                dialog.present()
            else:
                show_error(self, f"Command failed: {result.stderr}")
        except Exception as e:
            show_error(self, f"Error running command: {e}")

    def on_input_changed(self, buffer):
        if self.updating:
            return
        self.updating = True
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, False)
        hex_text = " ".join(f"{b:02x}" for b in text.encode(self.encoding))
        self.hex_view.get_buffer().set_text(hex_text)
        self.updating = False

    def on_hex_changed(self, buffer):
        if self.updating:
            return
        self.updating = True
        start, end = buffer.get_bounds()
        hex_text = buffer.get_text(start, end, False)
        try:
            hex_values = [x for x in hex_text.split() if x]
            byte_data = bytes(int(x, 16) for x in hex_values if len(x) == 2)
            input_text = byte_data.decode(self.encoding, errors='replace')
            self.input_view.get_buffer().set_text(input_text)
        except (ValueError, UnicodeDecodeError):
            pass
        self.updating = False

    def on_cursor_moved(self, textbuffer, iter, mark):
        pass

    def on_vt_clicked(self, button, entry):
        hash_value = entry.get_text().strip()
        if not hash_value:
            show_error(self, "Generate the hash first.")
            return
        try:
            api_key = keyring.get_password("HashApp", "virustotal")
            if not api_key:
                show_error(self, "Set the API key in Preferences.")
                return
        except Exception as e:
            show_error(self, f"Error fetching API key: {e}")
            return
        button.set_sensitive(False)

        def vt_thread():
            try:
                url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                headers = {"accept": "application/json", "x-apikey": api_key}
                response = requests.get(url, headers=headers)
                GLib.idle_add(self.handle_vt_response, response, None, hash_value, button)
            except Exception as e:
                GLib.idle_add(self.handle_vt_response, None, e, hash_value, button)

        threading.Thread(target=vt_thread, daemon=True).start()

    def handle_vt_response(self, response, error, hash_value, button):
        button.set_sensitive(True)
        if error:
            show_error(self, f"Error: {str(error)}")
            return
        if response.status_code == 404:
            dialog = Adw.MessageDialog(transient_for=self, heading="No Match Found",
                                       body=f"Results for {hash_value} not found in VirusTotal Database")
            dialog.add_response("ok", "OK")
            dialog.present()
            return
        if response.status_code != 200:
            show_error(self, f"API Error: {response.status_code}")
            return
        try:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            msg = f"Malicious: {stats.get('malicious', 0)}\nHarmless: {stats.get('harmless', 0)}\nUndetected: {stats.get('undetected', 0)}"
            dialog = Adw.MessageDialog(transient_for=self, heading=f"Results for {hash_value}", body=msg)
            dialog.add_response("ok", "OK")
            dialog.present()
        except Exception as e:
            show_error(self, f"Failed to parse response: {str(e)}")

    def on_file_clicked(self, button):
        def on_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.file_path = file.get_path()
                    self.file_entry.set_text(self.file_path)
                    self.generate_button.set_sensitive(True)
                    if self.notebook.get_current_page() == 1:
                        self.hex_file_path = self.file_path
                        with open(self.file_path, 'rb') as f:
                            content = f.read()
                        text = content.decode(self.encoding, errors='replace')
                        self.input_view.get_buffer().set_text(text)
            except Exception as e:
                show_error(self, f"Error selecting file: {e}")

        dialog = Gtk.FileDialog(title="Select a File")
        dialog.open(self, None, on_response)

    def on_generate_clicked(self, button):
        if not self.file_path or not os.path.isfile(self.file_path):
            show_error(self, "Invalid file path")
            return
        try:
            hashes = {}
            for algo, (check, entry, vt_button) in self.hash_entries.items():
                entry.set_text("")
                vt_button.set_sensitive(False)
                if check.get_active():
                    hash_value = calculate_hash(algo, self.file_path)
                    entry.set_text(hash_value)
                    vt_button.set_sensitive(bool(hash_value))
                    hashes[algo] = hash_value
            self.hash_history.append((self.file_path, hashes))
            self.update_hash_history()
        except Exception as e:
            show_error(self, f"Error generating hash: {str(e)}")

    def update_hash_history(self):
        self.history_listbox.remove_all()
        for file_path, hashes in reversed(self.hash_history):
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            path_label = Gtk.Label(label=file_path, wrap=True, xalign=0)
            path_label.set_selectable(True)
            path_label.add_css_class("history-path")
            box.append(path_label)
            hash_grid = Gtk.Grid(column_spacing=12, row_spacing=6)
            hash_grid.attach(Gtk.Label(label="Algorithm"), 0, 0, 1, 1)
            hash_grid.attach(Gtk.Label(label="Hash Value"), 1, 0, 1, 1)
            row_idx = 1
            for algo, hash_value in hashes.items():
                hash_grid.attach(Gtk.Label(label=algo), 0, row_idx, 1, 1)
                hash_value_label = Gtk.Label(label=hash_value)
                hash_value_label.set_selectable(True)
                hash_value_label.set_xalign(1.0)
                hash_value_label.add_css_class("history-hash")
                hash_grid.attach(hash_value_label, 1, row_idx, 1, 1)
                row_idx += 1
            box.append(hash_grid)
            row.set_child(box)
            self.history_listbox.append(row)