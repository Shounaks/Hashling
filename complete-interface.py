import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version('Secret', '1')

import hashlib
import os
import zlib
import keyring
import threading
import requests
from gi.repository import GObject

from gi.repository import Secret, GLib, Gtk, Adw, Gio

# Schema for secret storage
SECRET_SCHEMA = Secret.Schema.new(
    "com.example.HashApp",
    Secret.SchemaFlags.NONE,
    {
        "service": Secret.SchemaAttributeType.STRING,
        "username": Secret.SchemaAttributeType.STRING,
    },
)


class PreferencesDialog(Adw.PreferencesWindow):
    def __init__(self, parent, **kwargs):
        super().__init__(transient_for=parent, **kwargs)
        self.set_title("API Key Settings")
        self.set_default_size(600, 200)
        self.parent = parent

        self.api_entry = Gtk.PasswordEntry(
            show_peek_icon=True,
            placeholder_text="Enter VirusTotal API Key",
            hexpand=True
        )

        try:
            api_key = keyring.get_password("HashApp", "virustotal")
            self.api_entry.set_text(api_key or "")
        except Exception as e:
            print(f"Error loading key: {e}")

        save_btn = Gtk.Button(
            label="Save",
            css_classes=["suggested-action"],
            margin_top=12
        )
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
            dialog = Adw.MessageDialog(
                transient_for=self.parent,
                heading="Error",
                body=f"Failed to save key: {str(e)}"
            )
            dialog.add_response("ok", "OK")
            dialog.present()


class HashHexWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_title("Hashling - File Hash & Hex Editor")
        self.set_default_size(600, 600)

        # Initialize class variables
        self.file_path = None
        self.hex_file_path = None
        self.updating = False
        self.encoding = "utf-8"  # Default encoding

        # Main container
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(main_box)

        # Header bar
        header_bar = Adw.HeaderBar()
        main_box.append(header_bar)

        # Notebook
        self.notebook = Gtk.Notebook()
        main_box.append(self.notebook)

        # Menu button
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Settings")
        menu = Gio.Menu()
        menu.append("Preferences", "app.preferences")
        popover = Gtk.PopoverMenu()
        popover.set_menu_model(menu)
        menu_btn.set_popover(popover)
        header_bar.pack_end(menu_btn)

        # Create tabs
        self.create_calculate_tab()
        self.create_hex_tab()
        self.create_recovery_tab()

    def create_calculate_tab(self):
        content_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
            spacing=12
        )

        # File selection
        self.file_entry = Gtk.Entry(
            placeholder_text="Select a file...",
            hexpand=True,
            editable=False
        )
        file_button = Gtk.Button(
            icon_name="document-open-symbolic",
            tooltip_text="Select File"
        )
        file_button.connect("clicked", self.on_file_clicked)
        file_row = Gtk.Box(spacing=6)
        file_row.append(self.file_entry)
        file_row.append(file_button)
        content_box.append(file_row)

        content_box.append(Gtk.Separator())

        # Hash algorithms
        self.algorithms = [
            ("MD5", True),
            ("SHA1", True),
            ("SHA256", True),
            ("SHA384", True),
            ("SHA512", True),
            ("ADLER32", True),
            ("CRC32", True),
            ("RIPEMD160", hasattr(hashlib, 'ripemd160'))
        ]

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
            vt_button = Gtk.Button(
                icon_name="globe-symbolic",
                tooltip_text="Check VirusTotal",
                sensitive=False
            )
            vt_button.connect("clicked", self.on_vt_clicked, entry)
            grid.attach(vt_button, 3, row, 1, 1)
            self.hash_entries[algo] = (check, entry, vt_button)
            row += 1

        scrolled = Gtk.ScrolledWindow(vexpand=True)
        scrolled.set_child(grid)
        content_box.append(scrolled)

        self.generate_button = Gtk.Button(
            label="Generate Selected Hashes",
            sensitive=False,
            css_classes=["suggested-action"]
        )
        self.generate_button.connect("clicked", self.on_generate_clicked)
        content_box.append(self.generate_button)

        self.notebook.append_page(content_box, Gtk.Label(label="Calculate"))

    def create_hex_tab(self):
        hex_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12
        )

        # Toolbar
        toolbar = Gtk.Box(spacing=6)
        open_btn = Gtk.Button(label="Open", tooltip_text="Open File")
        open_btn.connect("clicked", self.on_hex_open_clicked)
        save_btn = Gtk.Button(label="Save", tooltip_text="Save File")
        save_btn.connect("clicked", self.on_hex_save_clicked)
        toolbar.append(open_btn)
        toolbar.append(save_btn)

        # Encoding dropdown
        encoding_store = Gtk.StringList.new(["utf-8", "utf-16"])
        self.encoding_combo = Gtk.DropDown(model=encoding_store)
        self.encoding_combo.set_selected(0)  # Select the first item by default
        self.encoding_combo.connect("notify::selected", self.on_encoding_changed)

        toolbar.append(self.encoding_combo)

        hex_box.append(toolbar)

        # Input view
        self.input_view = Gtk.TextView()
        self.input_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.input_view.set_monospace(True)
        input_scroll = Gtk.ScrolledWindow(vexpand=True)
        input_scroll.set_child(self.input_view)
        hex_box.append(input_scroll)

        # Hex view
        self.hex_view = Gtk.TextView()
        self.hex_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.hex_view.set_monospace(True)
        self.hex_view.set_editable(True)
        hex_scroll = Gtk.ScrolledWindow(vexpand=True)
        hex_scroll.set_child(self.hex_view)
        hex_box.append(hex_scroll)

        # Connect signals
        self.input_view.get_buffer().connect("changed", self.on_input_changed)
        self.hex_view.get_buffer().connect("changed", self.on_hex_changed)

        # Read Cursor Events
        self.input_view.get_buffer().connect("mark-set", self.on_cursor_moved)
        self.hex_view.get_buffer().connect("mark-set", self.on_cursor_moved)

        self.notebook.append_page(hex_box, Gtk.Label(label="Hex Editor"))

    def on_hex_open_clicked(self, button):
        def on_dialog_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.hex_file_path = file.get_path()
                    with open(self.hex_file_path, 'rb') as f:
                        content = f.read()
                        text = content.decode(self.encoding, errors='replace')
                        self.input_view.get_buffer().set_text(text)
            except Exception as e:
                self.show_error(f"Error opening file: {e}")

        dialog = Gtk.FileDialog(title="Open File")
        dialog.open(self, None, on_dialog_response)

    def on_hex_save_clicked(self, button):
        if not self.hex_file_path:
            def on_save_response(dialog, result):
                try:
                    file = dialog.save_finish(result)
                    if file:
                        self.hex_file_path = file.get_path()
                        self.save_hex_content()
                except Exception as e:
                    self.show_error(f"Error saving file: {e}")

            dialog = Gtk.FileDialog(title="Save File")
            dialog.save(self, None, on_save_response)
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
            self.show_error(f"Error saving file: {e}")

    def on_encoding_changed(self, combo, param):
        self.encoding = combo.get_model().get_string(combo.get_selected())
        if self.hex_file_path:
            try:
                content = self.text_view.get_buffer()
                text = content.decode(self.encoding, errors='replace')
                self.input_view.get_buffer().set_text(text)
            except Exception as e:
                self.show_error(f"Error applying encoding: {e}")

    def create_recovery_tab(self):
        recovery_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12
        )

        # Source file
        source_box = Gtk.Box(spacing=6)
        self.source_entry = Gtk.Entry(placeholder_text="Select source file...", editable=False)
        source_btn = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Select Source")
        source_btn.connect("clicked", self.on_source_clicked)
        source_box.append(self.source_entry)
        source_box.append(source_btn)
        recovery_box.append(source_box)

        # Target location
        target_box = Gtk.Box(spacing=6)
        self.target_entry = Gtk.Entry(placeholder_text="Select target location...", editable=False)
        target_btn = Gtk.Button(icon_name="folder-open-symbolic", tooltip_text="Select Target")
        target_btn.connect("clicked", self.on_target_clicked)
        target_box.append(self.target_entry)
        target_box.append(target_btn)
        recovery_box.append(target_box)

        # Run button
        self.run_button = Gtk.Button(
            label="Run Recovery",
            sensitive=False,
            css_classes=["suggested-action"]
        )
        self.run_button.connect("clicked", self.on_run_clicked)
        recovery_box.append(self.run_button)

        self.notebook.append_page(recovery_box, Gtk.Label(label="Recovery"))

    def on_source_clicked(self, button):
        def on_dialog_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.source_path = file.get_path()
                    self.source_entry.set_text(self.source_path)
                    self.update_run_button()
            except Exception as e:
                self.show_error(f"Error selecting source: {e}")

        dialog = Gtk.FileDialog(title="Select Source File")
        dialog.open(self, None, on_dialog_response)

    def on_target_clicked(self, button):
        def on_dialog_response(dialog, result):
            try:
                file = dialog.select_folder_finish(result)
                if file:
                    self.target_path = file.get_path()
                    self.target_entry.set_text(self.target_path)
                    self.update_run_button()
            except Exception as e:
                self.show_error(f"Error selecting target: {e}")

        dialog = Gtk.FileDialog(title="Select Target Folder")
        dialog.select_folder(self, None, on_dialog_response)

    def update_run_button(self):
        self.run_button.set_sensitive(hasattr(self, 'source_path') and hasattr(self, 'target_path'))

    def on_run_clicked(self, button):
        import subprocess
        try:
            # For now using echo as placeholder
            cmd = f"echo {self.source_path} {self.target_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                dialog = Adw.MessageDialog(
                    transient_for=self,
                    heading="Success",
                    body="Recovery completed successfully",
                    css_classes=["success"]
                )
                dialog.add_response("ok", "OK")
                dialog.present()
            else:
                self.show_error(f"Command failed: {result.stderr}")
        except Exception as e:
            self.show_error(f"Error running command: {e}")

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

    def update_hex_view(self):
        pass
        """Update the hex view based on the normal text."""
        # text = self.textbuffer1.get_text(self.textbuffer1.get_start_iter(), self.textbuffer1.get_end_iter(), True)
        # hex_text = ' '.join(f'{ord(c):02X}' for c in text)  # Convert each char to hex
        # self.textbuffer2.set_text(hex_text)

    def on_cursor_moved(self, textbuffer, iter, mark):
        """Synchronize cursor highlight between normal and hex view."""
        pass
        # textbuffer1 = self.input_view.get_buffer()
        # textbuffer2 = self.hex_view.get_buffer()
        # if mark.get_name() == "insert":  # Ensure we track the cursor (insertion point)
        #     position = iter.get_offset()  # Get cursor position in normal text
        #
        #     # Calculate the hex view position (each char is 2 hex digits + a space)
        #     hex_position = position * 3
        #
        #     # Apply highlight in hex view
        #     start_iter = self.textbuffer2.get_iter_at_offset(hex_position)
        #     end_iter = self.textbuffer2.get_iter_at_offset(hex_position + 2)
        #
        #     self.textbuffer2.remove_all_tags(self.textbuffer2.get_start_iter(), self.textbuffer2.get_end_iter())
        #     highlight_tag = self.textbuffer2.create_tag("highlight", background="yellow")
        #     self.textbuffer2.apply_tag(highlight_tag, start_iter, end_iter)

    def on_vt_clicked(self, button, entry):
        hash_value = entry.get_text().strip()
        if not hash_value:
            self.show_error("Generate the hash first.")
            return

        try:
            api_key = keyring.get_password("HashApp", "virustotal")
            if not api_key:
                self.show_error("Set the API key in Preferences.")
                return
        except Exception as e:
            self.show_error(f"Error fetching API key: {e}")
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
            self.show_error(f"Error: {str(error)}")
            return
        if response.status_code == 404:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading="No Match Found",
                body=f"Results for {hash_value} not found in VirusTotal Database"
            )
            dialog.add_response("ok", "OK")
            dialog.present()
            return
        if response.status_code != 200:
            self.show_error(f"API Error: {response.status_code}")
            return
        try:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            msg = (f"Malicious: {stats.get('malicious', 0)}\n"
                   f"Harmless: {stats.get('harmless', 0)}\n"
                   f"Undetected: {stats.get('undetected', 0)}")
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading=f"Results for {hash_value}",
                body=msg
            )
            dialog.add_response("ok", "OK")
            dialog.present()
        except Exception as e:
            self.show_error(f"Failed to parse response: {str(e)}")

    def on_file_clicked(self, button):
        def on_dialog_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.file_path = file.get_path()
                    self.file_entry.set_text(self.file_path)
                    self.generate_button.set_sensitive(True)
                    if self.notebook.get_current_page() == 1:  # Hex Editor tab
                        self.hex_file_path = self.file_path
                        with open(self.file_path, 'rb') as f:
                            content = f.read()
                            text = content.decode(self.encoding, errors='replace')
                            self.input_view.get_buffer().set_text(text)
            except Exception as e:
                self.show_error(f"Error selecting file: {e}")

        dialog = Gtk.FileDialog(title="Select a File")
        dialog.open(self, None, on_dialog_response)

    def on_generate_clicked(self, button):
        if not self.file_path or not os.path.isfile(self.file_path):
            self.show_error("Invalid file path")
            return
        try:
            for algo, (check, entry, vt_button) in self.hash_entries.items():
                entry.set_text("")
                vt_button.set_sensitive(False)
                if check.get_active():
                    hash_value = self.calculate_hash(algo)
                    entry.set_text(hash_value)
                    vt_button.set_sensitive(bool(hash_value))
        except Exception as e:
            self.show_error(f"Error generating hash: {str(e)}")

    def calculate_hash(self, algorithm):
        chunk_size = 8192
        with open(self.file_path, "rb") as f:
            if algorithm == "MD5":
                hash_obj = hashlib.md5()
            elif algorithm == "SHA1":
                hash_obj = hashlib.sha1()
            elif algorithm == "SHA256":
                hash_obj = hashlib.sha256()
            elif algorithm == "SHA384":
                hash_obj = hashlib.sha384()
            elif algorithm == "SHA512":
                hash_obj = hashlib.sha512()
            elif algorithm == "RIPEMD160":
                hash_obj = hashlib.new('ripemd160')
            elif algorithm == "ADLER32":
                value = 1
                while chunk := f.read(chunk_size):
                    value = zlib.adler32(chunk, value)
                return hex(value & 0xffffffff)[2:].zfill(8)
            elif algorithm == "CRC32":
                value = 0
                while chunk := f.read(chunk_size):
                    value = zlib.crc32(chunk, value)
                return hex(value & 0xffffffff)[2:].zfill(8)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            if algorithm not in ["ADLER32", "CRC32"]:
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)
                return hash_obj.hexdigest()

    def show_error(self, message):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Error",
            body=message
        )
        dialog.add_response("ok", "OK")
        dialog.present()


class HashHexApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.example.HashApp")
        self.win = None
        self.create_action('preferences', self.on_preferences)

    def do_activate(self):
        self.win = HashHexWindow(application=self)
        self.win.present()

    def create_action(self, name, callback):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)

    def on_preferences(self, action, param):
        dialog = PreferencesDialog(self.win)
        dialog.present()


if __name__ == "__main__":
    app = HashHexApp()
    app.run(None)
