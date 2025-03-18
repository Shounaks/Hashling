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

from gi.repository import GLib
from gi.repository import Secret
from gi.repository import Gtk, Adw, Gio

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

        # Create password entry
        self.api_entry = Gtk.PasswordEntry(
            show_peek_icon=True,
            placeholder_text="Enter VirusTotal API Key",
            hexpand=True
        )

        # Load existing key
        try:
            api_key = keyring.get_password("HashApp", "virustotal")
            self.api_entry.set_text(api_key or "")
        except Exception as e:
            print(f"Error loading key: {e}")

        # Save button
        save_btn = Gtk.Button(
            label="Save",
            css_classes=["suggested-action"],
            margin_top=12
        )
        save_btn.connect("clicked", self.on_save)

        # Layout
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12
        )
        header_bar = Adw.HeaderBar()
        box.append(header_bar)
        box.append(self.api_entry)
        box.append(save_btn)

        self.set_content(box)

    def on_save(self, button):
        api_key = self.api_entry.get_text()
        try:
            # Store in system keyring
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


class HashGeneratorWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_title("Hashling - File Hash Generator")
        self.set_default_size(600, 400)

        # Main container
        main_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            width_request=400
        )

        # Header bar
        header_bar = Adw.HeaderBar()
        main_box.append(header_bar)

        # Store API Key
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Settings")
        menu = Gio.Menu()
        menu.append("Preferences", "app.preferences")
        popover = Gtk.PopoverMenu()
        popover.set_menu_model(menu)
        menu_btn.set_popover(popover)

        # Add to header bar
        header_bar.pack_end(menu_btn)

        # Content container
        content_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
            spacing=12
        )

        # File selection row
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

        # Separator
        content_box.append(Gtk.Separator())

        # Hash algorithms grid
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

        # Create grid layout
        grid = Gtk.Grid(
            column_spacing=12,
            row_spacing=6,
            margin_top=6,
            margin_bottom=6
        )

        # Column headers
        header_check = Gtk.Label(xalign=0)
        header_algo = Gtk.Label(label="Algorithm", xalign=0)
        header_hash = Gtk.Label(label="Hash Value", xalign=0)
        header_action = Gtk.Label(label="VirusTotal", xalign=0)

        grid.attach(header_check, 0, 0, 1, 1)
        grid.attach(header_algo, 1, 0, 1, 1)
        grid.attach(header_hash, 2, 0, 1, 1)
        grid.attach(header_action, 3, 0, 1, 1)

        # Header separator
        grid.attach(Gtk.Separator(), 0, 1, 3, 1)

        self.hash_entries = {}
        row = 2  # Start after headers

        for algo, available in self.algorithms:
            if not available:
                continue

            # Checkbox
            check = Gtk.CheckButton(active=True)
            check.set_margin_end(20)
            grid.attach(check, 0, row, 1, 1)

            # Algorithm label
            label = Gtk.Label(label=algo, xalign=0)
            label.set_size_request(120, -1)
            grid.attach(label, 1, row, 1, 1)

            # Hash entry
            entry = Gtk.Entry(
                editable=False,
                can_focus=False,
                hexpand=True
            )
            grid.attach(entry, 2, row, 1, 1)

            # VT Check button
            vt_button = Gtk.Button(
                icon_name="globe-symbolic",
                tooltip_text="Check VirusTotal",
                css_classes=["warning"],
                sensitive=False
            )
            vt_button.connect("clicked", self.on_vt_clicked, entry)
            grid.attach(vt_button, 3, row, 1, 1)  # Added to column 3

            self.hash_entries[algo] = (check, entry, vt_button)
            row += 1

        # Scrolled window for grid
        scrolled = Gtk.ScrolledWindow(
            hexpand=True,
            vexpand=True,
            min_content_height=200
        )
        scrolled.set_child(grid)
        content_box.append(scrolled)

        # Generate button
        self.generate_button = Gtk.Button(
            label="Generate Selected Hashes",
            sensitive=False,
            css_classes=["suggested-action"]
        )
        self.generate_button.connect("clicked", self.on_generate_clicked)
        content_box.append(self.generate_button)

        main_box.append(content_box)
        self.set_content(main_box)
        self.file_path = None

    def on_vt_clicked(self, button, entry):
        hash_value = entry.get_text().strip()
        if not hash_value:
            self.show_error("Generate the hash first.")
            return

        try:
            api_key = keyring.get_password("HashApp", "virustotal")
        except Exception as e:
            self.show_error(f"Error fetching API key: {e}")
            return

        if not api_key:
            self.show_error("Set the API key in Preferences.")
            return

        # Show loading dialog
        # self.loading_dialog = Adw.MessageDialog(
        #    transient_for=self,
        #    heading="Checking VirusTotal...",
        #    body=f"Checking {hash_value}"
        # )
        # spinner = Gtk.Spinner()
        # spinner.start()
        # self.loading_dialog.get_message_area().append(spinner)
        # self.loading_dialog.present()

        # Disable button during request
        button.set_sensitive(False)

        # Start API call in a thread
        def vt_thread():
            try:
                url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
                # print(url)
                headers = {"accept": "application/json", "x-apikey": api_key}
                # print("headers", headers)
                response = requests.get(url, headers=headers)
                GLib.idle_add(self.handle_vt_response, response, None, hash_value, button)
            except Exception as e:
                GLib.idle_add(self.handle_vt_response, None, e, hash_value, button)

        threading.Thread(target=vt_thread, daemon=True).start()

    def handle_vt_response(self, response, error, hash_value, button):
        # Dismiss loading dialog
        # if self.loading_dialog:
        #    self.loading_dialog.dismiss()

        button.set_sensitive(True)

        if error:
            self.show_error(f"Error: {str(error)}")
            return

        if response.status_code == 404:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading=f"No Match Found",
                body=f"Results for {hash_value} is not present in VirusTotal Database"
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
                css_classes=["destructive-action"],
                transient_for=self,
                heading=f"Results for {hash_value}",
                body=msg
            )
            dialog.add_response("ok", "OK")
            dialog.present()
        except Exception as e:
            self.show_error(f"Failed to parse response: {str(e)}")

    def create_action(self, name, callback):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)

    def on_preferences(self, action, param):
        dialog = PreferencesDialog(self)
        dialog.present()

    def on_file_clicked(self, button):
        def on_dialog_response(dialog, result):
            try:
                file = dialog.open_finish(result)
                if file:
                    self.file_path = file.get_path()
                    self.file_entry.set_text(self.file_path)
                    self.generate_button.set_sensitive(True)
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
                entry.set_text("")  # Clear previous results
                vt_button.set_sensitive(False)  # Disable existing state
                if check.get_active():
                    hash_value = self.calculate_hash(algo)
                    entry.set_text(hash_value)
                    vt_button.set_sensitive(bool(hash_value))  # Enable only if hash exists
                else:
                    vt_button.set_sensitive(False)
        except Exception as e:
            self.show_error(f"Error generating hash: {str(e)}")

    def calculate_hash(self, algorithm):
        """Calculate hash using chunked reading for all algorithms"""
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
                value = 1  # Adler32 initial value
                while chunk := f.read(chunk_size):
                    value = zlib.adler32(chunk, value)
                return hex(value & 0xffffffff)[2:].zfill(8)
            elif algorithm == "CRC32":
                value = 0  # CRC32 initial value
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


class HashApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.example.HashApp")
        action = Gio.SimpleAction.new('preferences', None)
        action.connect('activate', self.on_preferences)
        self.add_action(action)
        # self.add_action(Gio.SimpleAction.new('preferences', None).connect('activate', self.on_preferences))
        # self.create_action('preferences', self.on_preferences)

    def do_activate(self):
        self.win = HashGeneratorWindow(application=self)
        self.win.present()

    def on_preferences(self, action, param):
        dialog = PreferencesDialog(self.win)
        dialog.present()


if __name__ == "__main__":
    app = HashApp()
    app.run(None)
