import sys
import os
import gi
import threading
import subprocess
import queue
import time
from pathlib import Path

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib

class VolatilityApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id='com.example.VolatilityAnalyzer')
        self.file_path = None
        self.output_dir = None
        self.progress = 0
        self.task_queue = queue.Queue()
        self.running = False
        self.volatility_path = None
        self.selected_plugins = []
        self.extra_args = ""  # Store extra arguments for Volatility commands
        self.window = None

    def check_volatility(self):
        app_dir = Path(__file__).parent
        volatility_dir = app_dir / 'volatility3'
        volatility_file = volatility_dir / 'vol.py'
        if volatility_dir.exists() and volatility_file.exists():
            self.volatility_path = str(volatility_file)
            return True
        return False

    def get_volatility_path(self):
        if self.volatility_path:
            return self.volatility_path
        return 'volatility'

    def show_volatility_dialog(self):
        dialog = Gtk.Dialog(
            title="Volatility 3 Not Found",
            transient_for=None,
            modal=True
        )
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.add_button("Download Volatility 3", Gtk.ResponseType.OK)
        ok_button = dialog.get_widget_for_response(Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        content_area = dialog.get_content_area()
        content_area.set_margin_top(12)
        content_area.set_margin_bottom(12)
        content_area.set_margin_start(12)
        content_area.set_margin_end(12)

        message = Gtk.Label(
            label="Volatility 3 is not found in the application directory.\n"
                  "Would you like to download it from GitHub?"
        )
        message.set_wrap(True)
        content_area.append(message)

        dialog.connect("response", self.on_volatility_dialog_response)
        if self.window:
            dialog.set_transient_for(self.window)
        dialog.show()

    def on_volatility_dialog_response(self, dialog, response):
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            threading.Thread(target=self.clone_volatility, daemon=True).start()
        else:
            self.quit()

    def clone_volatility(self):
        try:
            app_dir = Path(__file__).parent
            cmd = ['git', 'clone', 'https://github.com/volatilityfoundation/volatility3.git']
            subprocess.run(
                cmd,
                cwd=str(app_dir),
                check=True,
                capture_output=True,
                text=True
            )
            # After cloning, recheck if Volatility 3 is available
            if self.check_volatility():
                # Update status and present the main window
                GLib.idle_add(self.status_label.set_label, "Volatility 3 downloaded successfully")
                GLib.idle_add(self.window.present)
            else:
                # If vol.py is still missing, inform the user and quit
                GLib.idle_add(
                    self.status_label.set_label,
                    "Failed to locate vol.py after cloning Volatility 3"
                )
                GLib.idle_add(self.quit)
        except subprocess.CalledProcessError as e:
            GLib.idle_add(
                self.status_label.set_label,
                f"Error downloading Volatility 3: {e.stderr}"
            )
            GLib.idle_add(self.quit)

    def do_activate(self):
        self.window = MainWindow(application=self)
        self.status_label = self.window.status_label
        if not self.check_volatility():
            self.show_volatility_dialog()
        else:
            self.volatility_path = self.get_volatility_path()
            self.window.present()

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = self.get_application()

        # Set up window
        self.set_title("Volatility Memory Analyzer")
        self.set_default_size(700, 500)

        # Main container
        main_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            width_request=400
        )

        # Header bar
        header_bar = Adw.HeaderBar()
        main_box.append(header_bar)

        # Content layout (with margins)
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content_box.set_margin_top(16)
        content_box.set_margin_bottom(16)
        content_box.set_margin_start(16)
        content_box.set_margin_end(16)

        # Welcome message
        welcome_label = Gtk.Label(label="Volatility Memory Analyzer")
        welcome_label.add_css_class("title-1")
        content_box.append(welcome_label)

        # File selection
        file_frame = Adw.PreferencesGroup(title="Memory Dump File")
        file_box = Gtk.Box(spacing=12, margin_top=8, margin_bottom=8)
        self.file_label = Gtk.Label(label="No file selected", hexpand=True, xalign=0)
        file_button = Gtk.Button(label="Select .vmem File")
        file_button.set_icon_name("document-open-symbolic")
        file_button.set_tooltip_text("Choose a memory dump file (.vmem)")
        file_button.connect("clicked", self.on_file_button_clicked)
        file_box.append(self.file_label)
        file_box.append(file_button)
        file_frame.add(file_box)
        content_box.append(file_frame)

        # Output directory selection
        output_frame = Adw.PreferencesGroup(title="Output Directory")
        output_box = Gtk.Box(spacing=12, margin_top=8, margin_bottom=8)
        self.output_label = Gtk.Label(label="No output directory selected", hexpand=True, xalign=0)
        output_button = Gtk.Button(label="Select Directory")
        output_button.set_icon_name("folder-open-symbolic")
        output_button.set_tooltip_text("Choose a directory to save output files")
        output_button.connect("clicked", self.on_output_button_clicked)
        output_box.append(self.output_label)
        output_box.append(output_button)
        output_frame.add(output_box)
        content_box.append(output_frame)

        # Plugin selection
        plugin_frame = Adw.PreferencesGroup(title="Volatility Plugins")
        plugin_box = Gtk.Box(spacing=12, margin_top=8, margin_bottom=8)
        self.plugin_label = Gtk.Label(label="No plugins selected", hexpand=True, xalign=0)
        plugin_button = Gtk.Button(label="Select Plugins")
        plugin_button.set_icon_name("list-add-symbolic")
        plugin_button.set_tooltip_text("Choose plugins to run")
        plugin_button.connect("clicked", self.on_plugin_button_clicked)
        plugin_box.append(self.plugin_label)
        plugin_box.append(plugin_button)
        plugin_frame.add(plugin_box)
        content_box.append(plugin_frame)

        # Extra arguments input
        args_frame = Adw.PreferencesGroup(title="Extra Arguments (Optional)")
        args_box = Gtk.Box(spacing=12, margin_top=8, margin_bottom=8)
        self.extra_args_entry = Gtk.Entry(
            placeholder_text="e.g., --pid 123 --verbose",
            hexpand=True
        )
        self.extra_args_entry.set_tooltip_text("Enter additional arguments for Volatility commands")
        args_box.append(self.extra_args_entry)
        args_frame.add(args_box)
        content_box.append(args_frame)

        # Analyze button
        self.analyze_button = Gtk.Button(label="Analyze", halign=Gtk.Align.CENTER)
        self.analyze_button.add_css_class("suggested-action")
        self.analyze_button.set_tooltip_text("Run selected plugins on the memory dump")
        self.analyze_button.set_sensitive(False)
        self.analyze_button.connect("clicked", self.on_analyze_clicked)
        content_box.append(self.analyze_button)

        # Progress and status
        status_frame = Adw.PreferencesGroup(title="Analysis Status")
        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_bottom=8)
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_text("0%")
        self.status_label = Gtk.Label(label="Ready to analyze")
        self.spinner = Gtk.Spinner()
        self.spinner.set_visible(False)
        status_box.append(self.progress_bar)
        status_box.append(self.status_label)
        status_box.append(self.spinner)
        status_frame.add(status_box)
        content_box.append(status_frame)

        # Available plugins (sorted)
        self.available_plugins = sorted([
            'banners.Banners', 'configwriter.ConfigWriter', 'frameworkinfo.FrameworkInfo',
            'isfinfo.IsfInfo', 'layerwriter.LayerWriter', 'linux.bash.Bash',
            'linux.boottime.Boottime', 'linux.capabilities.Capabilities',
            'linux.check_afinfo.Check_afinfo', 'linux.check_creds.Check_creds',
            'linux.check_idt.Check_idt', 'linux.check_modules.Check_modules',
            'linux.check_syscall.Check_syscall', 'linux.ebpf.EBPF', 'linux.elfs.Elfs',
            'linux.envars.Envars', 'linux.graphics.fbdev.Fbdev', 'linux.hidden_modules.Hidden_modules',
            'linux.iomem.IOMem', 'linux.ip.Addr', 'linux.ip.Link', 'linux.kallsyms.Kallsyms',
            'linux.keyboard_notifiers.Keyboard_notifiers', 'linux.kmsg.Kmsg',
            'linux.kthreads.Kthreads', 'linux.library_list.LibraryList', 'linux.lsmod.Lsmod',
            'linux.lsof.Lsof', 'linux.malfind.Malfind', 'linux.module_extract.ModuleExtract',
            'linux.modxview.Modxview', 'linux.mountinfo.MountInfo', 'linux.netfilter.Netfilter',
            'linux.pagecache.Files', 'linux.pagecache.InodePages', 'linux.pagecache.RecoverFs',
            'linux.pidhashtable.PIDHashTable', 'linux.proc.Maps', 'linux.psaux.PsAux',
            'linux.pscallstack.PsCallStack', 'linux.pslist.PsList', 'linux.psscan.PsScan',
            'linux.pstree.PsTree', 'linux.ptrace.Ptrace', 'linux.sockstat.Sockstat',
            'linux.tracing.ftrace.CheckFtrace', 'linux.tracing.perf_events.PerfEvents',
            'linux.tracing.tracepoints.CheckTracepoints', 'linux.tty_check.tty_check',
            'linux.vmaregexscan.VmaRegExScan', 'linux.vmcoreinfo.VMCoreInfo',
            'mac.bash.Bash', 'mac.check_syscall.Check_syscall', 'mac.check_sysctl.Check_sysctl',
            'mac.check_trap_table.Check_trap_table', 'mac.dmesg.Dmesg', 'mac.ifconfig.Ifconfig',
            'mac.kauth_listeners.Kauth_listeners', 'mac.kauth_scopes.Kauth_scopes',
            'mac.kevents.Kevents', 'mac.list_files.List_Files', 'mac.lsmod.Lsmod',
            'mac.lsof.Lsof', 'mac.malfind.Malfind', 'mac.mount.Mount', 'mac.netstat.Netstat',
            'mac.proc_maps.Maps', 'mac.psaux.Psaux', 'mac.pslist.PsList', 'mac.pstree.PsTree',
            'mac.socket_filters.Socket_filters', 'mac.timers.Timers', 'mac.trustedbsd.Trustedbsd',
            'mac.vfsevents.VFSevents', 'regexscan.RegExScan', 'timeliner.Timeliner',
            'vmscan.Vmscan', 'windows.amcache.Amcache', 'windows.bigpools.BigPools',
            'windows.callbacks.Callbacks', 'windows.cmdline.CmdLine', 'windows.crashinfo.Crashinfo',
            'windows.deskscan.DeskScan', 'windows.desktops.Desktops', 'windows.devicetree.DeviceTree',
            'windows.dlllist.DllList', 'windows.driverirp.DriverIrp', 'windows.drivermodule.DriverModule',
            'windows.driverscan.DriverScan', 'windows.dumpfiles.DumpFiles', 'windows.envars.Envars',
            'windows.filescan.FileScan', 'windows.getservicesids.GetServiceSIDs',
            'windows.getsids.GetSIDs', 'windows.handles.Handles', 'windows.hollowprocesses.HollowProcesses',
            'windows.info.Info', 'windows.joblinks.JobLinks', 'windows.kpcrs.KPCRs',
            'windows.ldrmodules.LdrModules', 'windows.malfind.Malfind', 'windows.mbrscan.MBRScan',
            'windows.memmap.Memmap', 'windows.modscan.ModScan', 'windows.modules.Modules',
            'windows.mutantscan.MutantScan', 'windows.pedump.PEDump', 'windows.poolscanner.PoolScanner',
            'windows.privileges.Privs', 'windows.processghosting.ProcessGhosting',
            'windows.pslist.PsList', 'windows.psscan.PsScan', 'windows.pstree.PsTree',
            'windows.registry.amcache.Amcache', 'windows.registry.certificates.Certificates',
            'windows.registry.getcellroutine.GetCellRoutine', 'windows.registry.hivelist.HiveList',
            'windows.registry.hivescan.HiveScan', 'windows.registry.printkey.PrintKey',
            'windows.registry.scheduled_tasks.ScheduledTasks', 'windows.registry.userassist.UserAssist',
            'windows.scheduled_tasks.ScheduledTasks', 'windows.sessions.Sessions',
            'windows.shimcachemem.ShimcacheMem', 'windows.ssdt.SSDT', 'windows.statistics.Statistics',
            'windows.strings.Strings', 'windows.svcdiff.SvcDiff', 'windows.svclist.SvcList',
            'windows.svcscan.SvcScan', 'windows.symlinkscan.SymlinkScan', 'windows.timers.Timers',
            'windows.truecrypt.Passphrase', 'windows.unloadedmodules.UnloadedModules',
            'windows.vadinfo.VadInfo', 'windows.vadregexscan.VadRegExScan', 'windows.vadwalk.VadWalk',
            'windows.virtmap.VirtMap', 'windows.windows.Windows', 'windows.windowstations.WindowStations'
        ])
        main_box.append(content_box)
        self.set_content(main_box)

    def on_file_button_clicked(self, button):
        dialog = Gtk.FileChooserDialog(
            title="Select Memory Dump (.vmem)",
            action=Gtk.FileChooserAction.OPEN,
            transient_for=self
        )
        filter_vmem = Gtk.FileFilter()
        filter_vmem.set_name("VMEM files")
        filter_vmem.add_pattern("*.vmem")
        dialog.add_filter(filter_vmem)
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Open", Gtk.ResponseType.ACCEPT)
        dialog.connect("response", self.on_file_dialog_response)
        dialog.show()

    def on_file_dialog_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            self.app.file_path = dialog.get_file().get_path()
            self.file_label.set_label(os.path.basename(self.app.file_path))
            self.check_analyze_button()
        dialog.destroy()

    def on_output_button_clicked(self, button):
        dialog = Gtk.FileChooserDialog(
            title="Select Output Directory",
            action=Gtk.FileChooserAction.SELECT_FOLDER,
            transient_for=self
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Select", Gtk.ResponseType.ACCEPT)
        dialog.connect("response", self.on_output_dialog_response)
        dialog.show()

    def on_output_dialog_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            self.app.output_dir = dialog.get_file().get_path()
            self.output_label.set_label(os.path.basename(self.app.output_dir))
            self.check_analyze_button()
        dialog.destroy()

    def on_plugin_button_clicked(self, button):
        dialog = Gtk.Dialog(
            title="Select Plugins",
            transient_for=self,
            modal=True,
            default_width=500,
            default_height=600
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_OK", Gtk.ResponseType.OK)
        ok_button = dialog.get_widget_for_response(Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        content_area = dialog.get_content_area()
        content_area.set_margin_top(12)
        content_area.set_margin_bottom(12)
        content_area.set_margin_start(12)
        content_area.set_margin_end(12)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_area.append(content_box)

        search_entry = Gtk.SearchEntry(placeholder_text="Search plugins...")
        search_entry.set_hexpand(True)
        content_box.append(search_entry)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.MULTIPLE)
        list_box.set_show_separators(True)
        scrolled.set_child(list_box)
        content_box.append(scrolled)

        self.plugin_rows = {}
        for plugin in self.available_plugins:
            row = Gtk.ListBoxRow()
            label = Gtk.Label(label=plugin, xalign=0)
            row.set_child(label)
            list_box.append(row)
            self.plugin_rows[plugin] = row

        def on_search_changed(entry):
            search_text = entry.get_text().lower()
            for plugin, row in self.plugin_rows.items():
                row.set_visible(search_text in plugin.lower())

        search_entry.connect("search-changed", on_search_changed)

        dialog.connect("response", self.on_plugin_dialog_response, list_box)
        dialog.show()

    def on_plugin_dialog_response(self, dialog, response, list_box):
        if response == Gtk.ResponseType.OK:
            self.app.selected_plugins = [row.get_child().get_label() for row in list_box.get_selected_rows()]
            self.plugin_label.set_label(f"{len(self.app.selected_plugins)} plugins selected")
            self.check_analyze_button()
        dialog.destroy()

    def check_analyze_button(self):
        self.analyze_button.set_sensitive(
            self.app.file_path is not None and
            self.app.output_dir is not None and
            len(self.app.selected_plugins) > 0
        )

    def on_analyze_clicked(self, button):
        self.analyze_button.set_sensitive(False)
        self.status_label.set_label("Running plugins...")
        self.progress_bar.set_fraction(0)
        self.spinner.set_visible(True)
        self.spinner.start()
        self.app.running = True
        # Capture extra arguments from the text box
        self.app.extra_args = self.extra_args_entry.get_text().strip()

        Path(self.app.output_dir).mkdir(parents=True, exist_ok=True)
        threading.Thread(target=self.start_plugin_threads, daemon=True).start()

    def start_plugin_threads(self):
        self.app.progress = 0
        self.app.task_queue = queue.Queue()

        for plugin in self.app.selected_plugins:
            self.app.task_queue.put(plugin)

        for _ in range(min(3, len(self.app.selected_plugins))):
            threading.Thread(target=self.worker, daemon=True).start()

        GLib.timeout_add(100, self.update_progress)

    def worker(self):
        while not self.app.task_queue.empty():
            plugin = self.app.task_queue.get()
            output_file = os.path.join(
                self.app.output_dir,
                f"{plugin.split('.')[-1].lower()}.txt"
            )

            try:
                cmd = [
                    'python3', self.app.volatility_path,
                    '-f', self.app.file_path,
                    plugin,
                ]
                # Add extra arguments if provided
                if self.app.extra_args:
                    extra_args = self.app.extra_args.split()
                    cmd.extend(extra_args)

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )

                with open(output_file, 'w') as f:
                    f.write(f"Volatility {plugin} Output\n")
                    f.write("=" * 50 + "\n")
                    f.write(result.stdout)

            except subprocess.CalledProcessError as e:
                with open(output_file, 'w') as f:
                    f.write(f"Error running {plugin}:\n")
                    f.write("=" * 50 + "\n")
                    f.write(e.stderr)

            except Exception as e:
                with open(output_file, 'w') as f:
                    f.write(f"Unexpected error running {plugin}:\n")
                    f.write("=" * 50 + "\n")
                    f.write(str(e))

            finally:
                with threading.Lock():
                    self.app.progress += 1 / len(self.app.selected_plugins)
                self.app.task_queue.task_done()

    def update_progress(self):
        if not self.app.running:
            return False

        fraction = min(self.app.progress, 1.0)
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"{int(fraction * 100)}%")

        if fraction >= 1.0:
            self.status_label.set_label("Analysis complete! Results saved in output directory.")
            self.analyze_button.set_sensitive(True)
            self.spinner.set_visible(False)
            self.spinner.stop()
            self.app.running = False
            return False

        return True

def main():
    app = VolatilityApp()
    app.run(sys.argv)

if __name__ == '__main__':
    main()
