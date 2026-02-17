"""
Live dashboard for WPAxFuzz - Real-time fuzzing status display
"""
import time
import threading
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.text import Text
from rich import box
import settings

console = Console()


class DashboardStats:
    """Global stats container for dashboard tracking"""
    def __init__(self):
        self.frames_sent = 0
        self.errors = 0
        self.current_mode = ""
        self.current_frame_type = ""
        self.interface = ""
        self.start_time = None
        self.last_error = ""
        self._lock = threading.Lock()
    
    def increment_frames(self, count=1):
        """Increment frames sent counter"""
        with self._lock:
            self.frames_sent += count
    
    def increment_errors(self, error_msg=""):
        """Increment error counter and store last error"""
        with self._lock:
            self.errors += 1
            if error_msg:
                self.last_error = error_msg[:100]  # Truncate long messages
    
    def set_mode(self, mode):
        """Set current fuzzing mode"""
        with self._lock:
            self.current_mode = mode
    
    def set_frame_type(self, frame_type):
        """Set current frame type being fuzzed"""
        with self._lock:
            self.current_frame_type = frame_type
    
    def set_interface(self, interface):
        """Set network interface"""
        with self._lock:
            self.interface = interface
    
    def start_timer(self):
        """Start the runtime timer"""
        with self._lock:
            if self.start_time is None:
                self.start_time = time.time()
    
    def get_runtime(self):
        """Get formatted runtime string"""
        with self._lock:
            if self.start_time is None:
                return "00:00:00"
            elapsed = time.time() - self.start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def reset(self):
        """Reset all stats"""
        with self._lock:
            self.frames_sent = 0
            self.errors = 0
            self.current_mode = ""
            self.current_frame_type = ""
            self.interface = ""
            self.start_time = None
            self.last_error = ""


# Global stats instance
dashboard_stats = DashboardStats()


class FuzzingDashboard:
    """Live dashboard for displaying real-time fuzzing status"""
    
    def __init__(self):
        self.stats = dashboard_stats
        self.running = False
        self.layout = Layout()
        self._setup_layout()
    
    def _setup_layout(self):
        """Setup the dashboard layout"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        self.layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
    
    def _generate_header(self):
        """Generate header panel"""
        title = Text("WPAxFuzz Live Dashboard", style="bold cyan", justify="center")
        return Panel(title, box=box.DOUBLE_EDGE)
    
    def _generate_status_panel(self):
        """Generate connection status panel"""
        conn_status = "[green]Connected[/green]" if settings.is_alive else "[red]Disconnected[/red]"
        conn_loss = "[red]YES[/red]" if settings.conn_loss else "[green]NO[/green]"
        
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Connection Status", conn_status)
        table.add_row("Connection Loss", conn_loss)
        table.add_row("Runtime", self.stats.get_runtime())
        table.add_row("Interface", self.stats.interface or "N/A")
        
        return Panel(table, title="[bold yellow]Connection Status", box=box.ROUNDED)
    
    def _generate_stats_panel(self):
        """Generate fuzzing stats panel"""
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Frames Sent", f"[green]{self.stats.frames_sent:,}[/green]")
        table.add_row("Errors", f"[red]{self.stats.errors}[/red]")
        table.add_row("Current Mode", f"[blue]{self.stats.current_mode or 'N/A'}[/blue]")
        table.add_row("Frame Type", f"[magenta]{self.stats.current_frame_type or 'N/A'}[/magenta]")
        
        return Panel(table, title="[bold yellow]Fuzzing Stats", box=box.ROUNDED)
    
    def _generate_error_panel(self):
        """Generate last error panel"""
        if self.stats.last_error:
            error_text = Text(self.stats.last_error, style="red")
        else:
            error_text = Text("No errors yet", style="dim")
        
        return Panel(error_text, title="[bold red]Last Error", box=box.ROUNDED)
    
    def _generate_footer(self):
        """Generate footer panel"""
        footer_text = Text("Press Ctrl+C twice to stop fuzzing and dashboard", 
                          style="dim", justify="center")
        return Panel(footer_text, box=box.SIMPLE)
    
    def generate_display(self):
        """Generate the complete dashboard display"""
        self.layout["header"].update(self._generate_header())
        self.layout["left"].update(self._generate_status_panel())
        self.layout["right"].update(self._generate_stats_panel())
        self.layout["footer"].update(self._generate_footer())
        return self.layout
    
    def run(self, refresh_per_second=4):
        """Run the live dashboard"""
        self.running = True
        self.stats.start_timer()
        
        try:
            with Live(self.generate_display(), refresh_per_second=refresh_per_second) as live:
                while self.running:
                    live.update(self.generate_display())
                    time.sleep(1 / refresh_per_second)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the dashboard"""
        self.running = False
    
    def update_stats(self, **kwargs):
        """Update dashboard stats"""
        if 'frames_sent' in kwargs:
            self.stats.increment_frames(kwargs['frames_sent'])
        if 'error' in kwargs:
            self.stats.increment_errors(kwargs['error'])
        if 'mode' in kwargs:
            self.stats.set_mode(kwargs['mode'])
        if 'frame_type' in kwargs:
            self.stats.set_frame_type(kwargs['frame_type'])
        if 'interface' in kwargs:
            self.stats.set_interface(kwargs['interface'])


def start_dashboard():
    """Start dashboard in a separate thread"""
    dashboard = FuzzingDashboard()
    dashboard_thread = threading.Thread(target=dashboard.run, daemon=True)
    dashboard_thread.start()
    return dashboard


def update_dashboard_frames(count=1):
    """Update frames sent count from fuzzing code"""
    dashboard_stats.increment_frames(count)


def update_dashboard_error(error_msg=""):
    """Update error count and message from fuzzing code"""
    dashboard_stats.increment_errors(error_msg)


def set_dashboard_context(mode="", frame_type="", interface=""):
    """Set the current fuzzing context for dashboard"""
    if mode:
        dashboard_stats.set_mode(mode)
    if frame_type:
        dashboard_stats.set_frame_type(frame_type)
    if interface:
        dashboard_stats.set_interface(interface)
    dashboard_stats.start_timer()


def reset_dashboard():
    """Reset dashboard stats"""
    dashboard_stats.reset()
