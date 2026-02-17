"""
UI Utilities for WPAxFuzz - Rich-based display functions
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Global console instance
console = Console()


def print_menu(title, options):
    """
    Display a numbered menu in a panel.
    
    Args:
        title: Menu title
        options: List of option strings (without numbers)
    """
    content = "\n".join(f"{i+1}) {opt}" for i, opt in enumerate(options))
    panel = Panel(
        content,
        title=title,
        border_style="blue",
        padding=(1, 2)
    )
    console.print(panel)


def get_input(prompt_text):
    """
    Display a styled input prompt.
    
    Args:
        prompt_text: Text to show before input
    
    Returns:
        User input string
    """
    console.print(f"[bold cyan]{prompt_text}[/bold cyan]", end="")
    return input()


def print_success(message):
    """Display a success message in green."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_error(message):
    """Display an error message in red."""
    console.print(f"[bold red]✗[/bold red] {message}")


def print_warning(message):
    """Display a warning message in yellow."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def print_info(message):
    """Display an info message in cyan."""
    console.print(f"[bold cyan]ℹ[/bold cyan] {message}")


if __name__ == "__main__":
    # Quick test
    print_menu("Test Menu", ["Option A", "Option B", "Option C"])
    print_success("Success!")
    print_error("Error!")
    print_warning("Warning!")
    print_info("Info!")
