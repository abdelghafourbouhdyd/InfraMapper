import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)
logging.basicConfig(level="INFO", format="%(message)s", datefmt="%H:%M:%S",
                    handlers=[RichHandler(console=console, show_path=False, markup=True)])
log = logging.getLogger("inframapper")
