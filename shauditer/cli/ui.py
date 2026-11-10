"""Terminal UI helpers for SHAuditer."""

PRODUCT_NAME = "SHAuditer"
FULL_NAME = "Smart Hybrid Automated Security Auditor"
DEVELOPER = "Street_Hackers"
QUOTE = '"With great power comes great responsibility."'
VERSION = "1.1.7"
PLATFORM = "Linux"

_BOX_WIDTH = 78
_LOGO = (
    "███████╗██╗  ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗███████╗██████╗",
    "██╔════╝██║  ██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗",
    "███████╗███████║███████║██║   ██║██║  ██║██║   ██║   █████╗  ██████╔╝",
    "╚════██║██╔══██║██╔══██║██║   ██║██║  ██║██║   ██║   ██╔══╝  ██╔══██╗",
    "███████║██║  ██║██║  ██║╚██████╔╝██████╔╝██║   ██║   ███████╗██║  ██║",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
)


def _box_line(text: str = "") -> str:
    return f"║{text:^{_BOX_WIDTH}}║"


def build_banner() -> str:
    lines = ["╔" + "═" * _BOX_WIDTH + "╗", _box_line()]
    lines.extend(_box_line(line) for line in _LOGO)
    lines.extend([
        _box_line(),
        _box_line(PRODUCT_NAME),
        _box_line(FULL_NAME),
        _box_line(),
        _box_line("Discover. Validate. Document."),
        _box_line(QUOTE),
        _box_line(),
        _box_line(f"Developed by {DEVELOPER}"),
        "╚" + "═" * _BOX_WIDTH + "╝",
        f"Version: {VERSION}",
        f"Platform: {PLATFORM}",
    ])
    return "\n".join(lines)


BANNER = build_banner()


def print_banner() -> None:
    print(BANNER)
