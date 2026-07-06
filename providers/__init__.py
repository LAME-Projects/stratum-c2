"""
Shared UI helpers for all provider wizards.
Imported by each providers/<name>/wizard.py during interactive deployment.
"""
import re
from prompt_toolkit import prompt as _pt_prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.styles import Style


class WizardError(Exception):
    """Raised by err() to abort a wizard step cleanly (replaces sys.exit)."""

STYLE = Style.from_dict({
    "ok":     "#00cc00 bold",
    "err":    "#cc0000 bold",
    "warn":   "#cccc00 bold",
    "info":   "#00cccc",
    "step":   "#cc00cc bold",
    "banner": "#cc0000 bold",
    "dim":    "#444444",
    "cyan":   "#00cccc bold",
    "green":  "#00cc00",
    "yellow": "#cccc00",
    "bold":   "bold",
})

def _p(pairs):
    print_formatted_text(FormattedText(pairs), style=STYLE)

def ok(msg):    _p([("class:ok",   f"  [OK]  {msg}")])
def err(msg):   _p([("class:err",  f"  [!!]  {msg}")]); raise WizardError(msg)
def warn(msg):  _p([("class:warn", f"  [!]   {msg}")])
def info(msg):  _p([("class:info", f"        {msg}")])
def step(n, t): _p([("class:step", f"\n=== STEP {n}: {t} ===")])
def sep():      _p([("class:dim",  "  " + "-" * 68)])

def ask(prompt_text: str, default: str = "", choices: tuple = ()) -> str:
    hint       = f" [{default}]" if default else ""
    completer  = WordCompleter(list(choices), sentence=True) if choices else None
    val        = _pt_prompt(f"  {prompt_text}{hint}: ", completer=completer).strip()
    return val if val else default

def ask_int(prompt_text: str, default: int, lo: int, hi: int) -> int:
    while True:
        raw = ask(prompt_text, str(default))
        if re.match(r"^\d+$", raw):
            v = int(raw)
            if lo <= v <= hi:
                return v
        _p([("class:warn", f"  Must be an integer between {lo} and {hi}")])

def ask_yn(prompt_text: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw  = _pt_prompt(f"  {prompt_text} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw.startswith("y")
