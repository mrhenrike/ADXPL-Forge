"""ADXPL-Forge interactive REPL interpreter."""

import atexit
import importlib
import os
import readline
import shlex
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from adxpl import __product__, __version__
from adxpl.core.dispatcher import _MODULE_MAP


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = rf"""
    ___    ____  _  __ ____  __
   /   |  / __ \| |/ // __ \/ /
  / /| | / / / /|   // /_/ / /
 / ___ |/ /_/ //   |/ ____/ /___
/_/  |_/_____//_/|_/_/   /_____/

  {__product__} v{__version__}
  Active Directory Attack & Audit Framework
  219 modules | 25 categories

  Type 'help' for available commands.
"""

# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

_HISTORY_FILE = Path.home() / ".adxpl_history"
_HISTORY_LENGTH = 1000


def _load_history() -> None:
    try:
        if _HISTORY_FILE.exists():
            readline.read_history_file(str(_HISTORY_FILE))
    except OSError:
        pass


def _save_history() -> None:
    try:
        readline.set_history_length(_HISTORY_LENGTH)
        readline.write_history_file(str(_HISTORY_FILE))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Completer
# ---------------------------------------------------------------------------

class _Completer:
    """Tab-completion for the ADXPL REPL."""

    _COMMANDS = [
        "use", "show", "set", "unset", "run", "back", "help",
        "exit", "quit", "info", "search", "clear",
    ]
    _SHOW_ARGS = ["modules", "options", "categories"]

    def __init__(self) -> None:
        self._matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            line = readline.get_line_buffer().lstrip()
            self._matches = self._calc_matches(line, text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _calc_matches(self, line: str, text: str) -> list[str]:
        parts = line.split()
        n = len(parts)

        # Empty line or first word
        if n == 0 or (n == 1 and not line.endswith(" ")):
            return [c + " " for c in self._COMMANDS if c.startswith(text)]

        cmd = parts[0].lower()

        # "use <category>/<module>"
        if cmd == "use":
            return self._complete_module_path(text)

        # "show modules|options|categories"
        if cmd == "show" and (n == 1 or (n == 2 and not line.endswith(" "))):
            return [a + " " for a in self._SHOW_ARGS if a.startswith(text)]

        # "set <option>"
        if cmd == "set" and (n == 1 or (n == 2 and not line.endswith(" "))):
            return self._complete_options(text)

        # "unset <option>"
        if cmd == "unset" and (n == 1 or (n == 2 and not line.endswith(" "))):
            return self._complete_options(text)

        # "search <term>" completes category/module
        if cmd == "search":
            return self._complete_module_path(text)

        return []

    @staticmethod
    def _complete_module_path(text: str) -> list[str]:
        results: list[str] = []
        if "/" in text:
            cat, partial = text.split("/", 1)
            modules = _MODULE_MAP.get(cat, {})
            for mod_name in sorted(modules):
                full = f"{cat}/{mod_name}"
                if full.startswith(text):
                    results.append(full + " ")
        else:
            # Complete category names
            for cat in sorted(_MODULE_MAP):
                if cat.startswith(text):
                    results.append(cat + "/")
            # Also complete full paths
            for cat, modules in sorted(_MODULE_MAP.items()):
                for mod_name in sorted(modules):
                    full = f"{cat}/{mod_name}"
                    if full.startswith(text):
                        results.append(full + " ")
        return results

    @staticmethod
    def _complete_options(text: str) -> list[str]:
        opts = [
            "target", "domain", "username", "password", "hashes",
            "dc_ip", "output", "listener", "lhost", "lport",
            "command", "method", "template", "ca", "spn",
            "impersonate", "threads", "timeout",
        ]
        return [o + " " for o in opts if o.startswith(text)]


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class _Session:
    """Holds the current module selection and options."""

    def __init__(self) -> None:
        self.category: str | None = None
        self.module_name: str | None = None
        self.module_path: str | None = None
        self.options: dict[str, str] = {}

    @property
    def prompt(self) -> str:
        if self.category and self.module_name:
            return f"\001\033[1;31m\002adxpl\001\033[0m\002(\001\033[1;34m\002{self.category}/{self.module_name}\001\033[0m\002) > "
        return "\001\033[1;31m\002adxpl\001\033[0m\002 > "

    def select(self, path: str) -> bool:
        """Select a module by category/name path. Returns True on success."""
        if "/" not in path:
            print(f"[!] Formato: use <category>/<module>")
            return False
        cat, mod = path.split("/", 1)
        mod_path = _MODULE_MAP.get(cat, {}).get(mod)
        if not mod_path:
            print(f"[!] Modulo desconhecido: {cat}/{mod}")
            return False
        self.category = cat
        self.module_name = mod
        self.module_path = mod_path
        return True

    def deselect(self) -> None:
        self.category = None
        self.module_name = None
        self.module_path = None

    def as_namespace(self) -> Namespace:
        """Build an argparse-like Namespace from current options."""
        ns = Namespace()
        ns.command = self.category
        ns.module = self.module_name
        for key, val in self.options.items():
            setattr(ns, key, val)
        return ns


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_help(**_: Any) -> None:
    print("""
Comandos disponiveis:
  use <category>/<module>   Selecionar modulo (ex: use attack/kerberoast)
  show modules              Listar todos os modulos
  show categories           Listar categorias
  show options              Mostrar opcoes atuais
  set <opt> <value>         Definir opcao (ex: set target 10.0.0.1)
  unset <opt>               Remover opcao
  run                       Executar modulo selecionado
  info                      Informacoes do modulo atual
  search <term>             Buscar modulos por nome
  back                      Desselecionar modulo
  clear                     Limpar tela
  help                      Mostrar esta ajuda
  exit / quit               Sair
""")


def _cmd_show(session: _Session, args: list[str]) -> None:
    if not args:
        print("[!] Uso: show modules | show options | show categories")
        return

    what = args[0].lower()

    if what == "modules":
        total = 0
        for cat in sorted(_MODULE_MAP):
            modules = sorted(_MODULE_MAP[cat])
            total += len(modules)
            print(f"\n  \033[1;33m{cat}\033[0m ({len(modules)} modulos)")
            for mod_name in modules:
                print(f"    {cat}/{mod_name}")
        print(f"\n  Total: {total} modulos em {len(_MODULE_MAP)} categorias\n")

    elif what == "categories":
        print()
        for cat in sorted(_MODULE_MAP):
            count = len(_MODULE_MAP[cat])
            print(f"  \033[1;33m{cat}\033[0m  ({count})")
        print()

    elif what == "options":
        if not session.options:
            print("[*] Nenhuma opcao definida.")
            return
        print()
        print(f"  {'Opcao':<20} {'Valor'}")
        print(f"  {'-'*20} {'-'*40}")
        for key in sorted(session.options):
            print(f"  {key:<20} {session.options[key]}")
        print()
    else:
        print(f"[!] Argumento desconhecido: {what}")


def _cmd_set(session: _Session, args: list[str]) -> None:
    if len(args) < 2:
        print("[!] Uso: set <opcao> <valor>")
        return
    key = args[0]
    val = " ".join(args[1:])
    session.options[key] = val
    print(f"[*] {key} => {val}")


def _cmd_unset(session: _Session, args: list[str]) -> None:
    if not args:
        print("[!] Uso: unset <opcao>")
        return
    key = args[0]
    if key in session.options:
        del session.options[key]
        print(f"[*] {key} removido")
    else:
        print(f"[!] Opcao nao encontrada: {key}")


def _cmd_use(session: _Session, args: list[str]) -> None:
    if not args:
        print("[!] Uso: use <category>/<module>")
        return
    session.select(args[0])


def _cmd_run(session: _Session) -> int:
    if not session.module_path:
        print("[!] Nenhum modulo selecionado. Use 'use <category>/<module>' primeiro.")
        return 1

    ns = session.as_namespace()

    try:
        mod = importlib.import_module(session.module_path)
    except ImportError as exc:
        print(f"[!] Falha ao carregar {session.module_path}: {exc}")
        print("[*] Alguns modulos requerem dependencias opcionais. Instale com: pip install adxpl-forge[full]")
        return 1

    if not hasattr(mod, "run"):
        print(f"[!] Modulo {session.module_path} nao tem funcao run().")
        return 1

    try:
        return mod.run(ns)
    except KeyboardInterrupt:
        print("\n[!] Execucao interrompida pelo usuario.")
        return 130
    except Exception as exc:
        print(f"[!] Erro na execucao: {exc}")
        return 1


def _cmd_info(session: _Session) -> None:
    if not session.module_path:
        print("[!] Nenhum modulo selecionado.")
        return
    print(f"\n  Categoria: {session.category}")
    print(f"  Modulo:    {session.module_name}")
    print(f"  Path:      {session.module_path}")
    try:
        mod = importlib.import_module(session.module_path)
        if hasattr(mod, "__doc__") and mod.__doc__:
            print(f"  Descricao: {mod.__doc__.strip()}")
    except ImportError:
        print("  [!] Modulo nao pode ser carregado (dependencia faltante?)")
    print()


def _cmd_search(args: list[str]) -> None:
    if not args:
        print("[!] Uso: search <termo>")
        return
    term = args[0].lower()
    found = 0
    for cat, modules in sorted(_MODULE_MAP.items()):
        for mod_name in sorted(modules):
            if term in cat.lower() or term in mod_name.lower():
                print(f"  {cat}/{mod_name}")
                found += 1
    if found == 0:
        print(f"[*] Nenhum modulo encontrado para '{term}'.")
    else:
        print(f"\n  {found} modulo(s) encontrado(s).")


# ---------------------------------------------------------------------------
# Main REPL loop
# ---------------------------------------------------------------------------

def _repl() -> int:
    session = _Session()
    completer = _Completer()

    readline.set_completer(completer.complete)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")

    _load_history()
    atexit.register(_save_history)

    print(_BANNER)

    while True:
        try:
            line = input(session.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Saindo...")
            break

        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit"):
            print("[*] Saindo...")
            break
        elif cmd == "help":
            _cmd_help()
        elif cmd == "use":
            _cmd_use(session, args)
        elif cmd == "show":
            _cmd_show(session, args)
        elif cmd == "set":
            _cmd_set(session, args)
        elif cmd == "unset":
            _cmd_unset(session, args)
        elif cmd == "run":
            _cmd_run(session)
        elif cmd == "back":
            session.deselect()
        elif cmd == "info":
            _cmd_info(session)
        elif cmd == "search":
            _cmd_search(args)
        elif cmd == "clear":
            # Safe: hardcoded command, no user input
            os.system("clear" if os.name != "nt" else "cls")  # noqa: S605
        else:
            print(f"[!] Comando desconhecido: {cmd}. Digite 'help' para ajuda.")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ADXPL interactive shell."""
    # If argv provided, treat as single command (non-interactive)
    if argv:
        session = _Session()
        parts = argv
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd == "use" and args:
            session.select(args[0])
        return 0
    return _repl()


if __name__ == "__main__":
    sys.exit(main())
