"""Tests for adxpl.interpreter REPL."""

from unittest.mock import patch

from adxpl.interpreter import _BANNER, _Completer, _Session, main

# ---------------------------------------------------------------------------
# _Session tests
# ---------------------------------------------------------------------------

class TestSession:
    def test_initial_state(self):
        s = _Session()
        assert s.category is None
        assert s.module_name is None
        assert s.module_path is None
        assert s.options == {}

    def test_select_valid(self):
        s = _Session()
        assert s.select("attack/kerberoast") is True
        assert s.category == "attack"
        assert s.module_name == "kerberoast"
        assert s.module_path == "adxpl.modules.attack.kerberoast"

    def test_select_invalid_no_slash(self, capsys):
        s = _Session()
        assert s.select("kerberoast") is False
        out = capsys.readouterr().out
        assert "Formato" in out

    def test_select_invalid_module(self, capsys):
        s = _Session()
        assert s.select("attack/nonexistent") is False
        out = capsys.readouterr().out
        assert "desconhecido" in out

    def test_deselect(self):
        s = _Session()
        s.select("attack/kerberoast")
        s.deselect()
        assert s.category is None
        assert s.module_name is None

    def test_prompt_no_module(self):
        s = _Session()
        assert "adxpl" in s.prompt
        assert "/" not in s.prompt.replace("\001", "").replace("\002", "").replace("\033[1;31m", "").replace("\033[0m", "")

    def test_prompt_with_module(self):
        s = _Session()
        s.select("enum/bloodhound")
        raw = s.prompt
        assert "enum/bloodhound" in raw

    def test_as_namespace(self):
        s = _Session()
        s.select("attack/kerberoast")
        s.options["target"] = "10.0.0.1"
        s.options["domain"] = "corp.local"
        ns = s.as_namespace()
        assert ns.command == "attack"
        assert ns.module == "kerberoast"
        assert ns.target == "10.0.0.1"
        assert ns.domain == "corp.local"


# ---------------------------------------------------------------------------
# _Completer tests
# ---------------------------------------------------------------------------

class TestCompleter:
    def test_complete_commands(self):
        c = _Completer()
        with patch("readline.get_line_buffer", return_value=""):
            matches = c._calc_matches("", "")
        assert any("use " in m for m in matches)
        assert any("help " in m for m in matches)

    def test_complete_use_category(self):
        c = _Completer()
        matches = c._calc_matches("use att", "att")
        assert any("attack/" in m for m in matches)

    def test_complete_use_full_path(self):
        c = _Completer()
        matches = c._calc_matches("use attack/kerb", "attack/kerb")
        assert any("kerberoast" in m for m in matches)

    def test_complete_show_args(self):
        c = _Completer()
        matches = c._calc_matches("show ", "")
        labels = [m.strip() for m in matches]
        assert "modules" in labels
        assert "options" in labels

    def test_complete_set_options(self):
        c = _Completer()
        matches = c._calc_matches("set tar", "tar")
        assert any("target" in m for m in matches)


# ---------------------------------------------------------------------------
# Banner test
# ---------------------------------------------------------------------------

def test_banner_content():
    assert "ADXPL" in _BANNER
    assert "2.1.0" in _BANNER


# ---------------------------------------------------------------------------
# REPL loop tests via main()
# ---------------------------------------------------------------------------

class TestREPL:
    def test_exit_command(self):
        with patch("builtins.input", side_effect=["exit"]):
            ret = main()
        assert ret == 0

    def test_quit_command(self):
        with patch("builtins.input", side_effect=["quit"]):
            ret = main()
        assert ret == 0

    def test_eof_exits(self):
        with patch("builtins.input", side_effect=EOFError):
            ret = main()
        assert ret == 0

    def test_keyboard_interrupt_exits(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            ret = main()
        assert ret == 0

    def test_help_command(self, capsys):
        with patch("builtins.input", side_effect=["help", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "use <category>/<module>" in out

    def test_show_modules(self, capsys):
        with patch("builtins.input", side_effect=["show modules", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "attack" in out
        assert "kerberoast" in out

    def test_show_categories(self, capsys):
        with patch("builtins.input", side_effect=["show categories", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "enum" in out

    def test_use_and_info(self, capsys):
        with patch("builtins.input", side_effect=["use attack/kerberoast", "info", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "kerberoast" in out

    def test_set_and_show_options(self, capsys):
        with patch("builtins.input", side_effect=[
            "set target 10.0.0.1",
            "set domain corp.local",
            "show options",
            "exit",
        ]):
            main()
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "corp.local" in out

    def test_unset_option(self, capsys):
        with patch("builtins.input", side_effect=[
            "set target 10.0.0.1",
            "unset target",
            "exit",
        ]):
            main()
        out = capsys.readouterr().out
        assert "removido" in out

    def test_back_command(self, capsys):
        with patch("builtins.input", side_effect=[
            "use attack/kerberoast",
            "back",
            "exit",
        ]):
            main()
        # Just ensure no crash

    def test_search_command(self, capsys):
        with patch("builtins.input", side_effect=["search kerb", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "kerberoast" in out

    def test_unknown_command(self, capsys):
        with patch("builtins.input", side_effect=["foobar", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "desconhecido" in out

    def test_run_without_module(self, capsys):
        with patch("builtins.input", side_effect=["run", "exit"]):
            main()
        out = capsys.readouterr().out
        assert "Nenhum modulo selecionado" in out

    def test_main_with_argv(self):
        ret = main(["use", "attack/kerberoast"])
        assert ret == 0
