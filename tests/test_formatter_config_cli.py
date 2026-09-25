import json

from usi import cli
from usi.config import load_config
from usi.models import InvestigationResult, Severity, Signal, VerdictReport
from usi.output import formatter


def make_result(verdict="Suspicious", signals=None, from_cache=False):
    return InvestigationResult(
        url="https://x.top", host="x.top", is_onion=False, from_cache=from_cache,
        checked_at="2026-09-25T00:00:00+00:00",
        verdict=VerdictReport(verdict=verdict, signals=signals or [
            Signal("clickfix", "clickfix_instruction_detected", Severity.CRITICAL, "paste it",
                   {"matched_patterns": ["a"]}),
            Signal("whois", "registrar", Severity.INFO, "Registrar: X"),
        ]),
        skipped_layers=["reputation"],
    )


# --- formatter ---

def test_result_dict_round_trip_preserves_everything():
    original = make_result()
    restored = formatter.result_from_dict(formatter.result_to_dict(original))
    assert restored.url == original.url
    assert restored.verdict.verdict == original.verdict.verdict
    assert restored.verdict.signals == original.verdict.signals
    assert restored.skipped_layers == ["reputation"]
    assert restored.from_cache is True


def test_to_json_is_valid_and_carries_signals():
    data = json.loads(formatter.to_json(make_result()))
    assert data["verdict"]["verdict"] == "Suspicious"
    assert data["verdict"]["signals"][0]["severity"] == "CRITICAL"


def test_human_report_hides_info_unless_verbose():
    normal = formatter.to_human_report(make_result())
    verbose = formatter.to_human_report(make_result(), verbose=True)
    assert "paste it" in normal and "Registrar: X" not in normal
    assert "Registrar: X" in verbose


def test_human_report_quiet_prints_only_verdict():
    out = formatter.to_human_report(make_result(), quiet=True)
    assert "Suspicious" in out and "paste it" not in out


def test_human_report_marks_cached_results():
    assert "cached result" in formatter.to_human_report(make_result(from_cache=True))


def test_plain_fallback_report_matches_content():
    out = formatter._plain_report(make_result(), verbose=False)
    assert "Verdict: Suspicious" in out and "paste it" in out and "Registrar: X" not in out
    assert "Skipped: reputation" in formatter._plain_report(make_result())
    assert "No notable signals." in formatter._plain_report(make_result(signals=[
        Signal("whois", "registrar", Severity.INFO, "x")]))


# --- config ---

def test_defaults_when_no_config_file(tmp_path):
    cfg = load_config(tmp_path / "missing.toml")
    assert cfg.reputation_enabled is False
    assert cfg.fetch_max_bytes == 2_097_152
    assert all(not r.enabled for r in cfg.reputation.values())


def test_toml_values_are_loaded(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[fetch]\ntimeout_seconds = 7\n[cache]\nttl_hours = 3\n'
                 '[reputation.virustotal]\nenabled = true\napi_key = "abc"\n', encoding="utf-8")
    cfg = load_config(p)
    assert cfg.fetch_timeout_seconds == 7
    assert cfg.cache_ttl_hours == 3
    assert cfg.reputation["virustotal"].api_key == "abc"
    assert cfg.reputation["virustotal"].enabled is True


def test_env_var_overrides_file_and_enables_client(tmp_path, monkeypatch):
    p = tmp_path / "c.toml"
    p.write_text('[reputation.virustotal]\nenabled = false\napi_key = "from-file"\n', encoding="utf-8")
    monkeypatch.setenv("USI_VIRUSTOTAL_API_KEY", "from-env")
    cfg = load_config(p)
    assert cfg.reputation["virustotal"].api_key == "from-env"
    assert cfg.reputation["virustotal"].enabled is True


def test_relative_cache_path_resolves_against_project_not_cwd(tmp_path, monkeypatch):
    # Regression: a relative cache path used to land in whatever directory
    # the tool was run from, silently creating a second cache there.
    from pathlib import Path
    from usi.config import PROJECT_ROOT
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "c.toml"
    p.write_text('[cache]\npath = "mycache/x.sqlite3"\n', encoding="utf-8")
    assert Path(load_config(p).cache_path) == PROJECT_ROOT / "mycache" / "x.sqlite3"
    assert Path(load_config(tmp_path / "none.toml").cache_path).is_absolute()


def test_absolute_cache_path_is_kept(tmp_path):
    p = tmp_path / "c.toml"
    target = tmp_path / "abs.sqlite3"
    p.write_text(f'[cache]\npath = "{target.as_posix()}"\n', encoding="utf-8")
    assert load_config(p).cache_path == str(target)


# --- cli ---

def test_cli_invalid_target_is_a_clean_error_exit_2(capsys):
    assert cli.main(["http://x.com:99999/", "--offline", "--no-store"]) == 2
    err = capsys.readouterr().err
    assert "error:" in err and "Traceback" not in err


def test_cli_empty_target_exits_2(capsys):
    assert cli.main(["", "--offline", "--no-store"]) == 2

def test_cli_parser_flags():
    args = cli.build_parser().parse_args(["x.com", "--offline", "--json", "--timeout", "3", "-v"])
    assert args.offline and args.json and args.verbose and args.timeout == 3


def test_cli_main_prints_json(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "run", lambda *a, **k: make_result())
    monkeypatch.setattr(cli, "load_config", lambda p: __import__("usi.config", fromlist=["Config"]).Config())
    assert cli.main(["x.top", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["url"] == "https://x.top"


def test_cli_refresh_disables_cache_and_overrides_apply(monkeypatch):
    seen = {}

    def fake_run(url, config, **kw):
        seen.update(kw, timeout=config.fetch_timeout_seconds, maxb=config.fetch_max_bytes)
        return make_result()
    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setattr(cli, "load_config", lambda p: __import__("usi.config", fromlist=["Config"]).Config())
    cli.main(["x.top", "--refresh", "--timeout", "9", "--max-bytes", "123", "-q"])
    assert seen["no_cache"] is True and seen["timeout"] == 9 and seen["maxb"] == 123
