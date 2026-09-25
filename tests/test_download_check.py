from usi.content import download_check


def test_exe_with_octet_stream_flagged():
    sig = download_check.analyze(
        final_url="https://fake-zoom-update.top/ZoomInstaller.exe",
        content_type="application/octet-stream",
        content_disposition=None,
    )
    assert sig is not None
    assert sig.code == "direct_file_download"
    assert sig.evidence["extension"] == ".exe"


def test_msi_with_msdownload_content_type_flagged():
    sig = download_check.analyze(
        final_url="https://fake-teams-update.top/TeamsUpdate.msi",
        content_type="application/x-msdownload",
        content_disposition=None,
    )
    assert sig is not None
    assert sig.code == "direct_file_download"


def test_attachment_disposition_flagged_even_without_content_type():
    sig = download_check.analyze(
        final_url="https://example.com/download/payload.ps1",
        content_type=None,
        content_disposition="attachment; filename=payload.ps1",
    )
    assert sig is not None


def test_exe_looking_url_served_as_real_html_not_flagged():
    # A URL that merely mentions ".exe" in its path/query but is actually
    # a normal HTML page (a support article, a blog post) must not be
    # flagged - the response headers, not the URL text alone, decide.
    sig = download_check.analyze(
        final_url="https://example.com/blog/how-to-run-installer.exe.html",
        content_type="text/html; charset=utf-8",
        content_disposition=None,
    )
    assert sig is None


def test_normal_pdf_not_flagged():
    sig = download_check.analyze(
        final_url="https://example.com/whitepaper.pdf",
        content_type="application/pdf",
        content_disposition=None,
    )
    assert sig is None


def test_normal_image_not_flagged():
    sig = download_check.analyze(
        final_url="https://example.com/logo.png",
        content_type="image/png",
        content_disposition=None,
    )
    assert sig is None


def test_no_final_url_not_flagged():
    assert download_check.analyze(None, "application/octet-stream", None) is None


def test_vbs_implant_flagged():
    # Per JUMPSEC's source analysis of a leaked BlueNoroff kit: a
    # 497-line VBScript implant (Trojan.NukeSped) delivered this way.
    sig = download_check.analyze(
        final_url="https://fake-zoom-update.top/ZoomSDKUpdate.vbs",
        content_type="application/octet-stream",
        content_disposition=None,
    )
    assert sig is not None
    assert sig.evidence["extension"] == ".vbs"


def test_scpt_applescript_lure_flagged():
    # Microsoft's macOS write-up: a file literally named
    # "Zoom SDK Update.scpt" run via Script Editor.
    sig = download_check.analyze(
        final_url="https://fake-zoom-update.top/Zoom%20SDK%20Update.scpt",
        content_type="application/octet-stream",
        content_disposition=None,
    )
    assert sig is not None
    assert sig.evidence["extension"] == ".scpt"


def test_command_file_flagged():
    sig = download_check.analyze(
        final_url="https://fake-teams-update.top/fix.command",
        content_type=None,
        content_disposition="attachment; filename=fix.command",
    )
    assert sig is not None
    assert sig.evidence["extension"] == ".command"


def test_workflow_automator_file_flagged():
    sig = download_check.analyze(
        final_url="https://fake-teams-update.top/TeamsFix.workflow",
        content_type="application/octet-stream",
        content_disposition=None,
    )
    assert sig is not None
    assert sig.evidence["extension"] == ".workflow"


def test_normal_html_page_not_flagged():
    sig = download_check.analyze(
        final_url="https://example.com/",
        content_type="text/html; charset=utf-8",
        content_disposition=None,
    )
    assert sig is None
