from usi.content import fake_meeting


def test_fake_zoom_camera_issue_flagged():
    sig = fake_meeting.check(
        host="zoom-verify-update.top",
        page_title="Zoom Meeting - Join",
        page_text="Join Zoom Meeting. Your camera is not working - please update your "
                   "client to join the technical interview.",
    )
    assert sig is not None
    assert sig.code == "fake_meeting_platform"
    assert sig.evidence["platform"] == "Zoom"


def test_fake_teams_coding_test_flagged():
    sig = fake_meeting.check(
        host="microsoft-teams-join.top",
        page_title="Join Microsoft Teams Meeting",
        page_text="You have been invited to complete a coding test. Clone this "
                   "repository and join the Microsoft Teams call to begin.",
    )
    assert sig is not None
    assert sig.code == "fake_meeting_platform"
    assert sig.evidence["platform"] == "Microsoft Teams"


def test_fake_google_meet_update_required_flagged():
    sig = fake_meeting.check(
        host="meet-google-join.top",
        page_title="Google Meet",
        page_text="Update required to join. Download the latest version to join this "
                   "Google Meet call.",
    )
    assert sig is not None
    assert sig.evidence["platform"] == "Google Meet"


def test_fake_skype_mic_blocked_flagged():
    sig = fake_meeting.check(
        host="skype-call-verify.top",
        page_title="Skype Call",
        page_text="Microphone access is blocked. Fix the connection issue to continue "
                   "your Skype interview.",
    )
    assert sig is not None
    assert sig.evidence["platform"] == "Skype"


def test_real_zoom_domain_never_flagged():
    sig = fake_meeting.check(
        host="zoom.us",
        page_title="Zoom Meeting",
        page_text="Your camera is not working. Please check your device settings.",
    )
    assert sig is None


def test_real_teams_domain_never_flagged():
    sig = fake_meeting.check(
        host="teams.microsoft.com",
        page_title="Microsoft Teams",
        page_text="Update required to join. Please update the app.",
    )
    assert sig is None


def test_real_meet_domain_never_flagged():
    sig = fake_meeting.check(
        host="meet.google.com",
        page_title="Google Meet",
        page_text="Camera is not working - check your browser permissions.",
    )
    assert sig is None


def test_brand_name_without_tech_difficulty_framing_not_flagged():
    # Mentioning Zoom alone (a normal meeting-invite page) is not enough -
    # the tech-difficulty/interview framing is the actual gate.
    sig = fake_meeting.check(
        host="fake-zoom-lookalike.top",
        page_title="Join our Zoom call",
        page_text="Click here to join our weekly team sync on Zoom at 3pm.",
    )
    assert sig is None


def test_tech_difficulty_framing_without_brand_name_not_flagged():
    sig = fake_meeting.check(
        host="example.com",
        page_title="Join the call",
        page_text="Your camera is not working. Update required to join.",
    )
    assert sig is None


def test_no_title_or_text_not_flagged():
    sig = fake_meeting.check(host="evil.top", page_title=None, page_text=None)
    assert sig is None


def test_camera_request_without_tech_difficulty_text_flagged():
    # Per JUMPSEC's source analysis: the kit sometimes just grants itself
    # real camera access with no "camera not working" bait text at all -
    # the getUserMedia call plus brand-domain mismatch is enough on its own.
    sig = fake_meeting.check(
        host="teams-join-verify.top",
        page_title="Join Microsoft Teams Meeting",
        page_text="Please enter your name to join the call.",
        raw_html="<script>navigator.mediaDevices.getUserMedia({video: true}).then(s => send(s));</script>",
    )
    assert sig is not None
    assert sig.code == "fake_meeting_platform"
    assert sig.evidence["requests_camera"] is True
    assert sig.evidence["matched_patterns"] == []


def test_camera_request_alone_without_brand_keyword_not_flagged():
    sig = fake_meeting.check(
        host="example.com",
        page_title="Video Call",
        page_text="Please enter your name to join.",
        raw_html="<script>navigator.mediaDevices.getUserMedia({video: true});</script>",
    )
    assert sig is None


def test_camera_request_on_real_zoom_domain_never_flagged():
    sig = fake_meeting.check(
        host="zoom.us",
        page_title="Zoom Meeting",
        page_text="Please enter your name to join.",
        raw_html="<script>navigator.mediaDevices.getUserMedia({video: true});</script>",
    )
    assert sig is None


def test_vscode_tasks_json_lure_flagged():
    sig = fake_meeting.check(
        host="fake-teams-coding-test.top",
        page_title="Microsoft Teams Technical Assessment",
        page_text="Clone the repository, open it in VS Code, and run the task to start "
                   "your Microsoft Teams technical interview.",
    )
    assert sig is not None
    assert sig.code == "fake_meeting_platform"


def test_no_raw_html_backward_compatible():
    # raw_html defaults to None - existing callers that only pass three
    # positional args must keep working unchanged.
    sig = fake_meeting.check(
        host="zoom-verify-update.top",
        page_title="Zoom Meeting - Join",
        page_text="Your camera is not working - please update your client to join.",
    )
    assert sig is not None
