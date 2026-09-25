from usi.content import crypto_drainer


def test_web3_plus_urgency_language_flagged():
    sig = crypto_drainer.check(
        page_title="Free Airdrop",
        page_text="Connect your wallet to claim your exclusive airdrop before it's gone!",
        raw_html="<script>window.ethereum.request({method: 'eth_requestAccounts'})</script>",
    )
    assert sig is not None
    assert sig.code == "crypto_drainer_pattern"


def test_web3_alone_is_info_only():
    sig = crypto_drainer.check(
        page_title="Our dApp",
        page_text="Welcome to our decentralized exchange.",
        raw_html="<script>window.ethereum.request({method: 'eth_requestAccounts'})</script>",
    )
    assert sig is not None
    assert sig.code == "web3_wallet_connect_present"
    from usi.models import Severity
    assert sig.severity == Severity.INFO


def test_urgency_language_without_web3_not_flagged():
    sig = crypto_drainer.check(
        page_title="Promo",
        page_text="Claim your airdrop now, limited time offer!",
        raw_html="<p>No wallet integration here.</p>",
    )
    assert sig is None


def test_normal_page_not_flagged():
    sig = crypto_drainer.check(
        page_title="My Blog", page_text="Welcome to our blog about gardening tips.", raw_html="<p>Welcome</p>",
    )
    assert sig is None


def test_empty_content_not_flagged():
    assert crypto_drainer.check(page_title=None, page_text=None, raw_html=None) is None


def test_seed_phrase_request_flagged_regardless_of_anything_else():
    sig = crypto_drainer.check(
        page_title="Wallet Sync", page_text="Enter your 12-word recovery phrase to sync your wallet.",
        raw_html="<p>plain html, no web3 js at all</p>",
    )
    assert sig is not None
    assert sig.code == "seed_phrase_request"
    from usi.models import Severity
    assert sig.severity == Severity.CRITICAL


def test_private_key_request_flagged():
    sig = crypto_drainer.check(
        page_title="Import Wallet", page_text="Please enter your private key to continue.", raw_html="",
    )
    assert sig is not None
    assert sig.code == "seed_phrase_request"


def test_fake_wallet_transfer_ui_flagged_without_web3_js():
    # Regression: a real OpenPhish-listed drainer ("Transfer Trust Wallet",
    # "Send USDT", "Paste Amount") had zero Web3 JS signatures in its
    # static HTML - this shape needs its own JS-independent detection.
    sig = crypto_drainer.check(
        page_title="Transfer Trust Wallet",
        page_text="Transfer Trust Wallet Send USDT Address or Domain Name Paste Amount USDT Max",
        raw_html="<p>no web3 js signatures here</p>",
    )
    assert sig is not None
    assert sig.code == "fake_wallet_transfer_ui"


def test_transfer_ui_language_without_wallet_brand_not_flagged():
    sig = crypto_drainer.check(
        page_title="Send Money",
        page_text="Send USDT to recipient address, paste amount below.",
        raw_html="<p></p>",
    )
    assert sig is None


def test_silent_multi_chain_wallet_enumeration_flagged():
    # Per JUMPSEC's source analysis of a leaked BlueNoroff kit: the fake
    # meeting page probes both EVM and Solana-family wallets the instant
    # it loads, with zero crypto-product framing anywhere on the page.
    sig = crypto_drainer.check(
        page_title="Join Meeting",
        page_text="Please wait while we connect you to the call.",
        raw_html=(
            "<script>"
            "window.addEventListener('eip6963:announceProvider', (e) => {});"
            "if (window.solana) { window.solana.connect(); }"
            "if (window.phantom) { console.log(window.phantom.isPhantom); }"
            "</script>"
        ),
    )
    assert sig is not None
    assert sig.code == "silent_wallet_enumeration"
    from usi.models import Severity
    assert sig.severity == Severity.HIGH


def test_multi_chain_probe_on_real_defi_page_not_flagged():
    # A real multi-chain wallet connector (RainbowKit/Web3Modal-style)
    # embedded in an actual DeFi product must not be flagged just for
    # supporting multiple chains - the crypto-product framing is what
    # distinguishes it from a bare reconnaissance script.
    sig = crypto_drainer.check(
        page_title="Our DeFi Swap",
        page_text="Connect your wallet to swap tokens and provide liquidity on our DeFi exchange.",
        raw_html=(
            "<script>"
            "window.ethereum.request({method: 'eth_requestAccounts'});"
            "if (window.solana) { window.solana.connect(); }"
            "</script>"
        ),
    )
    assert sig is None or sig.code != "silent_wallet_enumeration"


def test_single_ecosystem_probe_not_flagged_as_enumeration():
    # Only an EVM-side signature present (no non-EVM probe) - the
    # existing bare-Web3-present INFO signal applies instead, not
    # enumeration, which requires both ecosystems.
    sig = crypto_drainer.check(
        page_title="Our dApp",
        page_text="Welcome to our decentralized exchange.",
        raw_html="<script>window.ethereum.request({method: 'eth_requestAccounts'})</script>",
    )
    assert sig is not None
    assert sig.code == "web3_wallet_connect_present"


def test_urgency_bait_takes_priority_over_enumeration():
    # If urgency bait is present alongside multi-chain probing, the
    # existing crypto_drainer_pattern (Web3 + urgency) fires - the
    # enumeration path is specifically for the *no-bait* shape.
    sig = crypto_drainer.check(
        page_title="Free Airdrop",
        page_text="Connect your wallet to claim your exclusive airdrop before it's gone!",
        raw_html=(
            "<script>"
            "window.ethereum.request({method: 'eth_requestAccounts'});"
            "if (window.solana) { window.solana.connect(); }"
            "</script>"
        ),
    )
    assert sig is not None
    assert sig.code == "crypto_drainer_pattern"
