"""Crypto wallet-drainer detection - two distinct real-world shapes:

1. Fake dApp/airdrop/mint pages that get a victim to connect a real Web3
   wallet and sign a transaction that looks routine ("Claim Airdrop",
   "Confirm Swap") but actually grants the attacker's contract approval
   to drain it. Detected via Web3 wallet-connect JS signatures combined
   with airdrop/mint/migrate urgency language.
2. Fake wallet-UI clone pages mimicking a real wallet APP's own
   send/transfer screen ("Transfer Trust Wallet", "Send USDT", "Paste
   Amount") to trick the victim into pasting a seed phrase or sending
   funds directly - no Web3 JS API calls involved at all, since these
   pages often just POST a form rather than using window.ethereum, or
   keep their wallet logic in an externally bundled script this tool's
   plain-text scan can't see into. Shape (2) therefore has its own,
   JS-independent detection path: wallet-brand name + transfer-UI
   language, mirroring brand_impersonation's brand+domain-mismatch
   check but triggered by this UI language instead of a password field.

A THIRD, even more damning pattern stands alone regardless of either
shape above: any request for a seed phrase, recovery phrase, or private
key typed/pasted into a web page. No legitimate wallet ever asks for
this in a browser - every wallet's own documentation says so - so this
fires CRITICAL on the request alone, no corroboration needed. A request
means an instruction to enter one ("enter your recovery phrase") or a form
field that asks for one; merely naming the terms does not count, and a
negated instruction ("never enter your seed phrase") is a warning, not a
request. (Before 2026-09-25 the bare words were enough, which flagged
darknyx.com because it lists "private key" and "seed phrase" among the
indicator types it detects.)

A FOURTH shape, described in JUMPSEC's source-level analysis of a leaked
BlueNoroff fake-Zoom/Teams phishing kit: the page starts probing wallet
extensions the instant it loads - EIP-6963 announce-provider events,
legacy window.ethereum injection, then a sweep for non-EVM wallets
(Solana/Phantom-style) - with no airdrop/urgency bait at all, since the
page isn't pretending to be a dApp; it's pretending to be a meeting
invite. Bare Web3 JS alone stays INFO-only (legitimate dApps use it
too), but probing *multiple, unrelated wallet ecosystems* on a page
that never once reads like an actual crypto product is a distinguishable
shape from a normal multi-chain wallet connector (RainbowKit, Web3Modal
and friends are embedded in real DeFi/NFT pages, which almost always
mention at least one of those words somewhere)."""
import re

from ..models import Severity, Signal

# Web3 wallet-connect library/API signatures - present on legitimate
# dApps too, so on their own these are only INFO-level context, never
# proof of malice. Only catches inline JS - see module docstring on why
# this alone isn't sufficient.
_WEB3_JS_SIGNATURES = (
    r"window\.ethereum",
    r"walletconnect",
    r"\bwagmi\b",
    r"eth_requestaccounts",
    r"eth_sendtransaction",
    r"connectwallet",
)

# Phrasing specific to the airdrop/mint drainer bait.
_URGENCY_PATTERNS = (
    r"claim\s+(?:your\s+)?airdrop",
    r"mint\s+(?:now|free)",
    r"migrate\s+(?:your\s+)?tokens?",
    r"connect\s+(?:your\s+)?wallet\s+to\s+claim",
    r"limited\s+time\s+(?:airdrop|mint|offer)",
    r"exclusive\s+airdrop",
)

# Phrasing specific to a fake wallet-transfer-UI clone - mimicking the
# wallet app's own send screen rather than a dApp/airdrop page.
_WALLET_TRANSFER_UI_PATTERNS = (
    r"transfer\s+(?:trust\s*wallet|metamask|wallet)",
    r"send\s+(?:usdt|usdc|eth|btc|bnb)\b",
    r"recipient\s+address",
    r"paste\s+amount",
    r"wallet\s+balance",
)

# No legitimate wallet ever asks for this typed/pasted into a web page -
# fires on its own, no corroboration required.
_SEED_PHRASE_PATTERNS = (
    r"seed\s+phrase",
    r"recovery\s+phrase",
    r"private\s+key",
    r"12[\s-]word\s+phrase",
    r"24[\s-]word\s+phrase",
    r"mnemonic\s+phrase",
)

_SEED_TERM = "(?:" + "|".join(_SEED_PHRASE_PATTERNS) + ")"

# An instruction to hand one over: a verb of entering/submitting, then at most three words
# ("your", "the", "12-word"...), then the term. Bounded, so it cannot backtrack badly on long text.
_SEED_INSTRUCTION_RE = re.compile(
    r"\b(?:enter|type|paste|input|provide|submit|import|restore|verify|confirm|validate)\b"
    r"(?:\s+[\w'-]+){0,3}?\s+" + _SEED_TERM
)

# The same sentence negated ("never enter your seed phrase", "we will never ask you to enter ...").
_NEGATION_RE = re.compile(
    r"\b(?:never|do\s+not|don't|not|won't|will\s+not|should\s+not|shouldn't|no\s+legitimate|neither|nor|without)\b"
)

# A form field that asks for one: an input/textarea whose own attributes name it.
_SEED_FIELD_RE = re.compile(
    r"<(?:input|textarea)\b[^>]{0,300}?(?:seed|mnemonic|recovery|private[\s_-]?key|secret[\s_-]?phrase)",
)


def _seed_phrase_request(text_l: str, html_l: str) -> "list[str]":
    """The seed-phrase patterns present on the page, but only when the page asks for one to be
    entered; an empty list for a page that merely mentions them."""
    text_l = text_l.replace("’", "'")
    present = [p for p in _SEED_PHRASE_PATTERNS if re.search(p, text_l)]
    if not present:
        return []
    for m in _SEED_INSTRUCTION_RE.finditer(text_l):
        # only the same sentence can negate it: "This is not a scam. Enter your seed phrase" is a request
        same_sentence = re.split(r"[.!?\n]", text_l[max(0, m.start() - 120):m.start()])[-1]
        if not _NEGATION_RE.search(same_sentence[-60:]):
            return present
    if _SEED_FIELD_RE.search(html_l):
        return present
    return []


# Wallet brand names worth checking against the title even when the
# brand isn't in brands.json's broader curated list.
_WALLET_BRAND_NAMES = ("trust wallet", "metamask", "coinbase wallet", "phantom", "ledger", "trezor")

# EIP-6963 (multi-wallet discovery) and legacy window.ethereum injection -
# the EVM side of a silent wallet-enumeration sweep.
_EVM_PROBE_SIGNATURES = (
    r"window\.ethereum",
    r"eip6963",
    r"eth_requestaccounts",
)

# The non-EVM side - Solana/Phantom-family wallet extensions. Probing
# BOTH this and the EVM signatures above on one page, with no crypto-
# product framing anywhere, is the tell: a real dApp targets its own
# ecosystem and reads like a crypto product; a reconnaissance script
# sweeps everything indiscriminately.
_NON_EVM_PROBE_SIGNATURES = (
    r"window\.solana",
    r"window\.phantom",
    r"isphantom",
    r"\bsolflare\b",
    r"window\.backpack",
)

# Words that show up on essentially any real crypto product's page
# somewhere (product description, footer, FAQ) - their total absence
# alongside multi-chain wallet probing is what separates a fingerprinting
# script from a legitimate multi-wallet connector.
_LEGITIMATE_CRYPTO_CONTEXT_WORDS = (
    "dapp", "defi", "nft", "airdrop", "mint", "swap", "stake",
    "liquidity", "presale", "token sale",
)


def _wallet_enumeration_signal(html_l: str, haystack: str) -> "Signal | None":
    has_evm_probe = any(re.search(p, html_l) for p in _EVM_PROBE_SIGNATURES)
    has_non_evm_probe = any(re.search(p, html_l) for p in _NON_EVM_PROBE_SIGNATURES)
    if not (has_evm_probe and has_non_evm_probe):
        return None
    if any(word in haystack for word in _LEGITIMATE_CRYPTO_CONTEXT_WORDS):
        return None
    return Signal(
        source="crypto_drainer", code="silent_wallet_enumeration", severity=Severity.HIGH,
        message=(
            "This page silently probes for both Ethereum-family and Solana-family "
            "wallet extensions the moment it loads, with no accompanying crypto-"
            "product framing (no dApp/DeFi/NFT/airdrop language anywhere on the "
            "page) - consistent with a reconnaissance script fingerprinting "
            "installed wallets rather than a legitimate multi-chain connector."
        ),
    )


def _web3_signal(html_l: str, urgency_hits: "list[str]") -> "Signal | None":
    has_web3_js = any(re.search(p, html_l) for p in _WEB3_JS_SIGNATURES)
    if has_web3_js and urgency_hits:
        return Signal(
            source="crypto_drainer", code="crypto_drainer_pattern", severity=Severity.HIGH,
            message=(
                "This page combines Web3 wallet-connect functionality with urgent "
                "airdrop/mint/migration language - a common pattern for wallet-"
                "drainer sites that trick a connected wallet into signing an "
                "approval transaction that empties it. Never connect a real wallet "
                "or sign anything on a site you found unexpectedly."
            ),
            evidence={"urgency_phrases_matched": urgency_hits},
        )
    if has_web3_js:
        return Signal(
            source="crypto_drainer", code="web3_wallet_connect_present", severity=Severity.INFO,
            message="This page includes Web3 wallet-connect functionality. Common on "
                    "legitimate dApps too - not evidence of a drainer on its own.",
        )
    return None


def check(
    page_title: "str | None", page_text: "str | None", raw_html: "str | None"
) -> "Signal | None":
    title_l = (page_title or "").lower()
    text_l = (page_text or "").lower()
    html_l = (raw_html or "").lower()
    if not title_l and not text_l and not html_l:
        return None

    # Highest priority, fires alone: a REQUEST for a seed phrase/private key. Mentioning one is not
    # a request - security sites, wallet docs and warnings ("never enter your seed phrase") all name
    # them - so this needs an instruction to enter one, or an input field asking for one.
    seed_hits = _seed_phrase_request(text_l, html_l)
    if seed_hits:
        return Signal(
            source="crypto_drainer", code="seed_phrase_request", severity=Severity.CRITICAL,
            message=(
                "This page asks for a seed phrase, recovery phrase, or private key. "
                "No legitimate wallet or service ever asks for this in a web page - "
                "entering it here would hand over full control of the wallet."
            ),
            evidence={"matched_patterns": seed_hits},
        )

    # Fake wallet-transfer-UI clone: a wallet brand name plus transfer-UI
    # language, independent of any Web3 JS signature.
    transfer_ui_hits = [p for p in _WALLET_TRANSFER_UI_PATTERNS if re.search(p, text_l)]
    mentions_wallet_brand = any(b in title_l or b in text_l for b in _WALLET_BRAND_NAMES)
    if transfer_ui_hits and mentions_wallet_brand:
        return Signal(
            source="crypto_drainer", code="fake_wallet_transfer_ui", severity=Severity.HIGH,
            message=(
                "This page mimics a wallet app's own transfer/send screen and names a "
                "wallet brand - a common fake-wallet-clone pattern used to trick a "
                "visitor into sending funds directly or entering wallet credentials."
            ),
            evidence={"matched_patterns": transfer_ui_hits},
        )

    urgency_hits = [p for p in _URGENCY_PATTERNS if re.search(p, text_l)]
    web3_signal = _web3_signal(html_l, urgency_hits)
    if web3_signal and web3_signal.severity >= Severity.HIGH:
        return web3_signal

    # No urgency bait found - try the silent multi-chain enumeration
    # shape before falling back to the plain "Web3 present" INFO signal.
    enumeration_signal = _wallet_enumeration_signal(html_l, f"{title_l} {text_l}")
    if enumeration_signal:
        return enumeration_signal

    if web3_signal:
        return web3_signal

    return None
