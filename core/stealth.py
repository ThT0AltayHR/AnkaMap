"""
Stealth mode: reduces the odds that a scan is flagged by rate/anomaly-based
detection (as opposed to signature-based WAF rules, which core.waf_bypass
already targets). This is behavioral evasion, not payload obfuscation:

  - Randomized jittered delay between requests (mimics human browsing
    cadence instead of a flat, easily-fingerprinted request rate).
  - Rotates the User-Agent per request instead of once per session.
  - Occasionally inserts a slightly longer "pause" to break up bursts,
    even when running with many threads.

Honesty note: this raises the bar against naive rate-limiting/anomaly
detection; it is not a guarantee of invisibility against a well-tuned WAF,
CDN bot-management product, or behavioral-biometrics system.
"""

import random
import time

from config import USER_AGENTS


class StealthController:
    def __init__(self, enabled: bool = False, base_delay: float = 0.4, jitter: float = 0.6,
                 long_pause_chance: float = 0.05, long_pause_range=(1.5, 4.0)):
        self.enabled = enabled
        self.base_delay = base_delay
        self.jitter = jitter
        self.long_pause_chance = long_pause_chance
        self.long_pause_range = long_pause_range
        self._request_count = 0

    def before_request(self) -> None:
        if not self.enabled:
            return
        self._request_count += 1
        delay = self.base_delay + random.uniform(0, self.jitter)
        if random.random() < self.long_pause_chance:
            delay += random.uniform(*self.long_pause_range)
        time.sleep(delay)

    def next_user_agent(self) -> str:
        return random.choice(USER_AGENTS)
