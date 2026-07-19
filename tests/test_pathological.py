"""The native analyzer must stay silent on legal, idiomatic C.

Every construct in `fixtures/pathological.c` is compliant, and every one of them
once produced false positives that the detector's own unit tests had passed.
The pattern behind all of them is the same: fixtures written alongside an
implementation encode the implementation's model of C, so they are blind to
exactly the shapes the author did not think of.

This file is the cheap standing guard. It runs in milliseconds and catches the
bulk of what a multi-minute corpus run finds, so a new detector can be checked
against real-world shapes before its own tests are even written.

Two further guards live here:

  * `test_no_control_characters_in_analyzer_source` -- a `\\b` written through a
    shell heredoc once reached the source as a literal backspace (0x08), so a
    word-boundary anchor silently matched nothing and a detector flagged
    everything. That class of bug is invisible on screen.
  * `test_every_native_rule_is_reachable` -- a rule that fires nowhere is
    indistinguishable from a rule that is switched off. One detector was
    reported as "clean, zero findings" while actually disabled.
"""

from pathlib import Path

import pytest

from maishac.analyzers.native import NativeAnalyzer
from maishac.coverage import native_ids

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "pathological.c"


def _findings():
    return NativeAnalyzer().analyze([FIXTURE], FIXTURE.parent)


# The fixture cannot be findings-free: it must contain `goto` to exercise 15.2's
# label scoping, `#`/`##` to exercise 20.11 and 20.13, and plain `int` in the
# multi-line signatures that broke 15.2. Those trigger 15.1, 20.10 and Dir 4.6
# as genuine advisory findings. The claim this file makes is narrower and more
# useful: none of the rules that have previously misfired on real firmware may
# fire on these shapes.
_RULES_THAT_HAVE_MISFIRED = ["20.1", "20.2", "20.11", "20.13",
                             "15.2", "16.2", "16.3", "16.6", "12.5", "17.6"]


@pytest.mark.parametrize("rule", _RULES_THAT_HAVE_MISFIRED)
def test_specific_rules_stay_silent(rule):
    """Named so a regression points straight at the rule that broke."""
    hit = [f for f in _findings() if f.rule_id.endswith(f" {rule}")]
    assert not hit, f"{rule} fired on compliant code at line {hit[0].line}"


def test_no_control_characters_in_analyzer_source():
    """Escape sequences mangled into control characters are invisible on screen
    and silently neutralise a regex."""
    for path in (Path(__file__).resolve().parents[1] / "maishac" / "analyzers").glob("*.py"):
        data = path.read_bytes()
        bad = {b for b in data if b < 9 or 11 <= b <= 12 or 14 <= b <= 31}
        assert not bad, f"{path.name} contains control bytes {sorted(bad)}"


def test_every_native_rule_is_reachable():
    """A detector that can never fire is worse than a missing one: it reports
    zero, which reads as compliance. Every rule the native analyzer claims must
    at least be emittable, i.e. resolvable in the knowledge base."""
    from maishac.rules import REGISTRY
    for rid in native_ids():
        assert REGISTRY.get(rid), f"native claims {rid}, which is not in the KB"
    assert len(native_ids()) > 25, "native rule set shrank unexpectedly"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
