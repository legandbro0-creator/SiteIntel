"""Email security parser tests with a STUB resolver — no network."""
from __future__ import annotations

from modules import email_security as es


class StubResolver:
    """Answers canned TXT results keyed by (name)."""
    def __init__(self, answers):
        self.answers = answers
        self.timeout = self.lifetime = 1

    def resolve(self, name, rdtype):
        import dns.resolver
        key = str(name).rstrip(".")
        records = self.answers.get(key)
        if records is None:
            raise dns.resolver.NXDOMAIN
        if not records:
            raise dns.resolver.NoAnswer

        class FakeRdata:
            def __init__(self, text):
                self.strings = [text.encode()]

        class FakeAnswer:
            rrset = type("R", (), {"ttl": 300})()

            def __iter__(self):
                return iter([FakeRdata(t) for t in records])
        return FakeAnswer()


def test_spf_present_strict_policy():
    resolver = StubResolver({"site.test": ["v=spf1 include:_spf.example.net -all"]})
    status, findings = es.analyze_spf(resolver, "site.test")
    assert status == "present"
    assert findings[0]["status"] == "PASS" and "-all" in findings[0]["evidence"]


def test_spf_softfail_passes_with_note():
    resolver = StubResolver({"site.test": ["v=spf1 a ~all"]})
    status, findings = es.analyze_spf(resolver, "site.test")
    assert status == "present" and findings[0]["status"] == "PASS"


def test_spf_plus_all_is_warned():
    resolver = StubResolver({"site.test": ["v=spf1 +all"]})
    status, findings = es.analyze_spf(resolver, "site.test")
    assert findings[0]["status"] == "WARN" and "+all" in findings[0]["evidence"]


def test_spf_multiple_records_is_invalid():
    resolver = StubResolver({"site.test": ["v=spf1 -all", "v=spf1 ~all"]})
    status, findings = es.analyze_spf(resolver, "site.test")
    assert status == "invalid" and findings[0]["status"] == "WARN"


def test_spf_lookup_count_warning():
    many = " ".join([f"include:{i}.example.net" for i in range(12)])
    resolver = StubResolver({"site.test": [f"v=spf1 {many} -all"]})
    status, findings = es.analyze_spf(resolver, "site.test")
    lookup_warn = next(f for f in findings if f["name"] == "spf_lookups")
    assert lookup_warn["status"] == "WARN"


def test_spf_absent_vs_inconclusive():
    absent = StubResolver({"site.test": []})
    status, findings = es.analyze_spf(absent, "site.test")
    assert status == "absent" and findings[0]["status"] == "WARN"

    class TimeoutResolver(StubResolver):
        def resolve(self, name, rdtype):
            raise dns.exception.Timeout
    import dns.exception
    status, findings = es.analyze_spf(TimeoutResolver({}), "site.test")
    assert status == "inconclusive" and findings[0]["status"] == "INCONCLUSIVE"


def test_dmarc_policies_meaning():
    for policy, expected in (("reject", "PASS"), ("quarantine", "PASS"), ("none", "INFO")):
        resolver = StubResolver({f"_dmarc.site.test": [f"v=DMARC1; p={policy}; pct=100"]})
        status, findings = es.analyze_dmarc(resolver, "site.test")
        assert status == "present" and findings[0]["status"] == expected
        if policy == "none":
            assert "not a defect" in findings[0]["evidence"] or "monitoring" in findings[0]["evidence"]


def test_dmarc_absent_is_warn_but_not_shamed():
    status, findings = es.analyze_dmarc(StubResolver({}), "site.test")
    assert status == "absent" and findings[0]["status"] == "WARN"
    assert "posture gap" in findings[0]["limitations"][1]


def test_dkim_not_checked_without_selectors():
    status, findings = es.analyze_dkim(StubResolver({}), "site.test", [], False)
    assert status == "not_checked" and findings[0]["status"] == "NOT_TESTED"


def test_dkim_selector_found_and_revoked():
    resolver = StubResolver({"sel1._domainkey.site.test": ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
                             "old._domainkey.site.test": ["v=DKIM1; p="]})
    status, findings = es.analyze_dkim(resolver, "site.test", ["sel1", "old"], False)
    assert status == "present"
    live = next(f for f in findings if f["name"] == "dkim:sel1")
    revoked = next(f for f in findings if f["name"] == "dkim:old")
    assert live["status"] == "PASS" and revoked["status"] == "INFO"


def test_guessed_selector_absence_is_not_a_claim():
    status, findings = es.analyze_dkim(StubResolver({}), "site.test", [], True)
    assert status == "absent"
    assert any("proves nothing" in lim for f in findings for lim in f["limitations"])


def test_tls_rpt_parse():
    resolver = StubResolver({"_smtp._tls.site.test": ["v=TLSRPTv1; rua=mailto:tls@site.test"]})
    status, findings = es.analyze_tls_rpt(resolver, "site.test")
    assert status == "present" and findings[0]["status"] == "PASS"
