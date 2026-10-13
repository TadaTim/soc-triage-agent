"""IoC extraction unit tests: every type — positive, negative, and
adversarial near-miss cases."""

from __future__ import annotations

from packages.enrich.extract import extract_iocs
from packages.schemas.models import IoCType


def values(payload: str) -> set[tuple[str, str]]:
    return {(ioc.type.value, ioc.value) for ioc in extract_iocs(payload)}


def test_ipv4_plain_and_defanged() -> None:
    assert ("ipv4", "185.220.101.7") in values("beacon to 185.220.101.7 every 60s")
    assert ("ipv4", "185.220.101.7") in values("beacon to 185.220.101[.]7 every 60s")


def test_ipv4_rejects_invalid_octets_and_version_strings() -> None:
    # 300.400.1.1 is not an IP; 10.4.2.9182 is a version string, not an IP.
    assert values("contact 300.400.1.1 for details") == set()
    assert ("ipv4", "10.4.2.9182") not in values("agent version 10.4.2.9182 recorded")
    assert values("agent version 10.4.2.9182 recorded") == set()


def test_ipv6() -> None:
    assert ("ipv6", "2001:db8::1") in values("listener on 2001:db8::1 port 443")


def test_domain_and_defanged_domain() -> None:
    assert ("domain", "secure-login-verify.com") in values(
        "user visited secure-login-verify.com/login"
    )
    assert ("domain", "secure-login-verify.com") in values(
        "user visited secure-login-verify[.]com/login"
    )


def test_url_emits_url_and_host() -> None:
    got = values("download from http://176.113.115.19/payload.ps1 now")
    assert ("url", "http://176.113.115.19/payload.ps1") in got
    assert ("ipv4", "176.113.115.19") in got


def test_defanged_url_normalizes() -> None:
    got = values("clicked hxxps://secure-login-verify[.]com/login today")
    assert ("url", "https://secure-login-verify.com/login") in got
    assert ("domain", "secure-login-verify.com") in got


def test_hashes_by_length_and_boundaries() -> None:
    sha256 = "a" * 64
    sha1 = "b" * 40
    md5 = "c" * 32
    got = values(f"sha256 {sha256} sha1 {sha1} md5 {md5}")
    assert ("sha256", sha256) in got
    assert ("sha1", sha1) in got
    assert ("md5", md5) in got
    # A hash glued inside a longer token is not a standalone indicator.
    assert values(f"token xx{sha256}yy end") == set()


def test_email_domain_not_double_counted() -> None:
    got = values("report from analyst@corp.example about the incident")
    assert ("email", "analyst@corp.example") in got
    assert ("domain", "corp.example") not in got


def test_file_is_not_a_domain() -> None:
    got = values(r"image C:\Users\Public\update.exe executed")
    assert ("file", "update.exe") in got
    assert ("domain", "update.exe") not in got


def test_cve() -> None:
    assert ("cve", "cve-2024-3400") in values("finding CVE-2024-3400 present on service")


def test_dotted_camelcase_identifier_is_not_a_domain() -> None:
    got = values("decoded content includes (New-Object Net.WebClient).DownloadString('x')")
    assert ("domain", "net.webclient") not in got


def test_subdomain_emitted_whole() -> None:
    got = values("queries to a1b2c3.secure-login-verify.com spiked")
    assert ("domain", "a1b2c3.secure-login-verify.com") in got


def test_offsets_point_into_original_payload() -> None:
    payload = "beacon to 185.220.101[.]7 and hxxps://bad-domain.example[.]com/x end"
    for ioc in extract_iocs(payload):
        assert payload[ioc.start : ioc.end] == ioc.raw
    by_value = {ioc.value: ioc for ioc in extract_iocs(payload)}
    assert by_value["185.220.101.7"].raw == "185.220.101[.]7"
    assert by_value["https://bad-domain.example.com/x"].raw == (
        "hxxps://bad-domain.example[.]com/x"
    )


def test_no_iocs_in_clean_text() -> None:
    assert values("Nightly maintenance completed without errors or findings.") == set()


def test_ioc_types_enum_coverage() -> None:
    # Every IoCType except ipv6 (covered above) appears in some positive test.
    covered = {"ipv4", "domain", "url", "sha256", "sha1", "md5", "email", "file", "cve", "ipv6"}
    assert covered == {t.value for t in IoCType}


def test_hxxp_and_paren_defang_variants() -> None:
    got = values("mirror at hxxp://fileshare-delivery(.)com/get it")
    assert ("url", "http://fileshare-delivery.com/get") in got
    assert ("domain", "fileshare-delivery.com") in got


def test_url_trailing_punctuation_trimmed() -> None:
    got = values("see https://example.com/path.")
    assert ("url", "https://example.com/path") in got


def test_ipv4_leading_zero_rejected() -> None:
    assert values("odd address 010.1.2.3 in the log") == set()


def test_invalid_ipv6_candidate_skipped_without_crash() -> None:
    # "a::b::c" matches the loose pattern but is not a valid IPv6 address.
    assert ("ipv6", "a::b::c") not in values("weird token a::b::c appeared")


def test_ip_inside_url_not_duplicated_by_ip_pass() -> None:
    got = extract_iocs("GET http://91.240.118.7:8080/x HTTP/1.1")
    ips = [ioc for ioc in got if ioc.type == IoCType.IPV4]
    assert len(ips) == 1 and ips[0].value == "91.240.118.7"
