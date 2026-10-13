"""Golden dataset generator (Stage 3).

Builds 500 labeled alerts deterministically (seeded RNG) from SOC-realistic
templates. Design notes:

- The generator TRACKS every IoC it embeds in a payload, so each golden alert
  carries the exact IoC set a correct extractor must find. The extractor
  (packages/enrich/extract.py) is implemented independently and unit-tested
  against hand-written strings, so eval F1 is a real measurement, not a
  generator/extractor collusion.
- Payload prose deliberately avoids dotted usernames and other token shapes
  that would create accidental indicators; the only IoCs in a payload are the
  registered ones (plus two documented near-miss version strings that a
  correct extractor must REJECT).
- Adversarial cases (70): benign alerts dressed in scary language (threat
  digest with documentation-range IPs, authorized pentest, ransomware
  helpdesk scare) and malicious alerts dressed in bland language whose only
  tell is a threat-intel hit.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from packages.evals import pools

BASE_TIME = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
PENTEST_TIME = datetime(2026, 1, 14, 10, 30, tzinfo=UTC)
DATASET_PATH = Path(__file__).with_name("dataset.jsonl")
SEED = 20260115


class PB:
    """Payload builder that registers every embedded IoC."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.iocs: list[dict[str, str]] = []
        self._seen: set[tuple[str, str]] = set()

    def _reg(self, type_: str, value: str) -> None:
        key = (type_, value)
        if key not in self._seen:
            self._seen.add(key)
            self.iocs.append({"type": type_, "value": value})

    def add(self, text: str) -> PB:
        self.parts.append(text)
        return self

    def ip(self, ip: str) -> PB:
        self.parts.append(ip)
        self._reg("ipv4", ip)
        return self

    def domain(self, domain: str) -> PB:
        self.parts.append(domain)
        self._reg("domain", domain)
        return self

    def url(self, host: str, path: str, scheme: str = "https", defanged: bool = False) -> PB:
        if defanged:
            raw = f"hxxp{'s' if scheme == 'https' else ''}://{host.replace('.', '[.]')}{path}"
        else:
            raw = f"{scheme}://{host}{path}"
        self.parts.append(raw)
        self._reg("url", f"{scheme}://{host}{path}")
        self._reg("ipv4" if host[0].isdigit() else "domain", host)
        return self

    def sha256(self, digest: str) -> PB:
        self.parts.append(digest)
        self._reg("sha256", digest)
        return self

    def file(self, name: str) -> PB:
        self._reg("file", name.lower())
        return self

    def cve(self, cve: str) -> PB:
        self.parts.append(cve)
        self._reg("cve", cve.lower())
        return self

    def text(self) -> str:
        return " ".join(self.parts)


def _ws_ip(host: str) -> str:
    n = int(host.split("-")[1])
    return f"10.13.7.{10 + (n % 80)}"


def _rec(
    pb: PB,
    *,
    source: str,
    sensor_id: str,
    severity: str,
    title: str,
    disposition: str,
    scenario: str,
    adversarial: bool = False,
    src: str | None = None,
    dst: str | None = None,
    host: str | None = None,
    user: str | None = None,
    event_time: datetime | None = None,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "source": source,
        "sensor_id": sensor_id,
        "severity": severity,
        "title": title,
        "payload": pb.text(),
        "src_ip": src,
        "dst_ip": dst,
        "host": host,
        "user": user,
        "event_time": event_time.isoformat() if event_time else None,
        "expected_disposition": disposition,
        "expected_iocs": pb.iocs,
        "scenario": scenario,
        "adversarial": adversarial,
        "notes": notes,
    }


def pick(rng: random.Random, seq: list[str]) -> str:
    return seq[rng.randrange(len(seq))]


# ---------------------------------------------------------------- benign -----

CVES = ["CVE-2024-3400", "CVE-2023-4966", "CVE-2024-21893", "CVE-2023-46805", "CVE-2024-47575"]
CDN_IPS = ["142.250.80.4", "151.101.1.69", "140.82.121.4", "104.244.42.193", "172.217.14.206"]


def s_vuln_scan(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS + pools.SERVERS)
    ip = _ws_ip(host) if host.startswith("WS") else f"10.13.4.{20 + int(host[-1])}"
    pb = PB()
    pb.add("Vulnerability scan completed by scanner").ip(pools.SCANNER_IP)
    pb.add(f"against host {host} (").ip(ip).add("). Finding:")
    pb.cve(pick(rng, CVES))
    pb.add(
        f"present on an audited service. Scan profile: full audit, credentialed. "
        f"Scanner signature verified. {rng.randint(40, 300)} checks executed."
    )
    return _rec(
        pb,
        source="vuln_scanner",
        sensor_id="nessus-01",
        severity="medium",
        title="Scheduled vulnerability scan completed",
        disposition="benign",
        scenario="vuln_scan",
        src=pools.SCANNER_IP,
        host=host,
    )


def s_failed_logins(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    user = pick(rng, pools.USERS)
    pb = PB()
    pb.add(f"A domain user failed to log on to {host} (").ip(ip).add(
        f") {rng.randint(3, 5)} times within 10 minutes at the local console. "
        "No successful logon followed. The account is not locked."
    )
    return _rec(
        pb,
        source="identity",
        sensor_id="ad-domain-01",
        severity="medium",
        title="Repeated failed logons at workstation console",
        disposition="benign",
        scenario="failed_logins",
        src=ip,
        host=host,
        user=user,
    )


def s_software_update(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    domain = pick(rng, pools.GOOD_DOMAINS)
    digest = pick(rng, pools.GOOD_SHA256)
    pb = PB()
    pb.add(f"Software update installed on {host} (").ip(ip).add("). Package source:")
    pb.url(domain, f"/updates/agent-{rng.randint(2, 9)}.bin")
    pb.add("Package SHA256:").sha256(digest)
    pb.add("Signature verified against the vendor certificate.")
    if rng.random() < 0.5:
        pb.add("Agent version 10.4.2.9182 recorded by the sensor.")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="low",
        title="Vendor software update installed",
        disposition="benign",
        scenario="software_update",
        dst=None,
        host=host,
    )


def s_backup_traffic(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, ["SRV-2001", "SRV-2003", *pools.WORKSTATIONS[:6]])
    ip = "10.13.4.21" if host == "SRV-2001" else _ws_ip(host)
    pb = PB()
    pb.add(f"Nightly backup from {host} (").ip(ip).add(") to backup target")
    pb.ip(pools.BACKUP_SERVER_IP)
    pb.add(
        f"transferred {rng.randint(40, 900)} GB inside the 02:00 maintenance window. "
        "Agent process backup_agent.exe reported success."
    )
    pb.file("backup_agent.exe")
    return _rec(
        pb,
        source="network",
        sensor_id="ndf-core",
        severity="medium",
        title="Large internal transfer to backup server",
        disposition="benign",
        scenario="backup_traffic",
        src=ip,
        dst=pools.BACKUP_SERVER_IP,
        host=host,
    )


def s_dns_popular(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(f"DNS query from {host} (").ip(ip).add(") for")
    pb.domain(pick(rng, pools.POPULAR_DOMAINS))
    pb.add("resolved to").ip(pick(rng, CDN_IPS)).add(". Query type A, response code NOERROR.")
    return _rec(
        pb,
        source="dns",
        sensor_id="dns-gw-01",
        severity="low",
        title="DNS resolution for popular domain",
        disposition="benign",
        scenario="dns_popular",
        host=host,
    )


def s_av_update_fail(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(f"Antivirus definition update failed on {host} (").ip(ip).add("). Vendor endpoint")
    pb.domain("definitions.vendor-av.net")
    pb.add(
        "timed out after 30 seconds. The avupdate.exe service will retry at the next "
        "interval. Definitions are 1 day old."
    )
    pb.file("avupdate.exe")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="low",
        title="AV definition update failed (timeout)",
        disposition="benign",
        scenario="av_update_fail",
        host=host,
    )


def s_admin_tasks(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.SERVERS + pools.WORKSTATIONS)
    ip = "10.13.4.22" if host == "SRV-2003" else _ws_ip(host)
    script = pick(rng, ["inventory.ps1", "diskcheck.ps1", "patchreport.ps1"])
    pb = PB()
    pb.add(f"An IT administrator ran a signed maintenance script on {host} (").ip(ip).add(
        f") from the IT subnet. Command: powershell -File \\\\fileserver\\scripts\\{script} "
        "The script is allowlisted by hash in the change calendar."
    )
    pb.file(script)
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="medium",
        title="Administrator maintenance script executed",
        disposition="benign",
        scenario="admin_tasks",
        host=host,
        user="it.admin",
    )


def s_vpn_travel(rng: random.Random) -> dict[str, Any]:
    user = pick(rng, pools.USERS)
    pb = PB()
    pb.add("Remote access logon from branch office egress").ip(pools.OFFICE_EGRESS_IP)
    pb.add(
        "to the VPN gateway. MFA push approved on a registered device. "
        "The egress address belongs to the Denver branch office."
    )
    return _rec(
        pb,
        source="identity",
        sensor_id="vpn-gw-01",
        severity="low",
        title="VPN logon from branch office egress",
        disposition="benign",
        scenario="vpn_travel",
        src=pools.OFFICE_EGRESS_IP,
        user=user,
    )


def s_usb_device(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(f"Removable storage device mounted on {host} (").ip(ip).add(
        f"). USB mass storage, serial USB-{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}. "
        "Policy mounted it read-only. No executable files were present on the device."
    )
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="low",
        title="USB storage device mounted read-only",
        disposition="benign",
        scenario="usb_device",
        host=host,
    )


def s_cert_expiry(rng: random.Random) -> dict[str, Any]:
    pb = PB()
    pb.add("TLS certificate for an internal service endpoint (").ip("10.13.4.30").add(
        f") expires in {rng.randint(7, 21)} days. Renewal is owned by the platform team. "
        "This is a hygiene notice, not an intrusion signal."
    )
    return _rec(
        pb,
        source="infra_monitor",
        sensor_id="cert-watch",
        severity="low",
        title="Internal TLS certificate expiring soon",
        disposition="benign",
        scenario="cert_expiry",
    )


def s_patch_tuesday(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS + pools.SERVERS)
    ip = _ws_ip(host) if host.startswith("WS") else "10.13.4.22"
    pb = PB()
    pb.add(f"Monthly patch cycle rebooted {host} (").ip(ip).add(
        f") at 03:{rng.randint(10, 59)}. {rng.randint(6, 22)} updates were downloaded from"
    )
    pb.domain("update.microsoft.com")
    pb.add("and installed successfully. No failed patches.")
    return _rec(
        pb,
        source="system",
        sensor_id="wsus-01",
        severity="low",
        title="Scheduled patch reboot completed",
        disposition="benign",
        scenario="patch_tuesday",
        host=host,
    )


def s_db_maintenance(rng: random.Random) -> dict[str, Any]:
    pb = PB()
    pb.add("Scheduled index maintenance on SRV-2003 (").ip("10.13.4.22").add(
        f") ran {rng.randint(31, 58)} minutes, above the soft threshold of 30 minutes. "
        "No errors were logged. The job is owned by the database service account."
    )
    return _rec(
        pb,
        source="infra_monitor",
        sensor_id="db-watch",
        severity="medium",
        title="Database maintenance job exceeded soft duration threshold",
        disposition="benign",
        scenario="db_maintenance",
        host="SRV-2003",
    )


def s_threat_digest(rng: random.Random) -> dict[str, Any]:
    doc_ip = pick(rng, pools.DOC_IPS)
    pb = PB()
    pb.add(
        "Weekly threat-intelligence digest received from the industry sharing group. "
        "In review: a phishing wave impersonating payroll portals was blocked at "
        "regional gateways. A historical indicator from the published report,"
    )
    pb.ip(doc_ip)
    pb.add(
        "(a documentation-range address used in the report) is no longer active. "
        "The write-up references the defunct illustration domain"
    )
    pb.domain("example-c2.invalid")
    pb.add("for training purposes. No local host communicated with any digest indicator.")
    return _rec(
        pb,
        source="email_gateway",
        sensor_id="mail-gw-02",
        severity="info",
        title="Weekly threat-intelligence digest received",
        disposition="benign",
        scenario="threat_digest",
        adversarial=True,
        notes="Scary content, zero local exposure; indicators are documentation-range / .invalid.",
    )


def s_pentest(rng: random.Random) -> dict[str, Any]:
    pb = PB()
    pb.add(
        f"Authorized red-team exercise {pools.PENTEST_TICKET}: simulated credential-access "
        f"tooling was executed on {pools.PENTEST_HOST} ("
    )
    pb.ip("10.13.7.41")
    pb.add(
        ") by the assessment team inside the approved engagement window recorded in the "
        "pentest calendar. EDR telemetry was collected for detection review."
    )
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="high",
        title="Simulated credential-access tooling on workstation",
        disposition="benign",
        scenario="pentest",
        adversarial=True,
        host=pools.PENTEST_HOST,
        event_time=PENTEST_TIME + timedelta(minutes=rng.randint(0, 240)),
        notes="Real attack tooling, but inside an authorized engagement window.",
    )


def s_helpdesk_scary(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(
        "User-reported incident: an employee reports a full-screen message claiming the "
        "workstation is encrypted and demanding payment in gift cards. Hands-on triage "
        f"found a browser pop-up from a mistyped search result on {host} ("
    )
    pb.ip(ip)
    pb.add(
        "). No files were modified and EDR shows no encryption activity. "
        "Browser cache cleared and the user was coached on pop-up scams."
    )
    return _rec(
        pb,
        source="helpdesk",
        sensor_id="itsm-01",
        severity="medium",
        title="User reports ransomware message on screen",
        disposition="benign",
        scenario="helpdesk_scary",
        adversarial=True,
        host=host,
        notes="A tech-support scam pop-up; language is alarming, evidence is empty.",
    )


# -------------------------------------------------------------- malicious -----


def s_c2_beacon(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    bad = pick(rng, pools.BAD_IPS)
    pb = PB()
    pb.add(f"Host {host} (").ip(ip).add(") is beaconing to")
    pb.ip(bad)
    pb.add(
        f"on port 443 at regular {pick(rng, ['60', '120', '300'])} second intervals. "
        f"{rng.randint(90, 400)} connections in the last 4 hours, each under 400 bytes. "
        "The destination has no business justification in the asset record."
    )
    return _rec(
        pb,
        source="firewall",
        sensor_id="fw-edge-01",
        severity="medium",
        title="Periodic beaconing to rare external address",
        disposition="malicious",
        scenario="c2_beacon",
        src=ip,
        dst=bad,
        host=host,
    )


def s_malware_hash(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    digest = pick(rng, pools.BAD_SHA256)
    pb = PB()
    pb.add(f"Process executed on {host} (").ip(ip).add(
        ") by an interactive user. Image: C:\\Users\\Public\\update.exe SHA256:"
    )
    pb.sha256(digest)
    pb.add("The file was written 3 minutes earlier by a browser download.")
    pb.file("update.exe")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="high",
        title="Unknown binary executed from public folder",
        disposition="malicious",
        scenario="malware_hash",
        host=host,
    )


def s_phishing_click(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    domain = pick(rng, pools.BAD_DOMAINS)
    pb = PB()
    pb.add("A user clicked a link in a message with subject Quarterly bonus schedule. URL:")
    pb.url(domain, "/login", defanged=rng.random() < 0.3)
    pb.add(f"loaded in the browser on {host} (")
    pb.ip(ip).add("). The page requested mailbox credentials.")
    return _rec(
        pb,
        source="proxy",
        sensor_id="proxy-01",
        severity="medium",
        title="User clicked phishing link",
        disposition="malicious",
        scenario="phishing_click",
        host=host,
    )


def s_ps_download(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    bad = pick(rng, pools.UNKNOWN_BAD_IPS)
    pb = PB()
    pb.add(f"PowerShell executed on {host} (").ip(ip).add(
        ") with an encoded command, command line length 1,842 characters. "
        "Decoded content includes (New-Object Net.WebClient).DownloadString('"
    )
    pb.url(bad, "/payload.ps1", scheme="http")
    pb.add("'). The parent process was a macro-enabled spreadsheet.")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="high",
        title="PowerShell download cradle from external address",
        disposition="malicious",
        scenario="ps_download",
        host=host,
        notes="Destination IP is NOT in the intel feed; behavior must catch this.",
    )


def s_brute_success(rng: random.Random) -> dict[str, Any]:
    bad = pick(rng, pools.BAD_IPS)
    pb = PB()
    pb.add(f"{rng.randint(120, 900)} failed logons for an administrative account from")
    pb.ip(bad)
    pb.add(
        "were followed by a successful logon. The source geolocates outside the "
        "operating region. Target host: SRV-2001 ("
    )
    pb.ip("10.13.4.21").add(").")
    return _rec(
        pb,
        source="identity",
        sensor_id="ad-domain-01",
        severity="high",
        title="Brute force followed by successful administrative logon",
        disposition="malicious",
        scenario="brute_success",
        src=bad,
        host="SRV-2001",
    )


def s_ransomware(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, [*pools.WORKSTATIONS, "SRV-2001"])
    ip = _ws_ip(host) if host.startswith("WS") else "10.13.4.21"
    digest = pick(rng, pools.BAD_SHA256)
    pb = PB()
    pb.add(f"Multiple files on {host} (").ip(ip).add(
        ") were renamed with a .locked extension within 2 minutes, and a recovery note "
        "file was dropped in three directories. Encryptor sample SHA256:"
    )
    pb.sha256(digest)
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="critical",
        title="Mass file renaming with recovery note",
        disposition="malicious",
        scenario="ransomware",
        host=host,
    )


def s_dns_tunnel(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    domain = pick(rng, pools.BAD_DOMAINS)
    label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    pb = PB()
    pb.add(f"DNS queries from {host} (").ip(ip).add(") to")
    pb.domain(f"{label}.{domain}")
    pb.add(
        "show unusually long labels (average 48 characters) and high volume "
        f"({rng.randint(800, 2400)} queries in 10 minutes), consistent with data "
        "staging over DNS."
    )
    return _rec(
        pb,
        source="dns",
        sensor_id="dns-gw-01",
        severity="medium",
        title="High-volume long-label DNS queries to one domain",
        disposition="malicious",
        scenario="dns_tunnel",
        host=host,
    )


def s_adv_stealth(rng: random.Random) -> dict[str, Any]:
    form = rng.randrange(4)
    if form == 0:
        bad = pick(rng, pools.BAD_IPS)
        pb = PB()
        pb.add("Successful logon for a service account from")
        pb.ip(bad)
        pb.add("to the VPN gateway (")
        pb.ip("10.13.1.1").add("). MFA was satisfied by a previously registered token.")
        return _rec(
            pb,
            source="identity",
            sensor_id="vpn-gw-01",
            severity="info",
            title="Successful service-account logon",
            disposition="malicious",
            scenario="adv_stealth_login",
            adversarial=True,
            src=bad,
            notes="Bland informational logon; only the intel hit on the source reveals it.",
        )
    if form == 1:
        host = pick(rng, pools.WORKSTATIONS)
        ip = _ws_ip(host)
        domain = pick(rng, pools.BAD_DOMAINS)
        pb = PB()
        pb.add(f"DNS query from {host} (").ip(ip).add(") for")
        pb.domain(domain)
        pb.add("was allowed by policy. Single query, one record returned.")
        return _rec(
            pb,
            source="dns",
            sensor_id="dns-gw-01",
            severity="low",
            title="DNS query allowed",
            disposition="malicious",
            scenario="adv_stealth_dns",
            adversarial=True,
            host=host,
            notes="One quiet query to a known-bad domain.",
        )
    if form == 2:
        host = pick(rng, pools.WORKSTATIONS)
        ip = _ws_ip(host)
        digest = pick(rng, pools.BAD_SHA256)
        pb = PB()
        pb.add(f"Software installation completed on {host} (").ip(ip).add(
            "). Package: C:\\Temp\\driverpack.exe SHA256:"
        )
        pb.sha256(digest)
        pb.add("The installer exited with code 0.")
        pb.file("driverpack.exe")
        return _rec(
            pb,
            source="edr",
            sensor_id="edr-fleet",
            severity="low",
            title="Software installation completed",
            disposition="malicious",
            scenario="adv_stealth_install",
            adversarial=True,
            host=host,
            notes="Routine-looking install of a known-malware hash.",
        )
    bad = pick(rng, pools.BAD_IPS)
    pb = PB()
    pb.add("Scheduled data transfer from SRV-2001 (")
    pb.ip("10.13.4.21").add(") to")
    pb.ip(bad)
    pb.add(
        f"completed: {rng.randint(1, 4)}.{rng.randint(1, 9)} GB in 18 minutes. "
        "The job reported success."
    )
    return _rec(
        pb,
        source="network",
        sensor_id="ndf-core",
        severity="info",
        title="Scheduled data transfer completed",
        disposition="malicious",
        scenario="adv_stealth_exfil",
        adversarial=True,
        src="10.13.4.21",
        dst=bad,
        host="SRV-2001",
        notes="Exfiltration wearing a backup costume; destination is a known-bad address.",
    )


# -------------------------------------------------------------- ambiguous -----


def s_amb_enc(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(f"PowerShell executed on {host} (").ip(ip).add(
        ") with an encoded command: powershell.exe -enc SQBFAFgA (964 characters total). "
        "The decoded script could not be retrieved by the sensor, and no network "
        "connection followed within the observation window."
    )
    pb.file("powershell.exe")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="medium",
        title="Encoded PowerShell command, content unavailable",
        disposition="needs_human",
        scenario="amb_enc",
        host=host,
        notes="Encoded command with no observable payload: genuinely ambiguous.",
    )


def s_amb_rare_hash(rng: random.Random) -> dict[str, Any]:
    digest = pick(rng, pools.UNKNOWN_SHA256)
    pb = PB()
    pb.add("Unrecognized binary executed on SRV-2003 (")
    pb.ip("10.13.4.22").add("). Image: C:\\Tools\\diaghelper.exe SHA256:")
    pb.sha256(digest)
    pb.add("The binary is unsigned and has not been seen on any other host in 90 days.")
    pb.file("diaghelper.exe")
    return _rec(
        pb,
        source="edr",
        sensor_id="edr-fleet",
        severity="medium",
        title="Unrecognized unsigned binary executed on server",
        disposition="needs_human",
        scenario="amb_rare_hash",
        host="SRV-2003",
        notes="Unknown hash on a high-value server: escalate, do not guess.",
    )


def s_amb_dga(rng: random.Random) -> dict[str, Any]:
    host = pick(rng, pools.WORKSTATIONS)
    ip = _ws_ip(host)
    pb = PB()
    pb.add(f"DNS query from {host} (").ip(ip).add(") for")
    pb.domain(pick(rng, pools.DGA_DOMAINS))
    pb.add(
        "was allowed. The domain was registered 2 days ago according to passive DNS. "
        "No host has queried this domain before."
    )
    return _rec(
        pb,
        source="dns",
        sensor_id="dns-gw-01",
        severity="low",
        title="Query to newly registered algorithm-like domain",
        disposition="needs_human",
        scenario="amb_dga",
        host=host,
        notes="DGA-shaped and newly registered, but absent from every feed.",
    )


PLAN: list[tuple[Callable[[random.Random], dict[str, Any]], int]] = [
    # benign — 315
    (s_vuln_scan, 30),
    (s_failed_logins, 30),
    (s_software_update, 30),
    (s_backup_traffic, 25),
    (s_dns_popular, 25),
    (s_av_update_fail, 20),
    (s_admin_tasks, 25),
    (s_vpn_travel, 15),
    (s_usb_device, 15),
    (s_cert_expiry, 15),
    (s_patch_tuesday, 20),
    (s_db_maintenance, 15),
    (s_threat_digest, 25),  # adversarial benign
    (s_pentest, 20),  # adversarial benign
    (s_helpdesk_scary, 5),  # adversarial benign
    # malicious — 165
    (s_c2_beacon, 30),
    (s_malware_hash, 25),
    (s_phishing_click, 20),
    (s_ps_download, 20),
    (s_brute_success, 20),
    (s_ransomware, 15),
    (s_dns_tunnel, 15),
    (s_adv_stealth, 20),  # adversarial malicious
    # ambiguous — 20
    (s_amb_enc, 8),
    (s_amb_rare_hash, 7),
    (s_amb_dga, 5),
]


def build_dataset() -> list[dict[str, Any]]:
    rng = random.Random(SEED)
    records: list[dict[str, Any]] = []
    n = 0
    for builder, count in PLAN:
        for _ in range(count):
            n += 1
            rec = builder(rng)
            event_time = (
                rec["event_time"]
                or (BASE_TIME + timedelta(minutes=rng.randint(0, 4000))).isoformat()
            )
            ingest = datetime.fromisoformat(event_time) + timedelta(seconds=rng.randint(5, 180))
            rec["event_time"] = event_time
            rec["ingest_time"] = ingest.isoformat()
            rec["id"] = f"g-{n:04d}"
            records.append(rec)
    rng.shuffle(records)
    # Re-number after shuffle so IDs carry no label information.
    for i, rec in enumerate(records, start=1):
        rec["id"] = f"g-{i:04d}"
    return records


def main() -> int:
    records = build_dataset()
    with DATASET_PATH.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    from collections import Counter

    labels = Counter(r["expected_disposition"] for r in records)
    adversarial = sum(1 for r in records if r["adversarial"])
    print(f"wrote {len(records)} golden alerts to {DATASET_PATH}")
    print(f"labels: {dict(labels)}")
    print(f"adversarial cases: {adversarial}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
