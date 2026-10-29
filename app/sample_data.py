"""Sample data generator for IdentityShield.
Generates realistic CloudTrail and Okta sample logs with all 5 attack scenarios.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

from app.config import SAMPLE_DIR

log = logging.getLogger(__name__)

INDIAN_CITIES = [
    {"city": "Bengaluru", "country": "India", "lat": 12.9716, "lon": 77.5946, "asn": "AS55836"},
    {"city": "Mysuru", "country": "India", "lat": 12.2958, "lon": 76.6394, "asn": "AS55836"},
    {"city": "Chennai", "country": "India", "lat": 13.0827, "lon": 80.2707, "asn": "AS45609"},
    {"city": "Hyderabad", "country": "India", "lat": 17.3850, "lon": 78.4867, "asn": "AS45609"},
]

USER_NAMES = [
    "anita.rao", "dev.kumar", "meera.n", "arjun.sharma", "priya.patel",
    "rahul.verma", "sneha.reddy", "vikram.singh", "neha.gupta", "rohit.joshi",
    "kavita.nair", "suresh.menon", "pooja.iyer", "amit.shah", "deepa.bose",
    "manoj.mishra", "swati.deshmukh", "sanjay.rao", "ananya.sen", "svc-report"
]

ROUTINE_ACTIONS = [
    ("GetObject", "s3.amazonaws.com", "arn:aws:s3:::corp-data-lake/reports/daily.csv"),
    ("ListBuckets", "s3.amazonaws.com", None),
    ("DescribeInstances", "ec2.amazonaws.com", None),
    ("DescribeSecurityGroups", "ec2.amazonaws.com", None),
    ("GetCallerIdentity", "sts.amazonaws.com", None),
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate(out_dir: Path | str, days: int = 60) -> dict:
    random.seed(42)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    end_time = datetime(2026, 10, 28, 18, 0, 0, tzinfo=timezone.utc)
    start_time = end_time - timedelta(days=days)

    metadata = []
    for u in USER_NAMES:
        if u == "svc-report":
            priv = 4
            groups = ["ServiceAccounts", "ReportingAdmin"]
        elif u in ("dev.kumar", "anita.rao"):
            priv = 3
            groups = ["Engineering", "DevOps"]
        else:
            priv = 1
            groups = ["Employees"]
        metadata.append({
            "identity_id": u,
            "email": f"{u}@corp.example",
            "privilege_level": priv,
            "groups": groups,
        })

    cloudtrail_records = []
    okta_records = []
    counts = {
        "benign": 0,
        "impossible_travel": 0,
        "dormant_reactivation": 0,
        "privilege_escalation": 0,
        "unusual_api": 0,
        "token_abuse": 0,
    }

    ct_id_seq = 1000
    okta_id_seq = 1000

    def next_ct_id():
        nonlocal ct_id_seq
        ct_id_seq += 1
        return f"ct-{ct_id_seq}"

    def next_okta_id():
        nonlocal okta_id_seq
        okta_id_seq += 1
        return f"okta-{okta_id_seq}"

    # Generate baseline normal activity
    current_day = start_time.date()
    end_day = end_time.date()

    user_ips = {
        u: f"203.0.113.{idx + 10}" for idx, u in enumerate(USER_NAMES)
    }

    while current_day <= end_day:
        weekday = current_day.weekday()
        is_attack_day = current_day >= (end_day - timedelta(days=2))

        # weekdays only for normal activity
        if weekday < 5:
            for u in USER_NAMES:
                # svc-report is dormant for 47 days before the attack window
                if u == "svc-report":
                    days_from_start = (current_day - start_time.date()).days
                    if days_from_start > 3 and not is_attack_day:
                        continue  # silent for ~47 days!

                # Routine login
                login_hour = random.randint(9, 11) - 5  # IST (UTC+5:30) approx ~ 03:30 to 05:30 UTC
                login_minute = random.randint(0, 59)
                t_login = datetime(current_day.year, current_day.month, current_day.day,
                                   login_hour, login_minute, random.randint(0, 59), tzinfo=timezone.utc)
                if t_login > end_time:
                    continue

                session_token = f"sess-{u}-{current_day.strftime('%Y%m%d')}"
                ak_id = f"AKIA{u.replace('.', '').replace('-', '').upper()[:8]}{current_day.day:02d}"
                loc = random.choice(INDIAN_CITIES)
                ip = user_ips[u]

                # Okta login
                okta_records.append({
                    "uuid": next_okta_id(),
                    "published": _iso(t_login),
                    "eventType": "user.session.start",
                    "actor": {"id": f"usr-{u}", "alternateId": f"{u}@corp.example"},
                    "outcome": {"result": "SUCCESS"},
                    "client": {
                        "ipAddress": ip,
                        "userAgent": {"rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
                        "geographicalContext": {
                            "country": loc["country"],
                            "city": loc["city"],
                            "geolocation": {"lat": loc["lat"], "lon": loc["lon"]},
                        },
                    },
                    "authenticationContext": {"externalSessionId": session_token},
                    "securityContext": {"asNumber": int(loc["asn"].replace("AS", ""))},
                    "label": "benign",
                })
                counts["benign"] += 1

                # 2-4 AWS CloudTrail calls
                n_calls = random.randint(2, 4)
                cur_t = t_login
                for _ in range(n_calls):
                    cur_t += timedelta(minutes=random.randint(15, 60))
                    if cur_t > end_time:
                        break
                    action_name, src, res = random.choice(ROUTINE_ACTIONS)
                    cloudtrail_records.append({
                        "eventID": next_ct_id(),
                        "eventTime": _iso(cur_t),
                        "eventName": action_name,
                        "eventSource": src,
                        "awsRegion": "ap-south-1",
                        "sourceIPAddress": ip,
                        "userAgent": "aws-sdk-go/v2",
                        "userIdentity": {
                            "type": "IAMUser",
                            "userName": u,
                            "arn": f"arn:aws:iam::123456789012:user/{u}",
                            "accessKeyId": ak_id,
                        },
                        "requestParameters": {"bucketName": "corp-data-lake"} if "s3" in src else {},
                        "resources": [{"ARN": res}] if res else [],
                        "errorCode": None,
                        "label": "benign",
                    })
                    counts["benign"] += 1

        current_day += timedelta(days=1)

    # ----------------- Attack Scenarios in the last 2 days -----------------
    attack_date = end_time - timedelta(hours=6)

    # S1: Impossible Travel (anita.rao)
    # Login Bengaluru at t, then login Frankfurt 30 min later (~7400 km away)
    t_s1_1 = attack_date - timedelta(hours=4)
    t_s1_2 = t_s1_1 + timedelta(minutes=30)
    bengaluru = INDIAN_CITIES[0]

    okta_records.append({
        "uuid": next_okta_id(),
        "published": _iso(t_s1_1),
        "eventType": "user.session.start",
        "actor": {"id": "usr-anita.rao", "alternateId": "anita.rao@corp.example"},
        "outcome": {"result": "SUCCESS"},
        "client": {
            "ipAddress": "203.0.113.10",
            "userAgent": {"rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            "geographicalContext": {
                "country": bengaluru["country"],
                "city": bengaluru["city"],
                "geolocation": {"lat": bengaluru["lat"], "lon": bengaluru["lon"]},
            },
        },
        "authenticationContext": {"externalSessionId": "sess-anita-blr"},
        "securityContext": {"asNumber": 55836},
        "label": "impossible_travel",
    })
    counts["impossible_travel"] += 1

    okta_records.append({
        "uuid": next_okta_id(),
        "published": _iso(t_s1_2),
        "eventType": "user.session.start",
        "actor": {"id": "usr-anita.rao", "alternateId": "anita.rao@corp.example"},
        "outcome": {"result": "SUCCESS"},
        "client": {
            "ipAddress": "194.12.45.67",
            "userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            "geographicalContext": {
                "country": "Germany",
                "city": "Frankfurt",
                "geolocation": {"lat": 50.1109, "lon": 8.6821},
            },
        },
        "authenticationContext": {"externalSessionId": "sess-anita-fra"},
        "securityContext": {"asNumber": 3320},
        "label": "impossible_travel",
    })
    counts["impossible_travel"] += 1

    # S2 & S3: Dormant reactivation and Privilege escalation chain (svc-report)
    # svc-report awakens after 47 days dormancy
    t_s2 = attack_date - timedelta(hours=3)
    okta_records.append({
        "uuid": next_okta_id(),
        "published": _iso(t_s2),
        "eventType": "user.session.start",
        "actor": {"id": "usr-svc-report", "alternateId": "svc-report@corp.example"},
        "outcome": {"result": "SUCCESS"},
        "client": {
            "ipAddress": "198.51.100.99",
            "userAgent": {"rawUserAgent": "curl/7.88.1"},
            "geographicalContext": {
                "country": "India",
                "city": "Bengaluru",
                "geolocation": {"lat": 12.9716, "lon": 77.5946},
            },
        },
        "authenticationContext": {"externalSessionId": "sess-svc-escalation"},
        "securityContext": {"asNumber": 55836},
        "label": "dormant_reactivation",
    })
    counts["dormant_reactivation"] += 1

    # Privilege escalation sequence within 15 minutes:
    # CreateAccessKey -> AttachUserPolicy -> AssumeRole -> GetSecretValue
    svc_chain = [
        ("CreateAccessKey", "iam.amazonaws.com", {"userName": "svc-report"}, None, 1),
        ("AttachUserPolicy", "iam.amazonaws.com", {
            "userName": "svc-report",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }, None, 4),
        ("AssumeRole", "sts.amazonaws.com", {
            "roleArn": "arn:aws:iam::123456789012:role/AdminRole",
            "roleSessionName": "svc-admin-session"
        }, None, 7),
        ("GetSecretValue", "secretsmanager.amazonaws.com", {
            "secretId": "prod/db/master-credentials"
        }, "arn:aws:secretsmanager:ap-south-1:123456789012:secret:prod/db/master-credentials", 11),
    ]

    for action, src, params, res, offset_min in svc_chain:
        t_call = t_s2 + timedelta(minutes=offset_min)
        cloudtrail_records.append({
            "eventID": next_ct_id(),
            "eventTime": _iso(t_call),
            "eventName": action,
            "eventSource": src,
            "awsRegion": "ap-south-1",
            "sourceIPAddress": "198.51.100.99",
            "userAgent": "aws-cli/2.13.5",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "svc-report",
                "arn": "arn:aws:iam::123456789012:user/svc-report",
                "accessKeyId": "AKIAESCALATIONKEY01",
            },
            "requestParameters": params,
            "resources": [{"ARN": res}] if res else [],
            "errorCode": None,
            "label": "privilege_escalation",
        })
        counts["privilege_escalation"] += 1

    # S4: Unusual API (dev.kumar)
    # StopLogging in a never-used region (e.g. ap-southeast-2)
    t_s4 = attack_date - timedelta(hours=2)
    cloudtrail_records.append({
        "eventID": next_ct_id(),
        "eventTime": _iso(t_s4),
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "ap-southeast-2",  # new region never used before!
        "sourceIPAddress": user_ips["dev.kumar"],
        "userAgent": "Boto3/1.28.3",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "dev.kumar",
            "arn": "arn:aws:iam::123456789012:user/dev.kumar",
            "accessKeyId": "AKIADEVKUMARKEY99",
        },
        "requestParameters": {"name": "prod-audit-trail"},
        "resources": [{"ARN": "arn:aws:cloudtrail:ap-southeast-2:123456789012:trail/prod-audit-trail"}],
        "errorCode": None,
        "label": "unusual_api",
    })
    counts["unusual_api"] += 1

    # S5: Token / session abuse (meera.n)
    # Same accessKeyId used from India and Brazil within 3 minutes,
    # and use after an Okta user.session.end
    t_s5_1 = attack_date - timedelta(hours=1)
    t_s5_2 = t_s5_1 + timedelta(minutes=2)
    t_s5_logout = t_s5_2 + timedelta(minutes=5)
    t_s5_after = t_s5_logout + timedelta(minutes=10)

    # First call from India
    cloudtrail_records.append({
        "eventID": next_ct_id(),
        "eventTime": _iso(t_s5_1),
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "203.0.113.12",  # India IP
        "userAgent": "aws-sdk-js/v3",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "meera.n",
            "arn": "arn:aws:iam::123456789012:user/meera.n",
            "accessKeyId": "AKIAMERRATOKEN77",
        },
        "requestParameters": {},
        "resources": [],
        "errorCode": None,
        "label": "token_abuse",
    })
    counts["token_abuse"] += 1

    # Concurrent call within 2 minutes from Brazil
    cloudtrail_records.append({
        "eventID": next_ct_id(),
        "eventTime": _iso(t_s5_2),
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "sa-east-1",
        "sourceIPAddress": "177.18.90.12",  # Brazil IP
        "userAgent": "python-requests/2.31.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "meera.n",
            "arn": "arn:aws:iam::123456789012:user/meera.n",
            "accessKeyId": "AKIAMERRATOKEN77",  # same token!
        },
        "requestParameters": {"bucketName": "finance-sensitive-export"},
        "resources": [{"ARN": "arn:aws:s3:::finance-sensitive-export/q3.xlsx"}],
        "errorCode": None,
        "label": "token_abuse",
    })
    counts["token_abuse"] += 1

    # Session end in Okta
    okta_records.append({
        "uuid": next_okta_id(),
        "published": _iso(t_s5_logout),
        "eventType": "user.session.end",
        "actor": {"id": "usr-meera.n", "alternateId": "meera.n@corp.example"},
        "outcome": {"result": "SUCCESS"},
        "client": {
            "ipAddress": "203.0.113.12",
            "userAgent": {"rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            "geographicalContext": {
                "country": "India",
                "city": "Bengaluru",
                "geolocation": {"lat": 12.9716, "lon": 77.5946},
            },
        },
        "authenticationContext": {"externalSessionId": "sess-meera-end"},
        "securityContext": {"asNumber": 55836},
        "label": "token_abuse",
    })
    counts["token_abuse"] += 1

    # Use after session end
    cloudtrail_records.append({
        "eventID": next_ct_id(),
        "eventTime": _iso(t_s5_after),
        "eventName": "ListBuckets",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "177.18.90.12",
        "userAgent": "python-requests/2.31.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "meera.n",
            "arn": "arn:aws:iam::123456789012:user/meera.n",
            "accessKeyId": "AKIAMERRATOKEN77",
        },
        "requestParameters": {},
        "resources": [],
        "errorCode": None,
        "label": "token_abuse",
    })
    counts["token_abuse"] += 1

    # Write files
    (out_path / "cloudtrail.json").write_text(
        json.dumps({"Records": cloudtrail_records}, indent=2), encoding="utf-8"
    )
    (out_path / "okta.json").write_text(
        json.dumps(okta_records, indent=2), encoding="utf-8"
    )
    (out_path / "metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    log.info("Generated sample data: %s", counts)
    return counts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = generate(SAMPLE_DIR)
    print("Sample generation complete:", res)
