import pandas as pd
from sentinellite import engineer_features, score_anomalies


def test_feature_engineering():
    df = pd.DataFrame([{
        "timestamp": pd.Timestamp("2026-08-25 02:00:00"),
        "user": "admin",
        "source_ip": "8.8.8.8",
        "event_type": "login",
        "status": "FAIL",
        "failed_attempts": 7,
        "bytes_out": 1000,
    }])
    out = engineer_features(df)
    assert out.loc[0, "off_hours"] == 1
    assert out.loc[0, "login_failure"] == 1
    assert out.loc[0, "external_ip"] == 1


def test_scoring_returns_risk_score():
    rows = []
    for i in range(30):
        rows.append({
            "timestamp": pd.Timestamp("2026-08-25 12:00:00"),
            "user": "user",
            "source_ip": "10.0.0.10",
            "event_type": "login",
            "status": "SUCCESS",
            "failed_attempts": 0,
            "bytes_out": 10000 + i,
        })
    rows.append({
        "timestamp": pd.Timestamp("2026-08-25 02:00:00"),
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "login",
        "status": "FAIL",
        "failed_attempts": 15,
        "bytes_out": 500000,
    })

    df = engineer_features(pd.DataFrame(rows))
    scored = score_anomalies(df, contamination=0.05)

    assert "risk_score" in scored.columns
    assert scored["anomaly"].sum() >= 1
