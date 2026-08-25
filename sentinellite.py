import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


def load_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {
        "timestamp", "user", "source_ip", "event_type",
        "status", "failed_attempts", "bytes_out"
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("One or more timestamps could not be parsed.")

    df["failed_attempts"] = pd.to_numeric(df["failed_attempts"], errors="coerce").fillna(0)
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["hour"] = out["timestamp"].dt.hour
    out["off_hours"] = ((out["hour"] < 6) | (out["hour"] >= 22)).astype(int)
    out["login_failure"] = (out["status"].str.upper() == "FAIL").astype(int)
    out["external_ip"] = (~out["source_ip"].astype(str).str.startswith(("10.", "192.168.", "172.16."))).astype(int)
    return out


def score_anomalies(df: pd.DataFrame, contamination: float = 0.04) -> pd.DataFrame:
    features = df[
        ["failed_attempts", "bytes_out", "hour", "off_hours", "login_failure", "external_ip"]
    ].copy()

    model = IsolationForest(
        n_estimators=250,
        contamination=contamination,
        random_state=42
    )
    model.fit(features)

    scored = df.copy()
    scored["model_score"] = -model.decision_function(features)
    scored["model_anomaly"] = (model.predict(features) == -1).astype(int)

    # Human-readable rule flags make the results easier to interpret.
    scored["rule_flag"] = (
        (scored["failed_attempts"] >= 5)
        | (scored["bytes_out"] >= 250_000)
        | ((scored["external_ip"] == 1) & (scored["off_hours"] == 1))
    ).astype(int)

    scored["risk_score"] = (
        scored["model_score"].rank(pct=True) * 70
        + scored["rule_flag"] * 20
        + (scored["failed_attempts"].clip(0, 10) / 10) * 10
    ).clip(0, 100).round(1)

    scored["anomaly"] = ((scored["model_anomaly"] == 1) | (scored["rule_flag"] == 1)).astype(int)

    return scored.sort_values(
        ["anomaly", "risk_score"], ascending=[False, False]
    )


def build_summary(scored: pd.DataFrame) -> dict:
    flagged = scored[scored["anomaly"] == 1]
    return {
        "events_analyzed": int(len(scored)),
        "events_flagged": int(len(flagged)),
        "flag_rate_percent": round((len(flagged) / max(len(scored), 1)) * 100, 2),
        "highest_risk_score": float(flagged["risk_score"].max()) if len(flagged) else 0.0,
        "top_flagged_users": flagged["user"].value_counts().head(5).to_dict(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="SentinelLite: lightweight security log anomaly detector"
    )
    parser.add_argument("input", help="CSV security log file")
    parser.add_argument("--output", default="anomalies.csv", help="Output CSV path")
    parser.add_argument("--summary", default="summary.json", help="Summary JSON path")
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.04,
        help="Expected proportion of statistical anomalies (default: 0.04)"
    )
    args = parser.parse_args()

    df = engineer_features(load_logs(args.input))
    scored = score_anomalies(df, contamination=args.contamination)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(args.output, index=False)

    summary = build_summary(scored)
    Path(args.summary).write_text(json.dumps(summary, indent=2))

    print("\nSentinelLite analysis complete")
    print("-" * 34)
    print(f"Events analyzed : {summary['events_analyzed']}")
    print(f"Events flagged  : {summary['events_flagged']}")
    print(f"Flag rate       : {summary['flag_rate_percent']}%")
    print(f"Highest risk    : {summary['highest_risk_score']}")
    print(f"\nSaved: {args.output}")
    print(f"Saved: {args.summary}")

    cols = [
        "timestamp", "user", "source_ip", "event_type",
        "failed_attempts", "bytes_out", "risk_score"
    ]
    print("\nTop suspicious events:")
    print(scored[scored["anomaly"] == 1][cols].head(10).to_string(index=False))


if __name__ == "__main__":
    main()
