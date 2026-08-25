from pathlib import Path

import pandas as pd
import streamlit as st

from sentinellite import load_logs, engineer_features, score_anomalies, build_summary


st.set_page_config(
    page_title="SentinelLite Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SentinelLite Security Dashboard")
st.caption(
    "Machine-learning-assisted security log triage using Isolation Forest "
    "and explainable security rules."
)

st.info(
    "SentinelLite prioritizes unusual events for human review. "
    "A flagged event does not automatically indicate malicious activity."
)

with st.sidebar:
    st.header("Analysis settings")
    contamination = st.slider(
        "Expected statistical anomaly rate",
        min_value=0.01,
        max_value=0.15,
        value=0.04,
        step=0.01,
        help="Controls the proportion of events Isolation Forest expects to be unusual.",
    )

    uploaded = st.file_uploader(
        "Upload a compatible CSV log",
        type=["csv"],
        help="Leave empty to use the included sample dataset.",
    )

if uploaded is not None:
    raw = pd.read_csv(uploaded)
    temp_path = Path("_uploaded_logs.csv")
    raw.to_csv(temp_path, index=False)
    df = load_logs(str(temp_path))
    temp_path.unlink(missing_ok=True)
    dataset_name = uploaded.name
else:
    df = load_logs("sample_logs.csv")
    dataset_name = "sample_logs.csv"

featured = engineer_features(df)
scored = score_anomalies(featured, contamination=contamination)
summary = build_summary(scored)
flagged = scored[scored["anomaly"] == 1].copy()

st.subheader(f"Analysis overview — {dataset_name}")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", f"{summary['events_analyzed']:,}")
m2.metric("Events flagged", f"{summary['events_flagged']:,}")
m3.metric("Flag rate", f"{summary['flag_rate_percent']:.2f}%")
m4.metric("Highest risk", f"{summary['highest_risk_score']:.1f}/100")

st.divider()

left, right = st.columns([1.4, 1])

with left:
    st.subheader("Highest-risk events")
    if flagged.empty:
        st.success("No events were flagged with the current settings.")
    else:
        top = flagged.head(10).copy()
        top["timestamp"] = pd.to_datetime(top["timestamp"])
        top["event_label"] = (
            top["timestamp"].dt.strftime("%H:%M")
            + " | "
            + top["user"].astype(str)
            + " | "
            + top["event_type"].astype(str)
            + " | "
            + top["source_ip"].astype(str)
        )
        chart_data = top.set_index("event_label")[["risk_score"]].sort_values("risk_score")
        st.bar_chart(chart_data, horizontal=True)

with right:
    st.subheader("Flagged event types")
    if flagged.empty:
        st.write("No flagged events.")
    else:
        type_counts = (
            flagged["event_type"]
            .value_counts()
            .rename_axis("event_type")
            .to_frame("count")
        )
        st.bar_chart(type_counts)

st.divider()
st.subheader("Analyst review queue")

display_cols = [
    "timestamp",
    "user",
    "source_ip",
    "event_type",
    "status",
    "failed_attempts",
    "bytes_out",
    "risk_score",
    "model_anomaly",
    "rule_flag",
]

if flagged.empty:
    st.write("No events currently require review.")
else:
    review = flagged[display_cols].copy()
    review["timestamp"] = review["timestamp"].astype(str)

    st.dataframe(
        review,
        use_container_width=True,
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk score",
                help="Prioritization score from 0 to 100.",
                min_value=0,
                max_value=100,
                format="%.1f",
            )
        },
    )

    st.download_button(
        "Download flagged events as CSV",
        data=review.to_csv(index=False).encode("utf-8"),
        file_name="sentinellite_flagged_events.csv",
        mime="text/csv",
    )

with st.expander("How the score works"):
    st.markdown(
        """
        SentinelLite combines two layers:

        1. **Isolation Forest** identifies statistically unusual behavior.
        2. **Explainable security rules** flag patterns such as repeated login
           failures, unusually large outbound transfers, and external off-hours activity.

        The resulting score is a triage aid for a human analyst—not a finding of malicious intent.
        """
    )
