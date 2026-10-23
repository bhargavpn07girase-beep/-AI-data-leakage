"""Local Streamlit dashboard for leak monitoring, with upload enforcement."""

from __future__ import annotations

from tempfile import NamedTemporaryFile

from leakguard.dashboard import build_dashboard_summary, validate_upload
from leakguard.incident import IncidentStore


def _launch_dashboard() -> None:
    import streamlit as st

    st.set_page_config(page_title="LeakGuard Monitor", page_icon="🔒", layout="wide")

    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #07111f 0%, #0d1b2a 100%);
            color: #eaf2ff;
        }
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        .glass {
            background: rgba(15, 30, 46, 0.82);
            border: 1px solid rgba(138, 180, 255, 0.22);
            border-radius: 18px;
            padding: 1.2rem 1.3rem;
            box-shadow: 0 12px 32px rgba(2, 8, 19, 0.35);
        }
        .hero {
            background: linear-gradient(135deg, rgba(64, 122, 255, 0.18), rgba(18, 209, 189, 0.14));
            border: 1px solid rgba(120, 182, 255, 0.28);
            border-radius: 20px;
            padding: 1.5rem 1.6rem;
            margin-bottom: 1rem;
        }
        .section-title {
            font-size: 1.1rem;
            font-weight: 700;
            color: #dfeeff;
            letter-spacing: 0.02em;
            margin-bottom: 0.75rem;
        }
        .metric-box {
            background: rgba(12, 22, 33, 0.9);
            border: 1px solid rgba(123, 167, 255, 0.18);
            border-radius: 16px;
            padding: 1rem 1.1rem;
            min-height: 110px;
        }
        .metric-title {
            color: #9bb9e6;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 800;
            color: #f4f8ff;
            margin-top: 0.45rem;
        }
        .chip {
            display: inline-block;
            background: rgba(38, 96, 255, 0.14);
            border: 1px solid rgba(111, 161, 255, 0.3);
            color: #d9ebff;
            border-radius: 999px;
            padding: 0.38rem 0.8rem;
            font-size: 0.76rem;
            margin-right: 0.5rem;
            margin-top: 0.5rem;
        }
        div[data-testid="stFileUploader"] > section {
            background: rgba(14, 24, 35, 0.9);
            border: 1px dashed rgba(145, 185, 255, 0.45);
            border-radius: 18px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.title("🔒 LeakGuard")
        st.caption("AI-Powered Data Leakage Defense")
        st.markdown("### System Status")
        st.success("Monitoring active")
        st.markdown("### Scope")
        st.write("Local detection only")
        st.write("Watch folder: data/monitored")
        st.markdown("### Protection Layers")
        st.markdown("- File event monitoring")
        st.markdown("- Sensitive content scanning")
        st.markdown("- ML anomaly detection")
        st.markdown("- Quarantine and audit trail")

    st.markdown(
        """
        <div class="hero">
            <div style="font-size:0.78rem; color:#8ec9ff; text-transform:uppercase; letter-spacing:0.12em;">Project Overview</div>
            <h1 style="margin:0.35rem 0 0.55rem 0; color:#f5faff;">AI-Powered Data Leakage Detection & Prevention</h1>
            <div style="color:#dfeeff; font-size:1rem; max-width:1100px;">
                A local, real-time system for detecting private data exposure, flagging risky files, and preventing unauthorized uploads through policy-based enforcement.
            </div>
            <div>
                <span class="chip">Real-time monitoring</span>
                <span class="chip">Sensitive data scanning</span>
                <span class="chip">ML risk scoring</span>
                <span class="chip">Quarantine enforcement</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    store = IncidentStore("data/leakguard.db")
    summary = build_dashboard_summary(store)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-box"><div class="metric-title">Total incidents</div><div class="metric-value">{}</div></div>'.format(summary.total), unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-box"><div class="metric-title">Open</div><div class="metric-value">{}</div></div>'.format(summary.open), unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-box"><div class="metric-title">Quarantined</div><div class="metric-value">{}</div></div>'.format(summary.quarantined), unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-box"><div class="metric-title">Healthy</div><div class="metric-value">{}</div></div>'.format(summary.normal), unsafe_allow_html=True)

    st.markdown("<div class='section-title'>System overview</div>", unsafe_allow_html=True)
    left_col, right_col = st.columns([2, 1])

    with left_col:
        st.markdown("<div class='glass'>", unsafe_allow_html=True)
        st.subheader("Recent risky files")
        if summary.recent_files:
            for path in summary.recent_files:
                st.code(path, language=None)
        else:
            st.info("No risky files have been detected yet.")
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        st.markdown("<div class='glass'>", unsafe_allow_html=True)
        st.subheader("Live status")
        st.success("System is active")
        st.caption(f"Latest scan: {summary.latest_scan or 'No scans yet'}")
        st.write("This project demonstrates real-time monitoring, content analysis, and decision enforcement in a controlled local environment.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-title'>Upload review</div>", unsafe_allow_html=True)
    with st.container():
        uploaded_files = st.file_uploader(
            "Upload files to review locally",
            type=["txt", "csv", "json", "jsonl", "parquet", "pdf", "docx", "log", "md", "env", "sql", "yaml", "yml"],
            accept_multiple_files=True,
        )
        if uploaded_files:
            for uploaded in uploaded_files:
                ext = f".{uploaded.name.split('.')[-1]}" if "." in uploaded.name else ".txt"
                with NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
                    temp_file.write(uploaded.read())
                    temp_path = temp_file.name
                allowed, reason, risk_score = validate_upload(temp_path)
                if allowed:
                    st.success(f"**{uploaded.name}**: Accepted — {reason} (Risk: {risk_score:.2f})")
                else:
                    st.error(f"**{uploaded.name}**: Blocked — {reason} (Risk: {risk_score:.2f})")

    st.markdown("<div class='section-title'>Audit trail</div>", unsafe_allow_html=True)
    incidents = store.list_incidents()
    if incidents:
        st.dataframe([
            {
                "status": incident.status,
                "risk": round(incident.risk_score, 2),
                "path": incident.path,
                "reasons": ", ".join(incident.reasons),
                "scanned_at": incident.scanned_at,
            }
            for incident in incidents[-10:]
        ], width="stretch")
    else:
        st.info("No audit entries yet.")


def main() -> None:
    _launch_dashboard()


if __name__ == "__main__":
    main()
