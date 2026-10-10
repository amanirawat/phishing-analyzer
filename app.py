"""Web interface. Run with:  streamlit run app.py"""
from pathlib import Path

import streamlit as st

from phishing_analyzer import analyze, analyze_eml
from phishing_analyzer.ai import ai_available

COLORS = {"Critical": "#c62828", "High": "#e65100", "Medium": "#f9a825", "Low": "#2e7d32"}
SAMPLES = Path(__file__).parent / "samples"

st.set_page_config(page_title="Phishing Email Analyzer", page_icon="🛡️", layout="centered")
st.title("🛡️ Phishing Email Analyzer")
st.caption("Paste a suspicious email or upload a .eml file. Get a risk score, the red flags, and what to do next.")

tab_paste, tab_upload, tab_sample = st.tabs(["Paste email", "Upload .eml", "Try a sample"])
text, raw = None, None

with tab_paste:
    pasted = st.text_area("Email content (include the From and Subject lines if you can)", height=220,
                          placeholder='From: "Support" <support@example.com>\nSubject: Action required\n\nDear customer, ...')
    if st.button("Analyze", type="primary", key="paste") and pasted.strip():
        text = pasted

with tab_upload:
    st.caption("In Gmail: ⋮ → Download message. In Outlook: File → Save As → .eml")
    uploaded = st.file_uploader("Upload an .eml file", type=["eml", "txt"])
    if uploaded and st.button("Analyze", type="primary", key="upload"):
        raw = uploaded.getvalue()

with tab_sample:
    choice = st.selectbox("Sample", sorted(p.name for p in SAMPLES.iterdir()))
    if st.button("Analyze sample", type="primary"):
        data = (SAMPLES / choice).read_bytes()
        raw, text = (data, None) if choice.endswith(".eml") else (None, data.decode())

use_ai = st.sidebar.toggle("AI explanation", value=ai_available(), disabled=not ai_available(),
                           help="Set ANTHROPIC_API_KEY and install `anthropic` to enable.")
st.sidebar.markdown(
    "**How it works**\n\n"
    "1. Parses headers, body, links, and attachments\n"
    "2. Runs 20+ rule checks across 5 categories\n"
    "3. Scores risk 0-100\n"
    "4. Optionally asks an AI model to explain the findings in plain English\n\n"
    "The AI never sets the score, so a malicious email can't talk its way to *safe*."
)

if text is not None or raw is not None:
    report = analyze_eml(raw, use_ai) if raw is not None else analyze(text, use_ai)
    color = COLORS[report.level]
    st.markdown(
        f"<div style='padding:1.2rem;border-radius:12px;border-left:8px solid {color};background:rgba(127,127,127,.08)'>"
        f"<div style='font-size:.85rem;opacity:.7'>PHISHING RISK</div>"
        f"<div style='font-size:2rem;font-weight:700;color:{color}'>{report.level} · {report.score}/100</div></div>",
        unsafe_allow_html=True,
    )
    st.progress(report.score / 100)
    st.write(report.summary)

    st.subheader("What to do")
    for n, action in enumerate(report.actions, 1):
        st.markdown(f"{n}. {action}")

    if report.indicators:
        st.subheader(f"Red flags ({len(report.indicators)})")
        for ind in report.indicators:
            with st.expander(f"{ind.title}  ·  +{ind.weight}"):
                st.markdown(f"**Category:** {ind.category}")
                st.markdown(f"**Evidence:** {ind.evidence}")
                st.markdown(f"**Advice:** {ind.advice}")

    st.caption(f"Explanation source: {'AI model' if report.ai_used else 'rule-based templates'}")
    st.download_button("Download report (JSON)", data=__import__("json").dumps(report.to_dict(), indent=2),
                       file_name="phishing_report.json", mime="application/json")
