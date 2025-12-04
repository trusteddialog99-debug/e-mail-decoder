import streamlit as st
import pandas as pd
import extract_msg
import tempfile
import os
import re
from email.utils import parseaddr

st.set_page_config(page_title="MSG/EML Header Analyzer", layout="wide")

st.title("MSG / EML Header Analyzer – korrigierte Version")

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    return text.split("\n\n", 1)[0]

def extract_from_msg(path: str) -> str | None:
    try:
        msg = extract_msg.Message(path)
    except:
        return None

    headers = None

    if hasattr(msg, "properties"):
        if "007D001F" in msg.properties:
            headers = msg.properties["007D001F"].value
        elif "007D001E" in msg.properties:
            headers = msg.properties["007D001E"].value

    if isinstance(headers, bytes):
        try:
            headers = headers.decode("utf-8", errors="ignore")
        except:
            headers = headers.decode("latin1", errors="ignore")

    return headers

def parse_headers(headers: str) -> dict:
    result = {
        "dkim_domain": "",
        "dkim_selector": "",
        "from_domain": "",
        "returnpath_domain": "",
        "headers_found": "yes" if headers else "no"
    }

    if not headers:
        return result

    dkim = re.search(r"(?mi)^dkim-signature:\s*((?:[^\r\n]|[\r\n][ \t])+)", headers)
    if dkim:
        block = dkim.group(1)
        d = re.search(r"\bd=([^;]+)", block)
        s = re.search(r"\bs=([^;]+)", block)
        if d: result["dkim_domain"] = d.group(1).strip()
        if s: result["dkim_selector"] = s.group(1).strip()

    fm = re.search(r"(?mi)^from:\s*(.*)", headers)
    if fm:
        _, addr = parseaddr(fm.group(1))
        if "@" in addr:
            result["from_domain"] = addr.split("@", 1)[1].lower()

    rp = re.search(r"(?mi)^return-path:\s*(.*)", headers)
    if rp:
        _, addr = parseaddr(rp.group(1))
        if "@" in addr:
            result["returnpath_domain"] = addr.split("@", 1)[1].lower()

    return result

uploaded_files = st.file_uploader(
    "MSG- oder EML-Dateien hochladen",
    type=["msg", "eml"],
    accept_multiple_files=True
)

if uploaded_files:
    results = []

    for up in uploaded_files:
        if up.name.lower().endswith(".eml"):
            headers = extract_from_eml(up.read())
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                tmp_path = tmp.name
            headers = extract_from_msg(tmp_path)
            os.remove(tmp_path)

        parsed = parse_headers(headers or "")

        results.append({
            "filename": up.name,
            **parsed
        })

    df = pd.DataFrame(results)
    st.subheader("Analyse-Ergebnisse")
    st.dataframe(df)

    st.download_button(
        "CSV herunterladen",
        df.to_csv(index=False).encode("utf-8"),
        "header_analysis.csv",
        "text/csv"
    )
else:
    st.info("Bitte MSG- oder EML-Dateien hochladen…")
