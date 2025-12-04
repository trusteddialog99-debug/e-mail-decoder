import streamlit as st
import pandas as pd
import tempfile
import os
import re
from email.utils import parseaddr
import olefile

st.set_page_config(page_title="MSG/EML Header Analyzer (robust)", layout="wide")

st.title("MSG / EML Header Analyzer – robustes MSG-Parsing")
st.markdown("""
Extrahiert aus den Internet-Headern (MSG/EML):
- DKIM Domain (d=)
- DKIM Selector (s=)
- From-Domain
- Return-Path-Domain

Hinweis: Für MSG-Dateien lesen wir die OLE-Stream-Namen
`__substg1.0_007D001F` (Unicode) oder `__substg1.0_007D001E` (ASCII).
""")

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    return parts[0] if parts else text

def extract_from_msg(path: str) -> str | None:
    """
    Read transport headers from .msg using olefile.
    Looks for streams:
      '__substg1.0_007D001F' - Unicode (UTF-16-LE)
      '__substg1.0_007D001E' - ASCII / ANSI
    Returns headers as str or None if not found.
    """
    try:
        ole = olefile.OleFileIO(path)
    except Exception:
        return None

    candidates = []
    # collect streams that contain the 007D property id
    for entry in ole.listdir(streams=True, storages=False):
        name = "/".join(entry)
        if "007D001F" in name.upper() or "007D001E" in name.upper():
            try:
                data = ole.openstream(entry).read()
                candidates.append((name, data))
            except Exception:
                continue

    # also try the exact typical top-level names
    for try_name in ("__substg1.0_007D001F", "__substg1.0_007D001E"):
        if ole.exists(try_name):
            try:
                data = ole.openstream(try_name).read()
                candidates.insert(0, (try_name, data))
            except Exception:
                pass

    ole.close()

    if not candidates:
        return None

    # prefer unicode (001F)
    for name, data in candidates:
        if "001F" in name.upper():
            try:
                text = data.decode("utf-16-le", errors="ignore")
                return text
            except Exception:
                pass

    # fallback decodings
    for name, data in candidates:
        for enc in ("utf-8", "latin1", "cp1252"):
            try:
                text = data.decode(enc, errors="ignore")
                return text
            except Exception:
                continue

    return None

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

    # unfold folded header lines
    normalized = re.sub(r"(\r?\n)[ \t]+", " ", headers)

    # DKIM (robust gegen folded lines)
    dkim = re.search(r"(?mi)^dkim-signature:\s*(.+?)(?=\r?\n[^ \t]|$)", normalized, flags=re.S)
    if dkim:
        block = dkim.group(1)
        d = re.search(r"\bd=([^;\s]+)", block, flags=re.I)
        s = re.search(r"\bs=([^;\s]+)", block, flags=re.I)
        if d:
            result["dkim_domain"] = d.group(1).strip().strip('"')
        if s:
            result["dkim_selector"] = s.group(1).strip().strip('"')

    # From
    fm = re.search(r"(?mi)^from:\s*(.+)$", normalized, flags=re.M)
    if fm:
        _, addr = parseaddr(fm.group(1))
        if "@" in addr:
            result["from_domain"] = addr.split("@",1)[1].lower()

    # Return-Path
    rp = re.search(r"(?mi)^return-path:\s*(.+)$", normalized, flags=re.M)
    if rp:
        m = re.search(r"<([^>]+)>", rp.group(1))
        if m:
            addr = m.group(1)
        else:
            _, addr = parseaddr(rp.group(1))
        if "@" in addr:
            result["returnpath_domain"] = addr.split("@",1)[1].lower()

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
            raw = up.read()
            headers = extract_from_eml(raw)
        else:
            # write temp file because olefile works with a file path
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                tmp_path = tmp.name
            headers = extract_from_msg(tmp_path)
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        parsed = parse_headers(headers or "")
        results.append({"filename": up.name, **parsed})

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
