"""OfferShield - fake job / internship offer forensics.
Deterministic checks (domains, fees, channels) + LLM for language analysis and the "trap reply"."""
import os, re, json, difflib
import streamlit as st

# ---------- config ----------
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
             "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "work", "site", "online", "buzz", "icu", "live", "shop", "cfd", "sbs"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "wa.me"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

PATTERNS = {
    "Asks for money (fee / deposit)": [r"registration fee", r"security deposit", r"training (kit|fee|charges)",
        r"processing fee", r"refundable", r"\bdeposit\b", r"laptop (charges|fee|deposit)",
        r"verification (fee|charges)", r"pay\s+(rs\.?|inr|₹|\$)\s?\d+", r"(rs\.?|inr|₹)\s?\d[\d,]*\s*(to be paid|will be refunded)"],
    "Moves you to a chat app": [r"telegram", r"whatsapp", r"signal app", r"text us on"],
    "Artificial urgency": [r"within \d+\s*(hours|hrs|minutes|mins)", r"immediately", r"last date (is )?today",
        r"limited (seats|slots|vacancies)", r"today only", r"offer (will )?expire"],
    "No real interview": [r"no interview", r"directly selected", r"selected without", r"shortlisted based on your (resume|profile)",
        r"you have been selected"],
    "Unrealistic pay": [r"(rs\.?|inr|₹)\s?\d{2,3},?\d{3}\s*(per|/|a)\s*(day|week)", r"earn\s+(rs\.?|inr|₹|\$)\s?\d[\d,]*\s*(daily|per day|weekly)",
        r"work from home.{0,40}(daily|per day)"],
    "Asks for sensitive documents early": [r"aadhaar", r"pan card", r"bank (account )?(details|statement)", r"passport copy", r"otp"],
}
WEIGHTS = {"Asks for money (fee / deposit)": 4, "Moves you to a chat app": 2, "Artificial urgency": 1,
           "No real interview": 2, "Unrealistic pay": 2, "Asks for sensitive documents early": 2}

# ---------- deterministic forensics ----------
def extract_domains(text):
    emails = re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text)
    urls = re.findall(r"https?://([\w.-]+)", text) + re.findall(r"\bwww\.([\w.-]+)", text)
    norm = lambda d: re.sub(r"^www\.", "", d.lower().strip("."))
    return sorted({norm(d) for d in emails}), sorted({norm(d) for d in urls})

def label_of(domain):
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "ac", "gov", "net"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]

def tld_of(domain):
    return domain.split(".")[-1]

def is_official(domain, official):
    return domain == official or domain.endswith("." + official)

def lookalike_check(domain, official, company):
    """Return reason string if `domain` imitates the brand but is not the official domain."""
    brand = label_of(official) if official else re.sub(r"[^a-z0-9]", "", company.lower())
    if not brand or len(brand) < 3 or (official and is_official(domain, official)):
        return None
    lab = label_of(domain).translate(LEET)
    flat = lab.replace("-", "")
    if brand in flat:
        return f"'{domain}' contains the brand '{brand}' but is not the official domain" + (f" ({official})" if official else "")
    ratio = difflib.SequenceMatcher(None, flat, brand).ratio()
    if ratio >= 0.8:
        return f"'{domain}' looks very similar to '{brand}' (similarity {ratio:.0%})"
    return None

def forensics(text, company, official):
    official = official.lower().strip().replace("https://", "").replace("http://", "").strip("/")
    official = re.sub(r"^www\.", "", official)
    email_domains, url_domains = extract_domains(text)
    findings, score = [], 0

    for d in email_domains:
        if d in FREE_MAIL:
            findings.append(("high", f"Recruiter writes from a free email service ({d}). Real companies use their own domain."))
            score += 2
        reason = lookalike_check(d, official, company)
        if reason:
            findings.append(("high", "Lookalike sender domain: " + reason)); score += 4
        elif official and not is_official(d, official) and d not in FREE_MAIL:
            findings.append(("medium", f"Sender domain '{d}' does not match the official domain '{official}'.")); score += 2
        if tld_of(d) in SUSPICIOUS_TLDS:
            findings.append(("medium", f"Sender domain '{d}' uses a TLD often seen in throwaway scam sites (.{tld_of(d)}).")); score += 1

    for d in url_domains:
        if d in SHORTENERS:
            findings.append(("medium", f"Link uses a URL shortener ({d}), which hides the real destination.")); score += 1
            continue
        reason = lookalike_check(d, official, company)
        if reason:
            findings.append(("high", "Lookalike link: " + reason)); score += 4
        if tld_of(d) in SUSPICIOUS_TLDS:
            findings.append(("medium", f"Link domain '{d}' uses a risky TLD (.{tld_of(d)}).")); score += 1

    low = text.lower()
    for name, pats in PATTERNS.items():
        hits = [m.group(0) for p in pats for m in [re.search(p, low)] if m]
        if hits:
            findings.append(("high" if WEIGHTS[name] >= 4 else "medium", f"{name}: found \u201c{hits[0]}\u201d"))
            score += WEIGHTS[name]
    return findings, score, email_domains, url_domains

# ---------- LLM ----------
SYSTEM = """You are a fraud analyst helping students check job/internship offers.
Return ONLY valid JSON with keys:
"summary": 2 plain-language sentences,
"llm_risk": integer 0-3 (0 looks genuine, 3 almost certainly a scam),
"extra_red_flags": list of short strings the code checks may have missed (empty if none),
"genuine_signs": list of short strings that look legitimate (empty if none),
"scammer_next_moves": list of 3 short strings: what a scammer would likely ask next,
"trap_reply": a polite, ready-to-send reply (under 120 words) asking 3 verification questions a real recruiter answers easily and a scammer cannot (official careers page link for this role, interviewer's name and company LinkedIn profile, how to confirm the offer on the official portal),
"action_plan": list of 3 short safe steps.
Never claim certainty. Do not invent facts that are not in the message."""

def call_llm(text, company, findings, cfg):
    from openai import OpenAI
    client = OpenAI(api_key=cfg["key"], base_url=cfg["base"] or None)
    ctx = "\n".join(f"- {f[1]}" for f in findings) or "- none"
    user = f"Company claimed: {company or 'unknown'}\nCode-based findings:\n{ctx}\n\nMessage:\n\"\"\"\n{text}\n\"\"\""
    r = client.chat.completions.create(model=cfg["model"], temperature=0.2,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}])
    raw = r.choices[0].message.content.strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
    m = re.search(r"\{.*\}", raw, re.S)
    return json.loads(m.group(0))

# ---------- UI ----------
st.set_page_config(page_title="OfferShield", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.stApp{background:#F3E8CC} h1,h2,h3{color:#19532B}
.verdict{padding:18px 22px;border-radius:14px;color:#fff;font-size:1.4rem;font-weight:700}
.card{background:#fff;border-radius:12px;padding:12px 16px;margin:6px 0;border-left:6px solid #F86015}
.card.high{border-left-color:#D42518}.card.medium{border-left-color:#F86015}.card.good{border-left-color:#9ABC04}
div.stButton>button{background:#19532B;color:#fff;border-radius:10px;border:0}
</style>""", unsafe_allow_html=True)

EXAMPLES = {
 "Fake offer (lookalike)": ("TechNova Solutions", "technova.com",
  "Dear Candidate,\nCongratulations! You have been selected for the Software Intern role at TechNova Solutions. No interview required, you are directly selected.\n"
  "Stipend: Rs. 45,000 per week, work from home.\nTo confirm your seat, pay a refundable registration fee of Rs. 2,499 within 3 hours. Seats are limited.\n"
  "Contact our HR on Telegram @technova_hr_official and share your Aadhaar and PAN card.\nApply: https://bit.ly/technova-offer\n"
  "Regards,\nPriya Sharma, HR Manager\npriya.hr@technova-careers.xyz"),
 "Genuine-looking offer": ("TechNova Solutions", "technova.com",
  "Hi Aarav,\nThank you for interviewing with us last Thursday. We'd like to offer you a Software Engineering Intern position starting 5 January. "
  "The stipend is Rs. 25,000 per month and details are in the attached offer letter. Please review it and reply by 20 December. "
  "You can also see the role at https://careers.technova.com/jobs/intern-swe.\nBest,\nRahul Mehta\nTalent Acquisition, rahul.mehta@technova.com"),
 "WhatsApp task scam": ("", "",
  "Hello! We found your profile. Part-time job, earn Rs. 8,000 per day liking videos from home. No experience, no interview. "
  "Join our WhatsApp group now: https://wa.me/919000000000. Limited slots, register immediately."),
}
for k, v in {"msg": "", "company": "", "official": ""}.items():
    st.session_state.setdefault(k, v)

def load_example(name):
    c, o, m = EXAMPLES[name]
    st.session_state.company, st.session_state.official, st.session_state.msg = c, o, m

st.title("🛡️ OfferShield")
st.caption("Fake job & internship offer forensics. Paste the message, get a verdict, the proof, and a reply that makes scammers show themselves.")

with st.sidebar:
    st.header("AI settings")
    key = st.text_input("API key", value=os.getenv("LLM_API_KEY", ""), type="password")
    base = st.text_input("Base URL (OpenAI-compatible)", value=os.getenv("LLM_BASE_URL", "https://api.featherless.ai/v1"))
    model = st.text_input("Model", value=os.getenv("LLM_MODEL", "Qwen/Qwen2.5-72B-Instruct"))
    st.caption("No key? The code-based checks still run.")
    st.markdown("---")
    st.caption("Limits: no live WHOIS or domain-age lookup; checks are heuristic. A low-risk result is not a guarantee.")

st.write("**Try an example:**")
cols = st.columns(len(EXAMPLES))
for col, name in zip(cols, EXAMPLES):
    col.button(name, on_click=load_example, args=(name,), use_container_width=True)

left, right = st.columns([3, 2])
with left:
    st.text_area("Paste the recruiter email / WhatsApp message / offer text", key="msg", height=260)
with right:
    st.text_input("Company they claim to be (optional)", key="company")
    st.text_input("Company's official website (optional, e.g. technova.com)", key="official")
    go = st.button("🔍 Analyze offer", type="primary", use_container_width=True)

if go:
    text = st.session_state.msg.strip()
    if len(text) < 30:
        st.warning("Paste the full message first."); st.stop()
    findings, score, emails, urls = forensics(text, st.session_state.company, st.session_state.official)

    ai, ai_err = None, None
    if key:
        with st.spinner("AI is analysing the message..."):
            try:
                ai = call_llm(text, st.session_state.company, findings, {"key": key, "base": base, "model": model})
                score += int(ai.get("llm_risk", 0)) * 2
            except Exception as e:
                ai_err = str(e)[:200]

    if score >= 7: label, color = "🚨 LIKELY SCAM", "#D42518"
    elif score >= 3: label, color = "⚠️ SUSPICIOUS: verify before replying", "#F86015"
    else: label, color = "✅ FEWER RED FLAGS (still verify)", "#19532B"
    st.markdown(f'<div class="verdict" style="background:{color}">{label} &nbsp;·&nbsp; risk points: {score}</div>', unsafe_allow_html=True)
    if ai: st.write(ai.get("summary", ""))
    if ai_err: st.info(f"AI step failed, showing code-based results only. ({ai_err})")
    if not key: st.info("Add an API key in the sidebar to unlock the AI analysis and the trap reply.")

    a, b = st.columns(2)
    with a:
        st.subheader("Evidence found by code")
        if emails or urls:
            st.caption(f"Sender domains: {', '.join(emails) or 'none'} | Link domains: {', '.join(urls) or 'none'}")
        if not findings: st.markdown('<div class="card good">No rule-based red flags found.</div>', unsafe_allow_html=True)
        for sev, msg in sorted(findings, key=lambda f: f[0] != "high"):
            st.markdown(f'<div class="card {sev}">{msg}</div>', unsafe_allow_html=True)
        if ai:
            for f in ai.get("extra_red_flags", []):
                st.markdown(f'<div class="card medium">🤖 {f}</div>', unsafe_allow_html=True)
            for g in ai.get("genuine_signs", []):
                st.markdown(f'<div class="card good">👍 {g}</div>', unsafe_allow_html=True)
    with b:
        if ai:
            st.subheader("What the scammer will do next")
            for s in ai.get("scammer_next_moves", []): st.markdown(f"- {s}")
            st.subheader("Safe action plan")
            for i, s in enumerate(ai.get("action_plan", []), 1): st.markdown(f"{i}. {s}")
    if ai:
        st.subheader("🪤 Trap reply: send this before anything else")
        st.caption("A real recruiter answers these easily. A scammer usually dodges, rushes you, or pushes you to pay.")
        st.code(ai.get("trap_reply", ""), language=None)
    st.caption("Report scams: cybercrime.gov.in or helpline 1930 (India). Never pay to get a job.")
