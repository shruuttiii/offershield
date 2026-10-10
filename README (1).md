# 🛡️ OfferShield: fake job & internship offer forensics
**Track:** AI + Cybersecurity (ForgeHacks 2026)

## Problem
Students and freshers lose money and personal documents to fake job/internship offers (registration fees, lookalike recruiter emails, Telegram/WhatsApp "HR").

## What it does
Paste a recruiter message. OfferShield returns:
1. **Sender & link forensics (plain code):** free-mail senders, lookalike domains (leetspeak/hyphen tricks, similarity), risky TLDs, URL shorteners, mismatch with the company's official domain.
2. **Pattern checks:** fees/deposits, chat-app redirection, urgency, no interview, unrealistic pay, early document requests.
3. **AI analysis (LLM):** plain-language summary, extra red flags, genuine signs, likely next scammer moves, safe action plan.
4. **Trap reply:** a polite message with verification questions a real recruiter answers and a scammer can't.
5. **Verdict** combining code evidence and AI risk.

## Technical approach
Streamlit UI · Python regex + `difflib` for deterministic checks · any OpenAI-compatible LLM (default: Featherless) returning structured JSON. Code evidence is shown separately from AI output so judges can see what is deterministic.

## What works / what doesn't (honest)
- Works: all checks above on pasted text; 3 built-in examples.
- Doesn't: no live WHOIS/domain-age lookup, no attachment/PDF parsing, English-centric patterns. Heuristics can miss new scam styles; a low score is not a guarantee.

## Run
```
pip install -r requirements.txt
export LLM_API_KEY=your_key   # optional; code checks work without it
export LLM_BASE_URL=https://api.featherless.ai/v1
export LLM_MODEL=Qwen/Qwen2.5-72B-Instruct
streamlit run app.py
```
Deploy: push to GitHub, then Streamlit Community Cloud, and add `LLM_API_KEY` under Secrets.
