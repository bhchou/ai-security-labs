# AI Security Labs — starter v0.3 (Gemini / OpenAI)

A local-first, demo-driven teaching prototype. It is **not** a production RAG system, not a reproduction of Microsoft's EchoLeak vulnerability, and not a claim that a particular prompt injection will reliably succeed.

## Prerequisites

- Python 3.10+ on macOS / Linux / Windows
- LLM API key for the two live-LLM labs (optional for `--dry-run` and `poisoning`)

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
cp .env.example .env      # Windows: copy .env.example .env
# edit .env and set GEMINI_API_KEY (Gemini is default)
```

## Gemini (default) or OpenAI

The same labs use the OpenAI Python SDK. For Gemini, this points to Google's documented OpenAI-compatible API endpoint. No OpenAI API account is required. Put your existing Gemini key in `.env`, keeping it out of Git. Model availability and free-tier request quotas depend on your Google AI Studio project; check https://ai.google.dev/gemini-api/docs/pricing and https://aistudio.google.com/usage.

Gemini Free Tier may use prompts/responses for product improvement: **use fictional data only**. Start with `gemini-2.5-flash-lite` for cheapest testing; if tool calls are not supported/reliable with your selected model, try `gemini-2.5-flash`. A model declining an injection is a real outcome, not a lab failure.

Switch to OpenAI later, only if desired, by changing `LLM_PROVIDER=openai` and setting `OPENAI_API_KEY`/`OPENAI_MODEL`.

## Lab 0: See an RAG-style data flow

```bash
python lab.py rag --dry-run
python lab.py rag
```

Observe: `USER QUERY`, `RETRIEVAL TRACE`, `AUGMENTED INPUT`, `MODEL RESPONSE`. Fixed-corpus keyword selection is *not* a vector retrieval pipeline; intentional to minimize setup. No fine-tuning occurs.

## Lab 1: Mini EchoLeak-inspired indirect prompt injection

```bash
python lab.py mail --case normal --mode vulnerable --dry-run
python lab.py mail --case normal --mode vulnerable
python lab.py mail --case attack --mode vulnerable
python lab.py mail --case attack --mode compare
```

Inspect `data/attack_mail.txt`, model tool proposals and mock-tool policy decisions. **No actual external email or network data exfiltration occurs.** The LLM can choose not to follow malicious directions; that is a valid result. The vulnerable mode merely illustrates the unsafe policy choice of accepting model-proposed external sending, not any actual exfiltration.

The demo directly provides a fictitious secret to the LLM; it *does not* reproduce unauthorized secret discovery/retrieval. Future lessons can add secure retrieval, user-specific ACLs, and a realistic threat model.

## Lab 2: Poison training samples

```bash
python lab.py poisoning
python lab.py poisoning --text '私人精品購物'
```

This lab trains two tiny multinomial Naive Bayes classifiers **for real** using clean and label-poisoned datasets, and compares prediction log scores. It is a toy model, not an LLM, and no GPU or network is used. Changing a few labels does not guarantee a prediction flip for every phrase. The demonstration is that training data affects learned decision behavior.

## Teaching route (future 2-hour talk)

1. Show query → retrieved data → LLM answer (training vs inference vs RAG).
2. Change the training CSV and show resulting model predictions.
3. Introduce poisoned email content and inspect proposed tool calls.
4. Add independent tool authorization and re-run exactly the same inputs.
5. Connect the observations to iPAS 115-2 Planning Q19 (Data Poisoning) and Protection Q29 (EchoLeak / Indirect Prompt Injection).

## Security + reproducibility notes

- The `example.test` domain and `DEMO-SECRET` strings are fictional.
- Do not upload real corporate files, API keys, personal data or confidential documents.
- Never commit `.env`; put keys in process environment or ignored `.env` only.
- The system prompt is not a security control. Always enforce authorization in code at the tool execution layer.
- On real deployments, avoid blindly sending privileged reference documents to an LLM; retrieve according to user entitlements first.
- For teaching, capture actual model, date, parameters, and result; keep fallback recordings if the model refuses to perform the attack.

## v0.3: controlled comparison

Run `python lab.py mail --case attack --mode compare`. The program calls the model **once**, records its proposed tool calls, then applies two different mock authorization policies to **the exact same calls**. If the model proposes no tool call, the experiment reports that no policy comparison was possible; it does not fabricate a successful attack. No network sending takes place.

For a deterministic policy-only check without an API, run `python -m unittest discover -s tests -v`.
