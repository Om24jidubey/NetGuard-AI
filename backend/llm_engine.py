"""
LLM Engine — NetGuard AI
Uses Groq (free) instead of OpenAI.
Takes anomaly detection result + RAG context and produces a
plain-English explanation with remediation steps.
"""

import os
from groq import Groq
from dotenv import load_dotenv
from rag_pipeline import query_rag

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.1-8b-instant"  # free, fast, excellent model on Groq

SYSTEM_PROMPT = """You are NetGuard AI, a senior network security engineer assistant.
Your job is to explain network threats clearly and give practical remediation steps.
Rules:
- Always explain in simple, clear English — avoid unnecessary jargon
- Always give exactly 3 concrete remediation steps numbered 1, 2, 3
- Be direct and confident, like a real expert would be
- Keep explanations under 200 words unless asked for more detail
- If you don't know something, say so honestly
"""


def explain_anomaly(anomaly_result: dict, raw_features: dict = None) -> str:
    attack_type = anomaly_result.get("attack_type", "Unknown Anomaly")
    severity    = anomaly_result.get("severity", "unknown")
    score       = anomaly_result.get("score", 0)

    rag_context = query_rag(f"What is {attack_type} and how to fix it?")

    feature_summary = ""

    detected_features = anomaly_result.get(
        "top_features",
        []
    )

    if detected_features and raw_features:

        details = []

        for feature in detected_features:

            value = raw_features.get(
                feature,
                "N/A"
            )

            details.append(
                f"{feature} = {value}"
            )

        feature_summary = (
            "\nMost anomalous features identified "
            "by the ML model:\n"
            + "\n".join(details)
        )

    user_prompt = f"""A network anomaly was detected with the following details:
- Attack Type: {attack_type}
- Severity: {severity.upper()}
- Anomaly Score: {score:.4f} (higher = more suspicious){feature_summary}

Relevant security documentation:
{rag_context}

Please explain:

1. What this attack is and how it works
2. Why the anomaly detector flagged it
3. How the anomalous features relate to the attack
4. Why it is dangerous
5. Three remediation steps the network engineer should take immediately

Be specific and practical.
"""

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt}
        ],
        temperature=0.3,
        max_tokens=500
    )
    DEBUG=False
    if DEBUG:
        print("\n========== LLM EXPLANATION ==========")
        print(user_prompt)
        print("=====================================\n")
    return response.choices[0].message.content


def chat(question: str, conversation_history: list = None) -> str:
    rag_context = query_rag(question, k=3)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if conversation_history:
        messages.extend(conversation_history[-6:])
    enriched_question = f"""{question}

Relevant security documentation for context:
{rag_context}
"""
    messages.append({"role": "user", "content": enriched_question})
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.4,
        max_tokens=600
    )
    return response.choices[0].message.content


def summarize_log_analysis(anomalies: list) -> str:
    total       = len(anomalies)
    attack_list = [a for a in anomalies if a["is_anomaly"]]
    num_attacks = len(attack_list)

    if total == 0:
        return "No traffic data to analyze."

    attack_types = {}
    for a in attack_list:
        t = a.get("attack_type", "Unknown")
        attack_types[t] = attack_types.get(t, 0) + 1

    attack_summary = "\n".join(
        [f"  - {t}: {c} occurrences" for t, c in attack_types.items()]
    ) or "  None"

    user_prompt = f"""Network log analysis complete. Here are the results:
- Total traffic samples analyzed: {total}
- Anomalies detected: {num_attacks} ({100*num_attacks//total}% of traffic)
- Attack types found:
{attack_summary}

Write a brief executive summary (3-4 sentences) of the network security status
and the top priority action the team should take.
"""
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt}
        ],
        temperature=0.3,
        max_tokens=250
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    print("Testing LLM Engine with Groq...\n")
    anomaly = {
        "is_anomaly": True,
        "score": 0.182,
        "severity": "high",
        "attack_type": "SYN Flood (DDoS)",
        "top_features": [
            " Flow Packets/s",
            " SYN Flag Count",
            " Average Packet Size"
        ]
    }
    features = {
    " Flow Packets/s": 6500,
    " SYN Flag Count": 120,
    " Average Packet Size": 1450,
    "serror_rate": 0.95,
    "count": 200,
    "src_bytes": 50000
    }
    print("--- Anomaly Explanation ---")
    print(explain_anomaly(anomaly, features))
    print("\n--- Chat Test ---")
    print(chat("What is ARP spoofing and how do I detect it?"))