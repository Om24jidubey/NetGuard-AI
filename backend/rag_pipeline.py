"""
RAG Pipeline — NetGuard AI
Loads security docs into ChromaDB vector store.
Uses sentence-transformers (FREE, no API key needed) for embeddings.
Given a query, finds relevant chunks and returns context for the LLM.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

load_dotenv()

CHROMA_DB_PATH = os.getenv("CHROMA_DB_PATH", "./chroma_db")
DOCS_PATH      = os.getenv("DOCS_PATH", "../docs")

# FREE embeddings using sentence-transformers — no API key needed
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2"
)

# Global vectorstore loaded once
_vectorstore = None


def _load_vectorstore():
    global _vectorstore

    if _vectorstore is not None:
        return _vectorstore

    if Path(CHROMA_DB_PATH).exists():
        print("[RAG] Loading existing ChromaDB from disk...")
        _vectorstore = Chroma(
            persist_directory=CHROMA_DB_PATH,
            embedding_function=embeddings
        )
        return _vectorstore

    print("[RAG] No DB found — ingesting documents...")
    _vectorstore = _ingest_documents()
    return _vectorstore


def _ingest_documents():
    docs_path = Path(DOCS_PATH)
    all_docs = []

    # Load PDFs if any exist in docs/ folder
    for pdf_file in docs_path.glob("*.pdf"):
        print(f"[RAG] Loading PDF: {pdf_file.name}")
        loader = PyPDFLoader(str(pdf_file))
        all_docs.extend(loader.load())

    # Load text files if any exist
    for txt_file in docs_path.glob("*.txt"):
        print(f"[RAG] Loading TXT: {txt_file.name}")
        loader = TextLoader(str(txt_file))
        all_docs.extend(loader.load())

    # If no docs found, use built-in knowledge base
    if not all_docs:
        print("[RAG] No docs found — using built-in security knowledge base.")
        all_docs = _builtin_security_docs()

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=100,
        separators=["\n\n", "\n", ".", " "]
    )
    chunks = splitter.split_documents(all_docs)
    print(f"[RAG] Created {len(chunks)} chunks.")

    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=CHROMA_DB_PATH
    )
    vectorstore.persist()
    print("[RAG] ChromaDB saved to disk.")
    return vectorstore


def _builtin_security_docs():
    """
    Built-in security knowledge base.
    App works immediately without any uploaded PDFs.
    """
    from langchain.schema import Document

    knowledge = [
        Document(page_content="""
SYN Flood Attack (DDoS):
A SYN flood is a type of Denial-of-Service attack where the attacker sends a large number
of TCP SYN requests to a target server without completing the handshake. This exhausts
the server connection table making it unable to respond to legitimate requests.
Indicators: Very high SYN packet count from single or spoofed IPs, low SYN-ACK responses.
Remediation: Enable SYN cookies on the server, rate-limit SYN packets at the firewall,
use a DDoS scrubbing service, block offending IPs.
"""),
        Document(page_content="""
Port Scan Attack:
Port scanning is a technique used by attackers to discover open ports and services on a host.
Common tools include Nmap and Masscan.
Indicators: Single IP sending packets to many different ports in a short time window.
Remediation: Use an IDS/IPS to detect scan patterns, block the scanning IP,
enable firewall logging, close unnecessary ports.
"""),
        Document(page_content="""
Brute Force Attack:
A brute force attack attempts to gain unauthorized access by systematically trying all
possible passwords. Common targets: SSH port 22, RDP port 3389, web login pages.
Indicators: Multiple failed login attempts from the same IP, high authentication failure rate.
Remediation: Implement account lockout policies, use multi-factor authentication,
use fail2ban to auto-block repeated failures, change default ports.
"""),
        Document(page_content="""
DDoS — Distributed Denial of Service:
A DDoS attack uses multiple compromised systems to flood a target with traffic.
Types include Volumetric UDP flood, Protocol SYN flood, Application layer HTTP flood.
Indicators: Sudden spike in traffic from many source IPs, server unresponsive to users.
Remediation: Use CDN with DDoS protection like Cloudflare or AWS Shield,
enable rate limiting, use traffic scrubbing services.
"""),
        Document(page_content="""
Man-in-the-Middle Attack (MITM):
An attacker secretly intercepts communication between two parties.
Common variants: ARP spoofing, DNS spoofing, SSL stripping.
Indicators: Unexpected ARP table changes, certificate errors, unusual DNS responses.
Remediation: Use encrypted protocols TLS and HTTPS, enable HSTS,
use static ARP entries, deploy network monitoring tools.
"""),
        Document(page_content="""
ICMP Flood (Ping Flood):
Attacker overwhelms target with ICMP Echo Request packets consuming all bandwidth.
Indicators: Very high ICMP traffic volume, target becomes unreachable.
Remediation: Rate-limit ICMP at the firewall, block external ICMP if not needed,
use QoS policies to deprioritize ICMP traffic.
"""),
        Document(page_content="""
DNS Amplification Attack:
Attacker sends small DNS queries with spoofed source IP to open DNS resolvers.
Resolvers send large responses to the victim amplifying the attack traffic volume.
Indicators: Large DNS response packets from many resolvers, UDP traffic spike on port 53.
Remediation: Disable open DNS resolvers, implement Response Rate Limiting,
filter spoofed source IPs using BCP38 standard.
"""),
        Document(page_content="""
ARP Spoofing:
Attacker sends fake ARP messages to link their MAC address with a legitimate IP.
This allows the attacker to intercept, modify or stop data in transit.
Indicators: Duplicate IP addresses in ARP table, unexpected MAC address changes.
Remediation: Use dynamic ARP inspection on switches, use static ARP entries,
deploy network monitoring tools that detect ARP anomalies.
"""),
        Document(page_content="""
UDP Flood:
Attacker sends large number of UDP packets to random ports on the target host.
Host checks for applications on those ports and sends ICMP unreachable replies.
Indicators: Very high UDP traffic from single or multiple IPs, high CPU on target.
Remediation: Rate limit UDP traffic at firewall, block UDP from untrusted sources,
use traffic scrubbing and DDoS protection services.
"""),
    ]
    return knowledge


def query_rag(question: str, k: int = 4) -> str:
    """
    Find the top-k relevant chunks and return them as context string for LLM.
    """
    vs = _load_vectorstore()
    docs = vs.similarity_search(question, k=k)

    if not docs:
        return "No relevant documentation found."

    context_parts = []
    for i, doc in enumerate(docs, 1):
        context_parts.append(f"[Source {i}]\n{doc.page_content.strip()}")

    return "\n\n".join(context_parts)


# Test directly
if __name__ == "__main__":
    print("Testing RAG pipeline...\n")
    questions = [
        "What is a SYN Flood attack?",
        "How do I detect a port scan?",
        "What is a brute force attack and how to stop it?"
    ]
    for q in questions:
        print(f"Q: {q}")
        print(f"A: {query_rag(q)[:300]}...")
        print("-" * 60)