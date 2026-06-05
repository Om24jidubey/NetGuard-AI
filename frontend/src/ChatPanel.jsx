import React, { useState, useRef, useEffect } from "react";

const API = "http://localhost:8001";

const SUGGESTED = [
  "What is a SYN Flood attack?",
  "How do I detect a port scan?",
  "What is ARP spoofing and how to prevent it?",
  "Explain DNS amplification attacks",
  "How do I stop a brute force attack on SSH?",
];

export default function ChatPanel() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hi! I'm NetGuard AI. Ask me anything about network security — attacks, detection, or how to fix threats. I'll explain everything in plain English. 🛡️",
    },
  ]);
  const [input, setInput]     = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendMessage(question = input) {
    const q = question.trim();
    if (!q || loading) return;

    const userMsg = { role: "user", content: q };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    // Build history for backend (exclude the initial greeting)
    const history = newMessages
      .slice(1)
      .map((m) => ({ role: m.role, content: m.content }));

    try {
      const res = await fetch(`${API}/chat`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ question: q, history: history.slice(0, -1) }),
      });
      const data = await res.json();
      setMessages((prev) => [...prev, { role: "assistant", content: data.answer }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "⚠️ Backend not reachable. Make sure the FastAPI server is running:\n\n`uvicorn main:app --reload`",
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <span>🤖 NetGuard AI Assistant</span>
        <span className="chat-subtitle">Powered by LLM + RAG over security docs</span>
      </div>

      {/* Suggested questions */}
      <div className="suggestions">
        {SUGGESTED.map((s, i) => (
          <button key={i} className="suggestion-chip" onClick={() => sendMessage(s)}>
            {s}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            <div className="message-avatar">
              {msg.role === "assistant" ? "🛡️" : "👤"}
            </div>
            <div className="message-bubble">
              <pre className="message-text">{msg.content}</pre>
            </div>
          </div>
        ))}

        {loading && (
          <div className="message assistant">
            <div className="message-avatar">🛡️</div>
            <div className="message-bubble">
              <div className="typing-indicator">
                <span></span><span></span><span></span>
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="chat-input-row">
        <textarea
          className="chat-input"
          placeholder="Ask about any network security threat..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          rows={2}
        />
        <button
          className="send-btn"
          onClick={() => sendMessage()}
          disabled={loading || !input.trim()}
        >
          {loading ? "..." : "Send"}
        </button>
      </div>
    </div>
  );
}