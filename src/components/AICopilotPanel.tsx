import React, { useState, useRef, useEffect } from 'react';
import { Send, Bot, Loader, Sparkles, HelpCircle, CheckCircle2, Shield, Trash2, ArrowRight } from 'lucide-react';

interface AICopilotPanelProps {
  onSendMessage: (msg: string) => Promise<string>;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'bot';
  text: string;
  timestamp: string;
  suggestedQuestions?: string[];
}

export const AICopilotPanel: React.FC<AICopilotPanelProps> = ({ onSendMessage }) => {
  const [chatInput, setChatInput] = useState('');
  const [chatLog, setChatLog] = useState<ChatMessage[]>([
    {
      id: 'welcome-msg',
      sender: 'bot',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      text: `### 🟢 Simple Explanation
Welcome! I am your AI Network Copilot. I analyze all the packets flowing across your network and explain everything in simple, everyday language — no IT degree needed!

### 📦 Real-World Example
Think of network packets like letters traveling through the postal system. I read the outside envelopes (the addresses and types of mail) to check if anything suspicious is being delivered to your house.

---
💡 **You might also want to ask:**
1. What are all these ARP and UDP packets on my network?
2. Is my computer safe from hackers right now?
3. How does Wi-Fi traffic travel between my phone and router?`,
      suggestedQuestions: [
        "What are all these ARP and UDP packets on my network?",
        "Is my computer safe from hackers right now?",
        "How does Wi-Fi traffic travel between my phone and router?"
      ]
    }
  ]);
  const [sending, setSending] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatLog, sending]);

  // Extract suggested follow-up questions from AI response text
  const extractSuggestions = (rawText: string): { cleanText: string; suggestions: string[] } => {
    const suggestions: string[] = [];
    const splitIndex = rawText.search(/(?:💡\s*)?(?:You might also want to ask|Suggested next questions|Follow-up questions)/i);
    
    if (splitIndex !== -1) {
      const mainContent = rawText.slice(0, splitIndex).trim();
      const suggestionPart = rawText.slice(splitIndex);
      
      const lines = suggestionPart.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*(?:\d+[\.\)]|[-*•])\s*(.*)$/);
        if (match && match[1]?.trim().length > 3) {
          suggestions.push(match[1].trim().replace(/^["']|["']$/g, ''));
        }
      }
      return { cleanText: mainContent, suggestions: suggestions.slice(0, 3) };
    }
    
    return { cleanText: rawText, suggestions: [] };
  };

  const handleSendText = async (textToSend: string) => {
    if (!textToSend.trim() || sending) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setChatLog(prev => [...prev, userMsg]);
    setChatInput('');
    setSending(true);

    try {
      const botRawResponse = await onSendMessage(textToSend);
      const { cleanText, suggestions } = extractSuggestions(botRawResponse);

      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        sender: 'bot',
        text: cleanText,
        suggestedQuestions: suggestions,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setChatLog(prev => [...prev, botMsg]);
    } catch (err: any) {
      setChatLog(prev => [
        ...prev,
        {
          id: `bot-${Date.now()}`,
          sender: 'bot',
          text: `⚠️ An error occurred while communicating with the AI model: ${err.message || err}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setSending(false);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleSendText(chatInput);
  };

  const clearChat = () => {
    setChatLog([
      {
        id: `welcome-${Date.now()}`,
        sender: 'bot',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: `### 🟢 Simple Explanation\nChat history cleared. What network activity or security topic would you like me to explain next?`,
        suggestedQuestions: [
          "Explain my current packet traffic in simple terms",
          "What is an IP address vs a MAC address?",
          "How can I tell if my connection is encrypted?"
        ]
      }
    ]);
  };

  const SUGGESTED_QUERIES = [
    { title: "Explain my traffic simply", query: "Explain what all the packets on my network are currently doing in simple terms for a beginner." },
    { title: "Is anyone scanning my PC?", query: "Are there any suspicious port scans, beacons, or hacker attempts in my recent packets?" },
    { title: "What is an ARP packet?", query: "What is an ARP packet, why does my network keep sending them, and give me a real-world analogy." },
    { title: "How does DNS work?", query: "Explain how DNS lookup works when I visit a website like google.com with a simple example." }
  ];

  // Helper to render formatted sections nicely
  const renderFormattedBotMessage = (text: string) => {
    // Split text by markdown headers ###
    const sections = text.split(/(?=###\s+)/g);

    return (
      <div className="space-y-3 font-sans text-xs leading-relaxed">
        {sections.map((section, idx) => {
          const trimmed = section.trim();
          if (!trimmed) return null;

          if (trimmed.startsWith('### 🟢') || trimmed.toLowerCase().includes('simple explanation')) {
            const body = trimmed.replace(/###\s*[^\n]+\n?/, '').trim();
            return (
              <div key={idx} className="bg-emerald-950/30 border border-emerald-500/40 rounded-lg p-3 space-y-1">
                <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px] uppercase tracking-wider">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Simple Explanation (Plain English)
                </div>
                <div className="text-slate-100 whitespace-pre-wrap">{body}</div>
              </div>
            );
          }

          if (trimmed.startsWith('### 📦') || trimmed.toLowerCase().includes('real-world example')) {
            const body = trimmed.replace(/###\s*[^\n]+\n?/, '').trim();
            return (
              <div key={idx} className="bg-cyan-950/30 border border-cyan-500/40 rounded-lg p-3 space-y-1">
                <div className="flex items-center gap-1.5 text-cyan-400 font-bold text-[11px] uppercase tracking-wider">
                  <HelpCircle className="w-3.5 h-3.5" />
                  Real-World Example & Analogy
                </div>
                <div className="text-cyan-100/90 whitespace-pre-wrap">{body}</div>
              </div>
            );
          }

          if (trimmed.startsWith('### 🔬') || trimmed.toLowerCase().includes('technical breakdown')) {
            const body = trimmed.replace(/###\s*[^\n]+\n?/, '').trim();
            return (
              <div key={idx} className="bg-brand-panel/80 border border-brand-border rounded-lg p-3 space-y-1">
                <div className="flex items-center gap-1.5 text-indigo-400 font-bold text-[11px] uppercase tracking-wider font-mono">
                  🔬 Technical Breakdown
                </div>
                <div className="text-slate-300 font-mono text-[11px] whitespace-pre-wrap">{body}</div>
              </div>
            );
          }

          if (trimmed.startsWith('### 🛡️') || trimmed.toLowerCase().includes('what should you do')) {
            const body = trimmed.replace(/###\s*[^\n]+\n?/, '').trim();
            return (
              <div key={idx} className="bg-amber-950/30 border border-amber-500/40 rounded-lg p-3 space-y-1">
                <div className="flex items-center gap-1.5 text-amber-400 font-bold text-[11px] uppercase tracking-wider">
                  <Shield className="w-3.5 h-3.5" />
                  Actionable Security Steps
                </div>
                <div className="text-amber-100/90 whitespace-pre-wrap">{body}</div>
              </div>
            );
          }

          // Default section render
          return (
            <div key={idx} className="text-slate-200 whitespace-pre-wrap">
              {trimmed.replace(/^###\s+/, '')}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="bg-brand-card border border-brand-border rounded-xl p-5 relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Bot className="w-5 h-5 text-cyan-400 animate-pulse" />
            <h3 className="text-sm font-bold tracking-wide text-white uppercase font-mono">
              Sentinel AI Copilot Intel
            </h3>
            <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
              Live Groq API Connected (openai/gpt-oss-20b)
            </span>
          </div>
          <p className="text-xs text-brand-muted leading-relaxed max-w-2xl">
            Ask any question about your live traffic, captured packets, or cybersecurity concepts. Responses are designed for everyone — plain English first, real-world examples, and 1-click follow-up questions!
          </p>
        </div>

        <button
          onClick={clearChat}
          className="text-xs bg-brand-panel hover:bg-rose-500/20 text-brand-muted hover:text-rose-300 border border-brand-border hover:border-rose-500/30 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 shrink-0 self-start md:self-auto cursor-pointer"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear Conversation
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        
        {/* Suggested Quick Prompts Sidebar */}
        <div className="lg:col-span-1 space-y-3">
          <div className="flex items-center gap-1.5 text-[10px] font-bold text-brand-dim uppercase tracking-wider px-1">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Beginner-Friendly Quick Prompts
          </div>
          {SUGGESTED_QUERIES.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendText(q.query)}
              disabled={sending}
              className="w-full text-left bg-brand-card/60 hover:bg-brand-panel hover:border-cyan-500/40 text-slate-300 border border-brand-border rounded-lg p-3 transition group cursor-pointer disabled:opacity-50"
            >
              <div className="font-bold text-xs text-cyan-400 group-hover:text-cyan-300 flex items-center justify-between">
                <span>{q.title}</span>
                <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <p className="text-[11px] text-brand-muted mt-1 leading-snug">{q.query}</p>
            </button>
          ))}
        </div>

        {/* Chat Area */}
        <div className="lg:col-span-3 flex flex-col h-[540px] bg-brand-card border border-brand-border rounded-xl overflow-hidden shadow-xl">
          
          {/* Chat message stream */}
          <div className="flex-1 overflow-y-auto p-4 space-y-5">
            {chatLog.map((chat) => (
              <div
                key={chat.id}
                className={`flex gap-3 max-w-[92%] ${
                  chat.sender === 'user' ? 'ml-auto flex-row-reverse' : ''
                }`}
              >
                <div
                  className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-[10px] font-mono font-bold shadow-md ${
                    chat.sender === 'user'
                      ? 'bg-gradient-to-br from-cyan-500 to-blue-600 text-white'
                      : 'bg-gradient-to-br from-emerald-600 to-teal-800 text-white'
                  }`}
                >
                  {chat.sender === 'user' ? 'YOU' : 'AI'}
                </div>

                <div className="space-y-2 flex-1">
                  <div
                    className={`rounded-xl p-4 shadow-sm ${
                      chat.sender === 'user'
                        ? 'bg-cyan-950/40 text-cyan-100 border border-cyan-500/30 text-xs'
                        : 'bg-brand-panel text-brand-text border border-brand-border'
                    }`}
                  >
                    {chat.sender === 'user' ? (
                      <p className="whitespace-pre-wrap font-sans text-xs leading-relaxed">{chat.text}</p>
                    ) : (
                      renderFormattedBotMessage(chat.text)
                    )}
                  </div>

                  {/* 1-Click Interactive Next Prompt Predictions */}
                  {chat.suggestedQuestions && chat.suggestedQuestions.length > 0 && (
                    <div className="bg-brand-panel/60 border border-cyan-500/20 rounded-lg p-3 space-y-2 animate-fade-in">
                      <div className="flex items-center gap-1.5 text-[10px] font-bold text-cyan-300 uppercase tracking-wider">
                        <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                        Next Prompt Predictions (Click to Ask):
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {chat.suggestedQuestions.map((sq, sIdx) => (
                          <button
                            key={sIdx}
                            onClick={() => handleSendText(sq)}
                            disabled={sending}
                            className="text-left text-xs bg-slate-900/90 hover:bg-cyan-950 text-slate-200 hover:text-cyan-300 border border-cyan-800/60 hover:border-cyan-400 px-3 py-1.5 rounded-md transition flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
                          >
                            <span className="text-cyan-400 font-bold">{sIdx + 1}.</span>
                            <span>{sq}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className={`text-[9px] text-brand-dim ${chat.sender === 'user' ? 'text-right' : 'text-left'}`}>
                    {chat.timestamp}
                  </div>
                </div>
              </div>
            ))}

            {sending && (
              <div className="flex gap-3 items-center text-xs text-cyan-400 font-mono bg-cyan-950/30 border border-cyan-500/30 rounded-lg p-3 w-fit animate-pulse">
                <Loader className="w-4 h-4 animate-spin text-cyan-400" />
                <span>AI is analyzing live traffic context & formulating simple explanation...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* User Input Form */}
          <form onSubmit={handleFormSubmit} className="bg-brand-panel border-t border-brand-border p-3 flex gap-3">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="Ask anything about your network packets in plain English..."
              disabled={sending}
              className="flex-1 text-xs bg-brand-card border border-brand-border text-brand-text rounded-lg px-3.5 py-2.5 outline-none focus:border-cyan-400 placeholder:text-brand-dim"
            />
            <button
              type="submit"
              disabled={sending || !chatInput.trim()}
              className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold rounded-lg px-5 py-2 flex items-center justify-center gap-1.5 transition disabled:opacity-50 cursor-pointer shadow-[0_0_10px_rgba(6,182,212,0.3)]"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ask AI</span>
            </button>
          </form>

        </div>
      </div>
    </div>
  );
};
