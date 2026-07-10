import { useState, useRef, useEffect } from 'react'
import { chat } from '@/api/client'
import { escapeHtml } from '@/lib/utils'

function ChatPage() {
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; text: string }>>([
    { role: 'assistant', text: "Hello! I'm your AI assistant. Select a model below and start chatting. MiniMax-M3 supports images and video via URLs." }
  ])
  const [input, setInput] = useState('')
  const [provider, setProvider] = useState('openrouter')
  const [model, setModel] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSend = async () => {
    if (!input.trim() || loading) return

    const userMessage = input.trim()
    setMessages(prev => [...prev, { role: 'user', text: userMessage }])
    setInput('')
    setLoading(true)

    try {
      const result = await chat({ message: userMessage, provider, model })
      setMessages(prev => [...prev, { role: 'assistant', text: result.response }])
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', text: `Error: ${(e as Error).message}` }])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="flex flex-col h-full">
      <header className="p-6 border-b border-border">
        <h2 className="text-2xl font-bold">AI Chat</h2>
        <p className="text-muted-foreground">Chat with AI models including MiniMax-M3 (multimodal)</p>
      </header>

      <div className="flex-1 overflow-auto p-6">
        <div className="space-y-4 max-w-3xl">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground text-xs">
                  AI
                </div>
              )}
              <div className={`max-w-xl p-3 rounded-lg ${
                msg.role === 'user' 
                  ? 'bg-primary/20' 
                  : 'bg-card border border-border'
              }`}>
                <p className="text-sm whitespace-pre-wrap">{escapeHtml(msg.text)}</p>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex gap-3">
              <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground text-xs">
                AI
              </div>
              <div className="bg-card border border-border p-3 rounded-lg">
                <div className="typing-indicator flex gap-1">
                  <span className="inline-block w-2 h-2 bg-muted rounded-full animate-bounce"></span>
                  <span className="inline-block w-2 h-2 bg-muted rounded-full animate-bounce [animation-delay:-0.16s]"></span>
                  <span className="inline-block w-2 h-2 bg-muted rounded-full animate-bounce [animation-delay:-0.32s]"></span>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      <div className="p-6 border-t border-border">
        <div className="max-w-3xl space-y-3">
          <div className="flex gap-2">
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="flex-1 px-3 py-2 bg-background border border-border rounded-md"
            >
              <option value="openrouter">OpenRouter</option>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="gemini">Gemini</option>
              <option value="nvidia">Nvidia NIM</option>
              <option value="nvidia-minimax">Nvidia MiniMax-M3</option>
            </select>
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="Model (e.g. minimaxai/minimax-m3)"
              className="flex-1 px-3 py-2 bg-background border border-border rounded-md"
            />
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type your message..."
              className="flex-1 px-3 py-2 bg-background border border-border rounded-md"
              disabled={loading}
            />
            <button
              onClick={handleSend}
              disabled={loading || !input.trim()}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md disabled:opacity-50"
            >
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ChatPage