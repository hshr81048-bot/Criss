import { useState, useEffect, useRef } from "react";
import "@/App.css";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Plus, Send, Trash2, MessageSquare, Sparkles, Menu, X, LogOut } from "lucide-react";
import { Toaster, toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showLogin, setShowLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [currentUser, setCurrentUser] = useState("");
  
  const [conversations, setConversations] = useState([]);
  const [currentConversation, setCurrentConversation] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    const savedUsername = localStorage.getItem('username');
    if (savedToken && savedUsername) {
      setToken(savedToken);
      setCurrentUser(savedUsername);
      setIsAuthenticated(true);
      loadConversations(savedToken);
    }
  }, []);

  const handleAuth = async (isLogin) => {
    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/register';
      const response = await axios.post(`${API}${endpoint}`, {
        username,
        password
      });
      
      setToken(response.data.token);
      setCurrentUser(response.data.username);
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('username', response.data.username);
      setIsAuthenticated(true);
      toast.success(isLogin ? 'Giriş başarılı!' : 'Kayıt başarılı!');
      loadConversations(response.data.token);
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Bir hata oluştu');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setToken("");
    setCurrentUser("");
    setConversations([]);
    setMessages([]);
    setCurrentConversation(null);
    toast.success('Çıkış yapıldı');
  };

  const loadConversations = async (authToken) => {
    try {
      const response = await axios.get(`${API}/conversations`, {
        headers: { Authorization: `Bearer ${authToken || token}` }
      });
      setConversations(response.data);
      if (response.data.length > 0 && !currentConversation) {
        selectConversation(response.data[0], authToken);
      }
    } catch (e) {
      console.error("Error loading conversations:", e);
    }
  };

  const selectConversation = async (conversation, authToken) => {
    setCurrentConversation(conversation);
    try {
      const response = await axios.get(`${API}/conversations/${conversation.id}/messages`, {
        headers: { Authorization: `Bearer ${authToken || token}` }
      });
      setMessages(response.data);
      if (window.innerWidth < 768) setSidebarOpen(false);
    } catch (e) {
      console.error("Error loading messages:", e);
    }
  };

  const createNewConversation = async () => {
    try {
      const response = await axios.post(`${API}/conversations`, 
        { title: "Yeni Konuşma" },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setConversations([response.data, ...conversations]);
      setCurrentConversation(response.data);
      setMessages([]);
      toast.success("Yeni konuşma başlatıldı");
      if (window.innerWidth < 768) setSidebarOpen(false);
    } catch (e) {
      console.error("Error creating conversation:", e);
      toast.error("Konuşma oluşturulamadı");
    }
  };

  const deleteConversation = async (conversationId, e) => {
    e.stopPropagation();
    try {
      await axios.delete(`${API}/conversations/${conversationId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const updatedConversations = conversations.filter(c => c.id !== conversationId);
      setConversations(updatedConversations);
      if (currentConversation?.id === conversationId) {
        if (updatedConversations.length > 0) {
          selectConversation(updatedConversations[0]);
        } else {
          setCurrentConversation(null);
          setMessages([]);
        }
      }
      toast.success("Konuşma silindi");
    } catch (e) {
      console.error("Error deleting conversation:", e);
      toast.error("Konuşma silinemedi");
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || loading) return;

    let conversationToUse = currentConversation;

    if (!conversationToUse) {
      try {
        const response = await axios.post(`${API}/conversations`, 
          { title: "Yeni Konuşma" },
          { headers: { Authorization: `Bearer ${token}` } }
        );
        conversationToUse = response.data;
        setCurrentConversation(conversationToUse);
        setConversations([conversationToUse, ...conversations]);
      } catch (e) {
        console.error("Error creating conversation:", e);
        toast.error("Konuşma oluşturulamadı");
        return;
      }
    }

    const userMessageContent = inputMessage;
    setInputMessage("");
    setLoading(true);

    const tempUserMessage = {
      id: "temp-user",
      role: "user",
      content: userMessageContent,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, tempUserMessage]);

    try {
      const response = await axios.post(`${API}/chat`, 
        {
          conversation_id: conversationToUse.id,
          content: userMessageContent
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setMessages(prev => [
        ...prev.filter(m => m.id !== "temp-user"),
        response.data.user_message,
        response.data.assistant_message
      ]);

      loadConversations();
    } catch (e) {
      console.error("Error sending message:", e);
      toast.error("Mesaj gönderilemedi");
      setMessages(prev => prev.filter(m => m.id !== "temp-user"));
    } finally {
      setLoading(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="auth-container" data-testid="auth-screen">
        <Toaster position="top-center" richColors />
        <div className="auth-card">
          <div className="auth-header">
            <Sparkles className="auth-logo" />
            <h1 className="auth-title">ZahirAI</h1>
            <p className="auth-subtitle">Yapay Zeka Asistanınız</p>
          </div>
          
          <div className="auth-tabs">
            <button 
              className={`auth-tab ${showLogin ? 'active' : ''}`}
              onClick={() => setShowLogin(true)}
              data-testid="login-tab"
            >
              Giriş Yap
            </button>
            <button 
              className={`auth-tab ${!showLogin ? 'active' : ''}`}
              onClick={() => setShowLogin(false)}
              data-testid="register-tab"
            >
              Kayıt Ol
            </button>
          </div>

          <form className="auth-form" onSubmit={(e) => { e.preventDefault(); handleAuth(showLogin); }}>
            <div className="form-group">
              <label>Kullanıcı Adı</label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Kullanıcı adınızı girin"
                required
                data-testid="username-input"
              />
            </div>
            <div className="form-group">
              <label>Şifre</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Şifrenizi girin"
                required
                data-testid="password-input"
              />
            </div>
            <Button 
              type="submit" 
              className="auth-submit-btn"
              data-testid="auth-submit-btn"
            >
              {showLogin ? 'Giriş Yap' : 'Kayıt Ol'}
            </Button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container" data-testid="zahir-ai-app">
      <Toaster position="top-center" richColors />
      
      {/* Sidebar */}
      <div className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`} data-testid="conversations-sidebar">
        <div className="sidebar-header">
          <div className="logo-section">
            <Sparkles className="logo-icon" />
            <h1 className="app-title">ZahirAI</h1>
          </div>
          <Button 
            onClick={createNewConversation}
            className="new-chat-btn"
            data-testid="new-conversation-btn"
          >
            <Plus size={18} />
            Yeni Sohbet
          </Button>
        </div>
        
        <ScrollArea className="conversations-list">
          {conversations.length === 0 ? (
            <div className="empty-state">
              <MessageSquare size={40} />
              <p>Henüz konuşma yok</p>
            </div>
          ) : (
            conversations.map((conv) => (
              <div
                key={conv.id}
                className={`conversation-item ${currentConversation?.id === conv.id ? 'active' : ''}`}
                onClick={() => selectConversation(conv)}
                data-testid={`conversation-${conv.id}`}
              >
                <MessageSquare size={16} />
                <span className="conversation-title">{conv.title}</span>
                <button
                  onClick={(e) => deleteConversation(conv.id, e)}
                  className="delete-btn"
                  data-testid={`delete-conversation-${conv.id}`}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))
          )}
        </ScrollArea>

        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar">{currentUser[0].toUpperCase()}</div>
            <span>{currentUser}</span>
          </div>
          <button onClick={handleLogout} className="logout-btn" data-testid="logout-btn">
            <LogOut size={18} />
          </button>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-area" data-testid="chat-area">
        <div className="chat-header">
          <button 
            className="menu-toggle" 
            onClick={() => setSidebarOpen(!sidebarOpen)}
            data-testid="menu-toggle"
          >
            {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
          <h2 className="chat-title">{currentConversation?.title || 'ZahirAI'}</h2>
        </div>

        {messages.length === 0 ? (
          <div className="welcome-screen">
            <div className="welcome-content">
              <Sparkles size={80} className="welcome-icon" />
              <h2 className="welcome-title">ZahirAI'ya Hoş Geldiniz</h2>
              <p className="welcome-subtitle">Size nasıl yardımcı olabilirim?</p>
              <div className="example-prompts">
                <button className="prompt-card" onClick={() => setInputMessage("Yapay zeka hakkında bilgi ver")}>
                  Yapay zeka hakkında bilgi ver
                </button>
                <button className="prompt-card" onClick={() => setInputMessage("Bana bir hikaye anlat")}>
                  Bana bir hikaye anlat
                </button>
                <button className="prompt-card" onClick={() => setInputMessage("Python'da liste nasıl oluşturulur?")}>
                  Python'da liste nasıl oluşturulur?
                </button>
              </div>
            </div>
          </div>
        ) : (
          <ScrollArea className="messages-container" data-testid="messages-container">
            <div className="messages-inner">
              {messages.map((msg, index) => (
                <div
                  key={msg.id || index}
                  className={`message-wrapper ${msg.role}`}
                  data-testid={`message-${msg.role}-${index}`}
                >
                  <div className="message-avatar">
                    {msg.role === "user" ? (
                      <div className="avatar user-avatar">{currentUser[0].toUpperCase()}</div>
                    ) : (
                      <div className="avatar ai-avatar">
                        <Sparkles size={18} />
                      </div>
                    )}
                  </div>
                  <div className="message-content">
                    <div className="message-header">
                      {msg.role === "user" ? "Siz" : "ZahirAI"}
                    </div>
                    <div className="message-text">{msg.content}</div>
                  </div>
                </div>
              ))}
              {loading && (
                <div className="message-wrapper assistant" data-testid="loading-indicator">
                  <div className="message-avatar">
                    <div className="avatar ai-avatar">
                      <Sparkles size={18} />
                    </div>
                  </div>
                  <div className="message-content">
                    <div className="message-header">ZahirAI</div>
                    <div className="typing-indicator">
                      <span></span>
                      <span></span>
                      <span></span>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          </ScrollArea>
        )}

        {/* Input Area */}
        <div className="input-area">
          <form onSubmit={sendMessage} className="input-form">
            <Input
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Mesajınızı yazın..."
              className="message-input"
              disabled={loading}
              data-testid="message-input"
            />
            <Button
              type="submit"
              disabled={loading || !inputMessage.trim()}
              className="send-btn"
              data-testid="send-message-btn"
            >
              <Send size={18} />
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default App;