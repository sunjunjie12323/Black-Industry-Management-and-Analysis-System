import React, { useState, useEffect, useRef } from 'react';
import { Input, Button, Select, Switch, Popconfirm, Spin, Empty, message } from 'antd';
import { PlusOutlined, DeleteOutlined, SendOutlined, MessageOutlined } from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api, getErrorMessage } from '../services/api';

interface ChatMsg {
  role: 'user' | 'assistant';
  content: string;
}

const SmartQA: React.FC = () => {
  const [conversations, setConversations] = useState<Record<string, unknown>[]>([]);
  const [currentConvId, setCurrentConvId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [convLoading, setConvLoading] = useState(true);
  const [industry, setIndustry] = useState('GENERAL');
  const [industries, setIndustries] = useState<Array<{ value: string; label: string }>>([
    { value: 'GENERAL', label: '通用' },
    { value: 'MANUFACTURING', label: '智能制造' },
    { value: 'EDUCATION', label: '智慧教育' },
    { value: 'MEDICAL', label: '医疗健康' },
    { value: 'FINANCE', label: '金融服务' },
  ]);
  const [ragEnabled, setRagEnabled] = useState(true);
  const endRef = useRef<HTMLDivElement>(null);

  const fetchConversations = async () => {
    setConvLoading(true);
    try {
      const res = await api.smartqa.listConversations();
      const d = res as Record<string, unknown>;
      setConversations((d?.items || d?.conversations || d?.data || []) as Record<string, unknown>[]);
    } catch {
      setConversations([]);
    } finally {
      setConvLoading(false);
    }
  };

  const fetchIndustries = async () => {
    try {
      const res = await api.smartqa.getIndustries();
      const d = res as Record<string, unknown>;
      const list = (d?.industries || d?.items || d?.data || []) as Array<Record<string, unknown>>;
      if (list.length > 0) {
        setIndustries(
          list.map((item) => ({
            value: String(item.value || item.id || item.key || ''),
            label: String(item.label || item.name || item.value || ''),
          }))
        );
      }
    } catch {}
  };

  useEffect(() => {
    fetchConversations();
    fetchIndustries();
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleNewConversation = async () => {
    try {
      const res = await api.smartqa.createConversation({
        title: `对话 ${conversations.length + 1}`,
        industry_context: industry,
      });
      const d = res as Record<string, unknown>;
      const id = String(d.id || d.conversation_id || d.conversationId || '');
      setCurrentConvId(id);
      setMessages([]);
      fetchConversations();
    } catch {
      message.error('创建对话失败');
    }
  };

  const handleDeleteConversation = async (id: string) => {
    try {
      await api.smartqa.deleteConversation(id);
      if (currentConvId === id) {
        setCurrentConvId(null);
        setMessages([]);
      }
      fetchConversations();
    } catch {
      message.error('删除失败');
    }
  };

  const handleSelectConversation = async (id: string) => {
    setCurrentConvId(id);
    try {
      const res = await api.smartqa.getConversation(id);
      const d = res as Record<string, unknown>;
      const msgs = (d?.messages || d?.items || []) as ChatMsg[];
      setMessages(msgs.length > 0 ? msgs : []);
    } catch {
      setMessages([]);
    }
  };

  const handleSend = async () => {
    if (!input.trim()) { message.warning('请输入问题'); return; }
    const msg = input.trim();
    if (!msg || loading) return;
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: msg }]);
    setLoading(true);
    try {
      let convId = currentConvId;
      if (!convId) {
        const res = await api.smartqa.createConversation({
          title: `对话 ${conversations.length + 1}`,
          industry_context: industry,
        });
        const d = res as Record<string, unknown>;
        convId = String(d.id || d.conversation_id || d.conversationId || '');
        setCurrentConvId(convId);
        fetchConversations();
      }
      const chatRes = await api.smartqa.chat(convId!, msg);
      const cd = chatRes as Record<string, unknown>;
      const extractStr = (v: unknown): string => {
        if (typeof v === 'string') return v;
        if (v && typeof v === 'object') {
          const o = v as Record<string, unknown>;
          return String(o.text || o.content || o.message || o.response || o.answer || '');
        }
        return '';
      };
      const content =
        extractStr(cd?.response) ||
        extractStr(cd?.content) ||
        extractStr(cd?.message) ||
        extractStr(cd?.answer) ||
        extractStr(cd?.text) ||
        extractStr(cd?.reply) ||
        '分析完成';
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content },
      ]);
    } catch (err) {
      message.error(getErrorMessage(err));
      setMessages((prev) => [...prev, { role: 'assistant', content: '请求失败，请检查后端服务' }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 90px)', background: 'var(--bg-0)' }}>
      <div
        style={{
          width: 240,
          flexShrink: 0,
          background: 'var(--bg-1)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div style={{ padding: '20px 16px 12px' }}>
          <Button
            icon={<PlusOutlined />}
            onClick={handleNewConversation}
            block
            style={{
              background: 'var(--accent-dim)',
              border: '1px solid var(--border-accent)',
              color: 'var(--accent)',
              fontWeight: 600,
              borderRadius: 'var(--radius)',
            }}
          >
            新建会话
          </Button>
        </div>

        <div style={{ padding: '0 16px 16px' }}>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              textTransform: 'uppercase' as const,
              color: 'var(--text-3)',
              letterSpacing: '0.08em',
              marginBottom: 6,
            }}
          >
            行业上下文
          </div>
          <Select
            value={industry}
            onChange={setIndustry}
            style={{ width: '100%' }}
            size="small"
            options={industries}
          />
        </div>

        <div
          style={{
            height: 1,
            background: 'var(--border)',
            margin: '0 16px',
          }}
        />

        <div style={{ flex: 1, overflow: 'auto', padding: '8px 8px' }}>
          {convLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
              <Spin size="small" />
            </div>
          ) : conversations.length === 0 ? (
            <Empty description="暂无对话，开始新对话吧" />
          ) : (
            conversations.map((conv) => {
              const id = String(conv.id || conv.conversation_id || conv.conversationId || '');
              const isActive = id === currentConvId;
              const title = String(conv.title || conv.name || '对话');
              return (
                <div
                  key={id}
                  onClick={() => handleSelectConversation(id)}
                  style={{
                    padding: '10px 12px',
                    cursor: 'pointer',
                    borderRadius: 'var(--radius)',
                    background: isActive ? 'var(--accent-dim)' : 'transparent',
                    marginBottom: 2,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    transition: 'background 0.15s',
                    borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-2)';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) (e.currentTarget as HTMLDivElement).style.background = 'transparent';
                  }}
                >
                  <span
                    style={{
                      fontSize: 13,
                      color: isActive ? 'var(--accent)' : 'var(--text-1)',
                      fontWeight: isActive ? 500 : 400,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      flex: 1,
                    }}
                  >
                    {title}
                  </span>
                  <Popconfirm
                    title="确认删除此对话？"
                    onConfirm={(e) => {
                      e?.stopPropagation();
                      handleDeleteConversation(id);
                    }}
                    onCancel={(e) => e?.stopPropagation()}
                    okText="删除"
                    cancelText="取消"
                  >
                    <DeleteOutlined
                      style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 8, flexShrink: 0 }}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </Popconfirm>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <div
          style={{
            padding: '16px 28px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'var(--bg-1)',
          }}
        >
          <div>
            <div
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: 28,
                fontWeight: 400,
                color: 'var(--text-0)',
                letterSpacing: '-0.02em',
                lineHeight: 1.1,
              }}
            >
              智能问答
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                textTransform: 'uppercase' as const,
                color: 'var(--text-3)',
                letterSpacing: '0.1em',
                marginTop: 2,
              }}
            >
              基于情报的智能对话
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                textTransform: 'uppercase' as const,
                color: 'var(--text-3)',
                letterSpacing: '0.08em',
              }}
            >
              RAG
            </span>
            <Switch checked={ragEnabled} onChange={setRagEnabled} size="small" />
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 28 }}>
          {messages.length === 0 ? (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                gap: 16,
              }}
            >
              <div
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: '50%',
                  background: 'var(--accent-dim)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1px solid var(--border-accent)',
                }}
              >
                <MessageOutlined style={{ fontSize: 24, color: 'var(--accent)' }} />
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: 24,
                  fontWeight: 400,
                  color: 'var(--text-0)',
                  letterSpacing: '-0.02em',
                }}
              >
                开始对话
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  color: 'var(--text-3)',
                  textTransform: 'uppercase' as const,
                  letterSpacing: '0.06em',
                }}
              >
                Ctrl + Enter 发送
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {messages.map((msg, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  }}
                >
                  <div
                    style={{
                      maxWidth: '70%',
                      padding: '14px 18px',
                      background: msg.role === 'user' ? 'var(--bg-3)' : 'var(--bg-1)',
                      color: msg.role === 'user' ? 'var(--text-0)' : 'var(--text-1)',
                      borderRadius: 'var(--radius-lg)',
                      fontSize: 14,
                      lineHeight: 1.75,
                      border: msg.role === 'user' ? '1px solid var(--border-hover)' : '1px solid var(--border)',
                    }}
                  >
                    {msg.role === 'assistant' ? (
                      <div className="ai-msg-markdown">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.content}</ReactMarkdown>
                      </div>
                    ) : (
                      <span style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</span>
                    )}
                  </div>
                </div>
              ))}
              {loading && (
                <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                  <div
                    style={{
                      padding: '14px 18px',
                      background: 'var(--bg-1)',
                      borderRadius: 'var(--radius-lg)',
                      color: 'var(--text-3)',
                      fontSize: 13,
                      border: '1px solid var(--border)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                    }}
                  >
                    <Spin size="small" />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      Thinking
                    </span>
                  </div>
                </div>
              )}
              <div ref={endRef} />
            </div>
          )}
        </div>

        <div
          style={{
            padding: '16px 28px',
            borderTop: '1px solid var(--border)',
            background: 'var(--bg-1)',
          }}
        >
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
            <Input.TextArea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="输入问题，Ctrl+Enter 发送"
              disabled={loading}
              autoSize={{ minRows: 1, maxRows: 4 }}
              style={{ flex: 1, resize: 'none' }}
            />
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={handleSend}
              loading={loading}
              disabled={!input.trim() || loading}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default SmartQA;
