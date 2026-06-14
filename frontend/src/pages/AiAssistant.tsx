import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Input, Button, Spin, Form, Modal, Tooltip } from 'antd';
import {
  SendOutlined,
  UserOutlined,
  ClearOutlined,
  ThunderboltOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  ReloadOutlined,
  RobotOutlined,
  PlusOutlined,
  MessageOutlined,
  HistoryOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { agentApi, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const { TextArea } = Input;

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  time: string;
}

interface AgentInfo {
  name: string;
  status: string;
  current_task?: string | null;
  execution_count?: number;
}

interface HistoryItem {
  id?: string;
  execution_id?: string;
  query?: string;
  status?: string;
  started_at?: string;
  start_time?: string;
  agent_name?: string;
  result_summary?: string | null;
  results_summary?: string | null;
}

const AiMsgContent: React.FC<{ content: string }> = ({ content }) => {
  const components = useMemo(() => ({
    pre: ({ children }: React.HTMLAttributes<HTMLElement> & { children?: React.ReactNode }) => (
      <pre style={{ background: '#1C1F35', color: '#E8E9ED', borderRadius: 8, padding: 16, overflowX: 'auto', margin: '8px 0', border: '1px solid rgba(255,255,255,0.06)', fontFamily: '"JetBrains Mono", monospace', fontSize: 13 }}>
        {children}
      </pre>
    ),
    code: ({ className, children, ...rest }: React.HTMLAttributes<HTMLElement> & { children?: React.ReactNode }) => {
      const isBlock = className?.includes('language-');
      if (isBlock) {
        return <code className={className} style={{ background: 'transparent', padding: 0, borderRadius: 0, color: 'inherit', fontFamily: '"JetBrains Mono", monospace', fontSize: 13 }} {...rest}>{children}</code>;
      }
      return <code style={{ background: 'rgba(108,92,231,0.15)', padding: '2px 6px', borderRadius: 4, fontFamily: '"JetBrains Mono", monospace', fontSize: 13, color: '#A78BFA' }} {...rest}>{children}</code>;
    },
  }), []);

  return (
    <div style={{ lineHeight: 1.75, fontSize: 15, color: '#E8E9ED' }}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
};

const AiAssistant: React.FC = () => {
  const messageApi = useAntdMessage();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportForm] = Form.useForm();
  const [reportLoading, setReportLoading] = useState(false);
  const [triggering, setTriggering] = useState<'collect' | 'analyze' | null>(null);
  const [loadingSeconds, setLoadingSeconds] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const loadingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  const fetchAgentStatus = useCallback(async () => {
    setAgentsLoading(true);
    try {
      const res = await agentApi.getStatus();
      const agentList = (res.agents as AgentInfo[]) || [];
      setAgents(Array.isArray(agentList) ? agentList : []);
    } catch {
      setAgents([]);
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await agentApi.getHistory(20);
      const items = (res.items || []) as unknown as HistoryItem[];
      setHistory(Array.isArray(items) ? items : []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgentStatus();
    fetchHistory();
    const iv = setInterval(() => { fetchAgentStatus(); fetchHistory(); }, 30000);
    return () => clearInterval(iv);
  }, [fetchAgentStatus, fetchHistory]);

  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const handleSend = async (text?: string) => {
    const msg = (text || input).trim();
    if (!msg || loading) return;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: msg, time: new Date().toLocaleTimeString() }]);
    setLoading(true);
    setLoadingSeconds(0);
    loadingTimerRef.current = setInterval(() => setLoadingSeconds(s => s + 1), 1000);
    try {
      const res = await agentApi.submitQuery(msg);
      const reply = res.message || res.results_summary || '分析完成';
      setMessages(prev => [...prev, { role: 'assistant', content: reply, time: new Date().toLocaleTimeString() }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: `请求失败: ${getErrorMessage(err)}`, time: new Date().toLocaleTimeString() }]);
    } finally {
      setLoading(false);
      if (loadingTimerRef.current) { clearInterval(loadingTimerRef.current); loadingTimerRef.current = null; }
      fetchHistory();
    }
  };

  const handleTriggerCollection = async () => {
    setTriggering('collect');
    try {
      const res = await agentApi.triggerCollection();
      messageApi.success(`采集任务已触发: ${res.task_id || res.status}`);
      fetchHistory();
    } catch (err) {
      messageApi.error(`采集触发失败: ${getErrorMessage(err)}`);
    } finally {
      setTriggering(null);
    }
  };

  const handleTriggerAnalysis = async () => {
    setTriggering('analyze');
    try {
      const res = await agentApi.triggerAnalysis();
      messageApi.success(`分析任务已触发: ${res.task_id || res.status}`);
      fetchHistory();
    } catch (err) {
      messageApi.error(`分析触发失败: ${getErrorMessage(err)}`);
    } finally {
      setTriggering(null);
    }
  };

  const handleGenerateReport = async () => {
    try {
      const values = await reportForm.validateFields();
      setReportLoading(true);
      await agentApi.generateReport({ intelligence_id: values.intelligence_id, content: values.content });
      messageApi.success('报告生成已启动');
      setReportModalOpen(false);
      reportForm.resetFields();
      fetchHistory();
    } catch (err) {
      if (err && typeof err === 'object' && 'errorFields' in (err as object)) return;
      messageApi.error(`报告生成失败: ${getErrorMessage(err)}`);
    } finally {
      setReportLoading(false);
    }
  };

  const quickPrompts = [
    '最近有哪些高危威胁情报？',
    '分析最近的DDoS攻击趋势',
    '帮我查看活跃的黑产IP',
    '总结本周威胁态势',
  ];

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 90px)', overflow: 'hidden', background: '#0B0D17' }}>
      {sidebarOpen && (
        <div style={{
          width: 260,
          background: '#141625',
          borderRight: '1px solid rgba(255,255,255,0.06)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
        }}>
          <div style={{ padding: '16px 16px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#E8E9ED', fontFamily: '"DM Sans", sans-serif' }}>对话与操作</span>
            <Tooltip title="收起侧栏">
              <Button type="text" size="small" icon={<SettingOutlined style={{ fontSize: 13 }} />} onClick={() => setSidebarOpen(false)} style={{ color: '#7C7F9A' }} />
            </Tooltip>
          </div>

          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <Button
              icon={<PlusOutlined />}
              block
              onClick={() => setMessages([])}
              style={{
                borderRadius: 8,
                border: '1px dashed rgba(255,255,255,0.12)',
                background: '#1C1F35',
                color: '#E8E9ED',
                fontSize: 13,
                height: 36,
              }}
            >
              新建对话
            </Button>
          </div>

          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#7C7F9A', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, fontFamily: '"DM Sans", sans-serif' }}>
              快捷操作
            </div>
            {[
              { key: 'collect', icon: <ThunderboltOutlined />, label: '触发采集', color: '#6C5CE7', onClick: handleTriggerCollection, isLoading: triggering === 'collect' },
              { key: 'analyze', icon: <ExperimentOutlined />, label: '触发分析', color: '#6C5CE7', onClick: handleTriggerAnalysis, isLoading: triggering === 'analyze' },
              { key: 'report', icon: <FileTextOutlined />, label: '生成报告', color: '#6C5CE7', onClick: () => setReportModalOpen(true), isLoading: false },
            ].map(item => (
              <button
                key={item.key}
                onClick={item.isLoading || triggering !== null ? undefined : item.onClick}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  width: '100%',
                  padding: '7px 10px',
                  borderRadius: 6,
                  border: 'none',
                  background: 'transparent',
                  cursor: triggering !== null ? 'not-allowed' : 'pointer',
                  fontSize: 13,
                  color: '#E8E9ED',
                  textAlign: 'left',
                  marginBottom: 2,
                  opacity: triggering !== null && !item.isLoading ? 0.4 : 1,
                  fontFamily: '"DM Sans", "PingFang SC", sans-serif',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={e => { if (!triggering) e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
              >
                {item.isLoading ? <Spin size="small" /> : <span style={{ color: item.color, fontSize: 14, display: 'inline-flex' }}>{item.icon}</span>}
                <span>{item.label}</span>
              </button>
            ))}
          </div>

          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#7C7F9A', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, fontFamily: '"DM Sans", sans-serif' }}>
              Agent 状态
            </div>
            {agentsLoading && agents.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '8px 0' }}><Spin size="small" /></div>
            ) : agents.length > 0 ? (
              agents.map(agent => {
                const isRunning = agent.status === 'running' || agent.status === 'active';
                return (
                  <div key={agent.name} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', fontSize: 12, color: '#7C7F9A' }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: isRunning ? '#6C5CE7' : 'rgba(255,255,255,0.12)', boxShadow: isRunning ? '0 0 4px rgba(108,92,231,0.4)' : 'none' }} />
                    <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{agent.name}</span>
                    {agent.execution_count != null && <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: '#7C7F9A' }}>{agent.execution_count}</span>}
                  </div>
                );
              })
            ) : (
              <div style={{ fontSize: 12, color: '#7C7F9A', padding: '4px 10px' }}>暂无数据</div>
            )}
          </div>

          <div style={{ flex: 1, overflow: 'auto', padding: '8px 12px' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#7C7F9A', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, fontFamily: '"DM Sans", sans-serif' }}>
              <HistoryOutlined style={{ marginRight: 4 }} />执行历史
            </div>
            {historyLoading ? (
              <div style={{ textAlign: 'center', padding: '8px 0' }}><Spin size="small" /></div>
            ) : history.length > 0 ? (
              history.map((item, i) => {
                const isCompleted = item.status === 'completed';
                const isFailed = item.status === 'failed';
                return (
                  <div key={i} style={{ padding: '6px 10px', borderRadius: 6, marginBottom: 2, cursor: 'default', transition: 'background 0.15s' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ width: 5, height: 5, borderRadius: '50%', background: isFailed ? '#EF4444' : isCompleted ? '#6C5CE7' : '#6C5CE7', flexShrink: 0 }} />
                      <span style={{ fontSize: 12, color: '#E8E9ED', fontWeight: 500, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.query || item.agent_name || '—'}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: '#7C7F9A', paddingLeft: 11, fontFamily: '"JetBrains Mono", monospace', marginTop: 2 }}>
                      {item.started_at || item.start_time ? new Date(item.started_at || item.start_time || '').toLocaleTimeString() : '—'}
                    </div>
                  </div>
                );
              })
            ) : (
              <div style={{ fontSize: 12, color: '#7C7F9A', padding: '4px 10px' }}>暂无记录</div>
            )}
          </div>

          <div style={{ padding: '8px 12px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <Button
              icon={<ReloadOutlined />}
              block
              size="small"
              onClick={() => { fetchAgentStatus(); fetchHistory(); }}
              style={{ borderRadius: 6, fontSize: 12, color: '#7C7F9A' }}
            >
              刷新状态
            </Button>
          </div>
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <div style={{
          height: 48,
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 20px',
          gap: 12,
          flexShrink: 0,
        }}>
          {!sidebarOpen && (
            <Button type="text" size="small" icon={<MessageOutlined />} onClick={() => setSidebarOpen(true)} style={{ color: '#7C7F9A' }} />
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #6C5CE7 0%, #A78BFA 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <RobotOutlined style={{ color: '#FFFFFF', fontSize: 14 }} />
            </div>
            <span style={{ fontSize: 14, fontWeight: 600, color: '#E8E9ED', fontFamily: '"DM Sans", "PingFang SC", sans-serif' }}>
              AI 助手
            </span>
          </div>
          <div style={{ flex: 1 }} />
          <Button type="text" size="small" icon={<ClearOutlined />} onClick={() => setMessages([])} style={{ color: '#7C7F9A', fontSize: 12 }}>
            清空对话
          </Button>
        </div>

        <div
          ref={chatContainerRef}
          style={{ flex: 1, overflow: 'auto', padding: messages.length === 0 ? 0 : '24px 0' }}
        >
          {messages.length === 0 && !loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 24, padding: '0 24px' }}>
              <div style={{
                width: 56,
                height: 56,
                borderRadius: 16,
                background: 'linear-gradient(135deg, #6C5CE7 0%, #A78BFA 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 8px 24px rgba(108,92,231,0.2)',
              }}>
                <RobotOutlined style={{ color: '#FFFFFF', fontSize: 26 }} />
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 20, fontWeight: 600, color: '#E8E9ED', marginBottom: 6, fontFamily: '"DM Sans", "PingFang SC", sans-serif' }}>
                  有什么可以帮你的？
                </div>
                <div style={{ fontSize: 14, color: '#7C7F9A' }}>
                  基于威胁情报的智能分析助手，支持情报查询、态势分析、报告生成
                </div>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', maxWidth: 600, marginTop: 8 }}>
                {quickPrompts.map((prompt) => (
                  <button
                    key={prompt}
                    onClick={() => handleSend(prompt)}
                    style={{
                      padding: '10px 16px',
                      borderRadius: 20,
                      border: '1px solid rgba(255,255,255,0.08)',
                      background: '#141625',
                      color: '#E8E9ED',
                      fontSize: 13,
                      cursor: 'pointer',
                      fontFamily: '"DM Sans", "PingFang SC", sans-serif',
                      transition: 'all 0.15s ease',
                      whiteSpace: 'nowrap',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.borderColor = '#6C5CE7';
                      e.currentTarget.style.background = 'rgba(108,92,231,0.12)';
                      e.currentTarget.style.color = '#6C5CE7';
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)';
                      e.currentTarget.style.background = '#141625';
                      e.currentTarget.style.color = '#E8E9ED';
                    }}
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ maxWidth: 720, margin: '0 auto', padding: '0 24px' }}>
              {messages.map((msg, i) => (
                <div key={i} style={{
                  marginBottom: 24,
                  display: 'flex',
                  gap: 16,
                  alignItems: 'flex-start',
                }}>
                  {msg.role === 'assistant' ? (
                    <div style={{
                      width: 28,
                      height: 28,
                      borderRadius: 8,
                      background: 'linear-gradient(135deg, #6C5CE7 0%, #A78BFA 100%)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      marginTop: 2,
                    }}>
                      <RobotOutlined style={{ color: '#FFFFFF', fontSize: 13 }} />
                    </div>
                  ) : (
                    <div style={{
                      width: 28,
                      height: 28,
                      borderRadius: 8,
                      background: 'rgba(255,255,255,0.06)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      marginTop: 2,
                    }}>
                      <UserOutlined style={{ color: '#7C7F9A', fontSize: 13 }} />
                    </div>
                  )}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#7C7F9A', marginBottom: 6, fontFamily: '"DM Sans", sans-serif' }}>
                      {msg.role === 'assistant' ? 'AI 助手' : '你'}
                    </div>
                    {msg.role === 'assistant' ? (
                      <AiMsgContent content={msg.content} />
                    ) : (
                      <div style={{ fontSize: 15, lineHeight: 1.75, color: '#E8E9ED', whiteSpace: 'pre-wrap' }}>
                        {msg.content}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {loading && (
                <div style={{ marginBottom: 24, display: 'flex', gap: 16, alignItems: 'flex-start' }}>
                  <div style={{
                    width: 28,
                    height: 28,
                    borderRadius: 8,
                    background: 'linear-gradient(135deg, #6C5CE7 0%, #A78BFA 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <RobotOutlined style={{ color: '#FFFFFF', fontSize: 13 }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#7C7F9A', marginBottom: 6, fontFamily: '"DM Sans", sans-serif' }}>
                      AI 助手
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#7C7F9A', fontSize: 14 }}>
                      <span style={{ display: 'inline-flex', gap: 4 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#6C5CE7', animation: 'pulse 1.2s ease-in-out infinite' }} />
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#6C5CE7', animation: 'pulse 1.2s ease-in-out 0.2s infinite' }} />
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#6C5CE7', animation: 'pulse 1.2s ease-in-out 0.4s infinite' }} />
                      </span>
                      <span>思考中{loadingSeconds > 0 ? ` · ${loadingSeconds}s` : ''}</span>
                      {loadingSeconds > 15 && <span style={{ fontSize: 12, color: '#7C7F9A' }}>响应较慢，请耐心等待</span>}
                    </div>
                  </div>
                </div>
              )}
              <div ref={endRef} />
            </div>
          )}
        </div>

        <div style={{
          borderTop: '1px solid rgba(255,255,255,0.06)',
          padding: '16px 24px 20px',
          background: '#0B0D17',
          flexShrink: 0,
        }}>
          <div style={{
            maxWidth: 720,
            margin: '0 auto',
            display: 'flex',
            gap: 8,
            alignItems: 'flex-end',
          }}>
            <TextArea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="发送消息..."
              autoSize={{ minRows: 1, maxRows: 4 }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              disabled={loading}
              style={{
                flex: 1,
                borderRadius: 12,
                padding: '10px 16px',
                fontSize: 14,
                fontFamily: '"DM Sans", "PingFang SC", sans-serif',
                border: '1px solid rgba(255,255,255,0.08)',
                resize: 'none',
                background: '#141625',
              }}
            />
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={() => handleSend()}
              disabled={!input.trim() || loading}
              style={{
                height: 40,
                width: 40,
                borderRadius: '50%',
                background: input.trim() && !loading
                  ? 'linear-gradient(135deg, #6C5CE7 0%, #A78BFA 100%)'
                  : 'rgba(255,255,255,0.12)',
                border: 'none',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                boxShadow: input.trim() && !loading ? '0 4px 12px rgba(108,92,231,0.3)' : 'none',
              }}
            />
          </div>
          <div style={{ textAlign: 'center', marginTop: 8, fontSize: 11, color: '#7C7F9A', fontFamily: '"DM Sans", sans-serif' }}>
            AI 助手可能产生不准确的信息，请注意甄别
          </div>
        </div>
      </div>

      <Modal
        title="生成报告"
        open={reportModalOpen}
        onCancel={() => setReportModalOpen(false)}
        footer={null}
        width={480}
        destroyOnHidden
      >
        <Form form={reportForm} layout="vertical" size="middle" style={{ marginTop: 16 }}>
          <Form.Item name="intelligence_id" label="情报 ID" extra="可选，指定基于哪条情报生成报告">
            <Input placeholder="输入情报ID，留空则基于全部情报" />
          </Form.Item>
          <Form.Item name="content" label="报告上下文" extra="可选，补充报告生成的背景信息">
            <TextArea rows={4} placeholder="输入报告要求或背景信息" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Button onClick={() => setReportModalOpen(false)} style={{ marginRight: 8 }}>取消</Button>
            <Button type="primary" loading={reportLoading} onClick={handleGenerateReport}>生成</Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AiAssistant;
