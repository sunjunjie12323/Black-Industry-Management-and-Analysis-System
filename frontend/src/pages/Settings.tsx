import React, { useState, useEffect, useRef } from 'react';
import { Input, Button, Form, Spin, Tag, Card } from 'antd';
import { UserOutlined, SaveOutlined, InfoCircleOutlined, RobotOutlined } from '@ant-design/icons';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const renderConfigValue = (val: unknown): React.ReactNode => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'boolean') {
    return <Tag color={val ? 'success' : 'default'} style={{ borderRadius: 9999, fontWeight: 500 }}>{val ? '启用' : '禁用'}</Tag>;
  }
  if (typeof val === 'string' || typeof val === 'number') return String(val);
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    if ('url' in obj && typeof obj.url === 'string') return obj.url;
    if ('connection_string' in obj && typeof obj.connection_string === 'string') return obj.connection_string;
    if ('host' in obj && 'port' in obj) return `${obj.host}:${obj.port}`;
    if ('status' in obj) {
      const parts = [String(obj.status)];
      if ('type' in obj) parts.push(String(obj.type));
      if ('host' in obj) parts.push(String(obj.host));
      if ('port' in obj) parts.push(String(obj.port));
      return parts.join(' · ');
    }
    return <pre style={{ fontSize: 12, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-1)' }}>{JSON.stringify(val, null, 2)}</pre>;
  }
  return String(val);
};

const Settings: React.FC = () => {
  const message = useAntdMessage();
  const mountedRef = useRef(true);
  const [profileLoading, setProfileLoading] = useState(false);
  const [modelLoading, setModelLoading] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [modelSaving, setModelSaving] = useState(false);
  const [profileData, setProfileData] = useState<Record<string, unknown> | null>(null);
  const [modelData, setModelData] = useState<Record<string, unknown> | null>(null);
  const [systemInfo, setSystemInfo] = useState<Record<string, unknown> | null>(null);
  const [systemLoading, setSystemLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'profile' | 'model' | 'system'>('profile');

  useEffect(() => {
    (async () => {
      setProfileLoading(true);
      setModelLoading(true);
      setSystemLoading(true);
      try {
        const profile = await api.auth.getMe();
        if (mountedRef.current) setProfileData(profile as unknown as Record<string, unknown>);
      } catch { /* ignore */ } finally { if (mountedRef.current) setProfileLoading(false); }
      try {
        const config = await api.deepseek.getCurrentModel();
        if (mountedRef.current) setModelData(config as Record<string, unknown>);
      } catch { /* ignore */ } finally { if (mountedRef.current) setModelLoading(false); }
      try {
        const info = await api.deployment.health();
        if (mountedRef.current) setSystemInfo(info as Record<string, unknown>);
      } catch { /* ignore */ } finally { if (mountedRef.current) setSystemLoading(false); }
    })();
    return () => { mountedRef.current = false; };
  }, []);

  const handleSaveProfile = async (values: Record<string, string>) => {
    try {
      if (values.new_password && values.new_password !== values.confirm_password) {
        message.error('两次输入的新密码不一致');
        return;
      }
      setProfileSaving(true);
      if (values.display_name || values.email) {
        try {
          await api.auth.updateProfile({ display_name: values.display_name, email: values.email });
        } catch {}
      }
      if (values.new_password) {
        if (!values.current_password) {
          message.warning('修改密码需输入当前密码');
          setProfileSaving(false);
          return;
        }
        await api.auth.changePassword(values.current_password, values.new_password);
      }
      message.success('个人设置已保存');
    } catch (err) {
      message.error(`保存失败: ${getErrorMessage(err)}`);
    } finally { setProfileSaving(false); }
  };

  const handleSaveModel = async (values: Record<string, string>) => {
    try {
      setModelSaving(true);
      const payload = {
        name: String(values.model_name || 'custom'),
        provider: 'custom',
        base_url: String(values.api_base || ''),
        api_key: String(values.api_key || ''),
        model_name: String(values.model_name || ''),
        temperature: Number(values.temperature) || 0.7,
        max_tokens: Number(values.max_tokens) || 4096,
      };
      await api.deepseek.addCustomModel(payload);
      message.success('模型配置已保存');
    } catch (err) {
      message.error(`保存失败: ${getErrorMessage(err)}`);
    } finally { setModelSaving(false); }
  };

  const TAB_ITEMS = [
    { key: 'profile' as const, label: '个人设置', icon: UserOutlined, color: '#6C5CE7' },
    { key: 'model' as const, label: '模型配置', icon: RobotOutlined, color: '#818CF8' },
    { key: 'system' as const, label: '系统信息', icon: InfoCircleOutlined, color: '#14B8A6' },
  ];

  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-2)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-0)',
    fontFamily: 'var(--font-body)',
  };

  const glassCard: React.CSSProperties = {
    background: 'var(--glass-bg)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-lg)',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
  };

  return (
    <div style={{ minHeight: '100%', background: '#0B0D17', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        background: 'var(--glass-bg)',
        borderBottom: '1px solid var(--border)',
        padding: '0 32px',
        display: 'flex',
        alignItems: 'stretch',
        gap: 0,
        height: 56,
        flexShrink: 0,
      }}>
        {TAB_ITEMS.map((item) => {
          const isActive = activeTab === item.key;
          const IconComp = item.icon;
          return (
            <button
              key={item.key}
              onClick={() => setActiveTab(item.key)}
              aria-label={item.label}
              aria-pressed={isActive}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '0 20px',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? `2.5px solid ${item.color}` : '2.5px solid transparent',
                cursor: 'pointer',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                fontWeight: isActive ? 600 : 400,
                color: isActive ? item.color : 'var(--text-2)',
                transition: 'all 0.2s ease',
                position: 'relative',
                whiteSpace: 'nowrap',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = item.color;
                  e.currentTarget.style.background = `${item.color}06`;
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-2)';
                  e.currentTarget.style.background = 'none';
                }
              }}
            >
              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 28,
                height: 28,
                borderRadius: 7,
                background: isActive ? `${item.color}12` : 'transparent',
                color: isActive ? item.color : 'var(--text-2)',
                fontSize: 14,
                transition: 'all 0.2s ease',
              }}>
                <IconComp />
              </span>
              {item.label}
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, padding: '28px 32px 48px', maxWidth: 800, overflow: 'auto' }}>
        {activeTab === 'profile' && (
          <div style={{ ...glassCard, padding: 28 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 20,
              paddingBottom: 16,
              borderBottom: '1px solid var(--border)',
            }}>
              <div style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(108, 92, 231, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <UserOutlined style={{ color: '#6C5CE7', fontSize: 16 }} />
              </div>
              <div>
                <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-0)', fontFamily: 'var(--font-display)' }}>个人设置</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>管理您的账户信息与安全</div>
              </div>
            </div>
            {profileLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
            ) : (
              <Form layout="vertical" size="middle" initialValues={{
                username: profileData?.username || '',
                email: profileData?.email || '',
                display_name: profileData?.display_name || profileData?.username || '',
              }} onFinish={handleSaveProfile}>
                <Form.Item name="username" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>用户名</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>用于登录系统的唯一标识</span>}>
                  <Input
                    prefix={<UserOutlined style={{ color: 'var(--text-3)' }} />}
                    placeholder="输入用户名"
                    disabled
                    style={inputStyle}
                  />
                </Form.Item>
                <Form.Item name="display_name" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>显示名称</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>在系统中展示的名称</span>}>
                  <Input placeholder="输入显示名称" style={inputStyle} />
                </Form.Item>
                <Form.Item name="email" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>邮箱</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>用于接收系统通知</span>}>
                  <Input placeholder="输入邮箱地址" type="email" style={inputStyle} />
                </Form.Item>
                <div style={{
                  height: 1,
                  background: 'var(--border)',
                  margin: '20px 0',
                }} />
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-2)', marginBottom: 16, fontFamily: 'var(--font-body)' }}>修改密码</div>
                <Form.Item name="current_password" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>当前密码</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>修改密码时需输入当前密码</span>}>
                  <Input.Password placeholder="输入当前密码" style={inputStyle} />
                </Form.Item>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <Form.Item name="new_password" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>新密码</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>留空则不修改密码</span>}>
                    <Input.Password placeholder="输入新密码" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="confirm_password" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>确认新密码</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>再次输入新密码以确认</span>}>
                    <Input.Password placeholder="再次输入新密码" style={inputStyle} />
                  </Form.Item>
                </div>
                <Form.Item style={{ marginBottom: 0, marginTop: 12 }}>
                  <button
                    type="submit"
                    disabled={profileSaving}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 8,
                      padding: '9px 28px',
                      borderRadius: 10,
                      border: 'none',
                      background: 'linear-gradient(135deg, #6C5CE7 0%, #818CF8 100%)',
                      color: '#FFFFFF',
                      fontSize: 14,
                      fontWeight: 600,
                      fontFamily: 'var(--font-body)',
                      cursor: profileSaving ? 'not-allowed' : 'pointer',
                      opacity: profileSaving ? 0.65 : 1,
                      transition: 'all 0.2s ease',
                      boxShadow: '0 2px 8px rgba(108, 92, 231, 0.25)',
                    }}
                    onMouseEnter={e => { if (!profileSaving) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 4px 14px rgba(108, 92, 231, 0.35)'; } }}
                    onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(108, 92, 231, 0.25)'; }}
                  >
                    <SaveOutlined style={{ fontSize: 13 }} />
                    {profileSaving ? '保存中...' : '保存设置'}
                  </button>
                </Form.Item>
              </Form>
            )}
          </div>
        )}

        {activeTab === 'model' && (
          <div style={{ ...glassCard, padding: 28 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 20,
              paddingBottom: 16,
              borderBottom: '1px solid var(--border)',
            }}>
              <div style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(129, 140, 248, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <RobotOutlined style={{ color: '#818CF8', fontSize: 16 }} />
              </div>
              <div>
                <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-0)', fontFamily: 'var(--font-display)' }}>模型配置</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>配置AI模型与API连接参数</div>
              </div>
            </div>
            {modelLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
            ) : (
              <Form layout="vertical" size="middle" initialValues={{
                model_name: modelData?.model_name || modelData?.model || 'deepseek',
                temperature: modelData?.temperature ?? 0.7,
                max_tokens: modelData?.max_tokens ?? 4096,
                api_base: modelData?.api_base || modelData?.base_url || '',
              }} onFinish={handleSaveModel}>
                <Form.Item name="model_name" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>模型名称</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>选择或输入使用的AI模型</span>}>
                  <Input placeholder="例如：deepseek, gpt-4" style={inputStyle} />
                </Form.Item>
                <Form.Item name="api_base" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>API 地址</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>模型API的基础URL地址</span>}>
                  <Input placeholder="https://api.deepseek.com/v1" style={inputStyle} />
                </Form.Item>
                <Form.Item name="api_key" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>API Key</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>{modelData?.api_key ? '已设置，留空则保持不变' : '输入API密钥'}</span>}>
                  <Input.Password placeholder={modelData?.api_key ? '已设置，留空保持不变' : '输入API Key'} style={inputStyle} />
                </Form.Item>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <Form.Item name="temperature" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>温度</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>控制输出随机性，越高越多样</span>}>
                    <Input type="number" min={0} max={2} step={0.1} placeholder="0.7" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="max_tokens" label={<span style={{ color: 'var(--text-1)', fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500 }}>最大Token数</span>} extra={<span style={{ color: 'var(--text-3)', fontSize: 12 }}>单次响应的最大长度</span>}>
                    <Input type="number" min={256} max={32768} step={256} placeholder="4096" style={inputStyle} />
                  </Form.Item>
                </div>
                <Form.Item style={{ marginBottom: 0, marginTop: 12 }}>
                  <button
                    type="submit"
                    disabled={modelSaving}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 8,
                      padding: '9px 28px',
                      borderRadius: 10,
                      border: 'none',
                      background: 'linear-gradient(135deg, #6C5CE7 0%, #818CF8 100%)',
                      color: '#FFFFFF',
                      fontSize: 14,
                      fontWeight: 600,
                      fontFamily: 'var(--font-body)',
                      cursor: modelSaving ? 'not-allowed' : 'pointer',
                      opacity: modelSaving ? 0.65 : 1,
                      transition: 'all 0.2s ease',
                      boxShadow: '0 2px 8px rgba(108, 92, 231, 0.25)',
                    }}
                    onMouseEnter={e => { if (!modelSaving) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 4px 14px rgba(108, 92, 231, 0.35)'; } }}
                    onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(108, 92, 231, 0.25)'; }}
                  >
                    <SaveOutlined style={{ fontSize: 13 }} />
                    {modelSaving ? '保存中...' : '保存配置'}
                  </button>
                </Form.Item>
              </Form>
            )}
          </div>
        )}

        {activeTab === 'system' && (
          <div style={{ ...glassCard, padding: 28 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 20,
              paddingBottom: 16,
              borderBottom: '1px solid var(--border)',
            }}>
              <div style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(20, 184, 166, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <InfoCircleOutlined style={{ color: '#14B8A6', fontSize: 16 }} />
              </div>
              <div>
                <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-0)', fontFamily: 'var(--font-display)' }}>系统信息</div>
                <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 2 }}>运行状态与组件健康检查</div>
              </div>
            </div>
            {systemLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
            ) : systemInfo ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                {Object.entries(systemInfo).map(([key, val]) => (
                  <div key={key} style={{
                    padding: 18,
                    background: 'var(--bg-2)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    transition: 'border-color 0.2s ease',
                  }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--border-hover)'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                  >
                    <div style={{
                      fontSize: 11,
                      color: 'var(--text-3)',
                      marginBottom: 8,
                      textTransform: 'capitalize',
                      fontFamily: 'var(--font-body)',
                      fontWeight: 500,
                      letterSpacing: '0.02em',
                    }}>
                      {({ api_version: 'API 版本', model_name: '模型名称', database: '数据库', redis: 'Redis', vector_db: '向量数据库', uptime: '运行时间', version: '系统版本', status: '状态', deepseek_connected: 'DeepSeek 连接', graph_db: '图谱数据库' } as Record<string, string>)[key] || key.replace(/_/g, ' ')}
                    </div>
                    <div style={{
                      fontSize: 14,
                      color: 'var(--text-0)',
                      fontWeight: 500,
                      fontFamily: 'var(--font-mono)',
                      wordBreak: 'break-all',
                    }}>
                      {renderConfigValue(val)}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{
                textAlign: 'center',
                padding: 56,
                color: 'var(--text-3)',
                fontFamily: 'var(--font-body)',
              }}>
                <InfoCircleOutlined style={{ fontSize: 32, color: 'var(--text-3)', marginBottom: 12, display: 'block' }} />
                无法获取系统信息
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Settings;
