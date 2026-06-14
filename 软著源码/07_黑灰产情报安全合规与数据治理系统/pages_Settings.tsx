import React, { useState, useEffect, useRef } from 'react';
import { Input, Button, Form, Spin, Tag, Card } from 'antd';
import { UserOutlined, SaveOutlined, SettingOutlined, InfoCircleOutlined, RobotOutlined } from '@ant-design/icons';
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
    return <pre style={{ fontSize: 12, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{JSON.stringify(val, null, 2)}</pre>;
  }
  return String(val);
};

const Settings: React.FC = () => {
  const message = useAntdMessage();
  const [profileLoading, setProfileLoading] = useState(false);
  const [modelLoading, setModelLoading] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [modelSaving, setModelSaving] = useState(false);
  const [profileData, setProfileData] = useState<Record<string, unknown> | null>(null);
  const [modelData, setModelData] = useState<Record<string, unknown> | null>(null);
  const [systemInfo, setSystemInfo] = useState<Record<string, unknown> | null>(null);
  const [systemLoading, setSystemLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setProfileLoading(true);
      setModelLoading(true);
      setSystemLoading(true);
      try {
        const profile = await api.auth.getMe();
        setProfileData(profile as unknown as Record<string, unknown>);
      } catch {} finally { setProfileLoading(false); }
      try {
        const config = await api.deepseek.getCurrentModel();
        setModelData(config as Record<string, unknown>);
      } catch {} finally { setModelLoading(false); }
      try {
        const info = await api.deployment.health();
        setSystemInfo(info as Record<string, unknown>);
      } catch {} finally { setSystemLoading(false); }
    })();
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

  const sectionStyle: React.CSSProperties = {
    background: 'var(--bg-1)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 24,
    marginBottom: 20,
  };

  const sectionHeaderStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    marginBottom: 16,
    paddingBottom: 12,
    borderBottom: '1px solid var(--border)',
  };

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden', maxWidth: 800 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0 }}>系统设置</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0' }}>管理账户、模型和系统配置</p>
      </div>

      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>
          <UserOutlined style={{ color: 'var(--accent)', fontSize: 16 }} />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>个人设置</span>
        </div>
        {profileLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : (
          <Form layout="vertical" size="middle" initialValues={{
            username: profileData?.username || '',
            email: profileData?.email || '',
            display_name: profileData?.display_name || profileData?.username || '',
          }} onFinish={handleSaveProfile}>
            <Form.Item name="username" label="用户名" extra="用于登录系统的唯一标识">
              <Input prefix={<UserOutlined style={{ color: 'var(--text-3)' }} />} placeholder="输入用户名" disabled />
            </Form.Item>
            <Form.Item name="display_name" label="显示名称" extra="在系统中展示的名称">
              <Input placeholder="输入显示名称" />
            </Form.Item>
            <Form.Item name="email" label="邮箱" extra="用于接收系统通知">
              <Input placeholder="输入邮箱地址" type="email" />
            </Form.Item>
            <Form.Item name="current_password" label="当前密码" extra="修改密码时需输入当前密码">
              <Input.Password placeholder="输入当前密码" />
            </Form.Item>
            <Form.Item name="new_password" label="新密码" extra="留空则不修改密码">
              <Input.Password placeholder="输入新密码" />
            </Form.Item>
            <Form.Item name="confirm_password" label="确认新密码" extra="再次输入新密码以确认">
              <Input.Password placeholder="再次输入新密码" />
            </Form.Item>
            <Form.Item style={{ marginBottom: 0, marginTop: 8 }}>
              <Button type="primary" icon={<SaveOutlined />} loading={profileSaving} htmlType="submit">保存设置</Button>
            </Form.Item>
          </Form>
        )}
      </div>

      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>
          <RobotOutlined style={{ color: 'var(--accent)', fontSize: 16 }} />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>模型配置</span>
        </div>
        {modelLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : (
          <Form layout="vertical" size="middle" initialValues={{
            model_name: modelData?.model_name || modelData?.model || 'deepseek',
            temperature: modelData?.temperature ?? 0.7,
            max_tokens: modelData?.max_tokens ?? 4096,
            api_base: modelData?.api_base || modelData?.base_url || '',
          }} onFinish={handleSaveModel}>
            <Form.Item name="model_name" label="模型名称" extra="选择或输入使用的AI模型">
              <Input placeholder="例如：deepseek, gpt-4" />
            </Form.Item>
            <Form.Item name="api_base" label="API 地址" extra="模型API的基础URL地址">
              <Input placeholder="https://api.deepseek.com/v1" />
            </Form.Item>
            <Form.Item name="api_key" label="API Key" extra={modelData?.api_key ? '已设置，留空则保持不变' : '输入API密钥'}>
              <Input.Password placeholder={modelData?.api_key ? '已设置，留空保持不变' : '输入API Key'} />
            </Form.Item>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <Form.Item name="temperature" label="温度" extra="控制输出随机性，越高越多样">
                <Input type="number" min={0} max={2} step={0.1} placeholder="0.7" />
              </Form.Item>
              <Form.Item name="max_tokens" label="最大Token数" extra="单次响应的最大长度">
                <Input type="number" min={256} max={32768} step={256} placeholder="4096" />
              </Form.Item>
            </div>
            <Form.Item style={{ marginBottom: 0, marginTop: 8 }}>
              <Button type="primary" icon={<SaveOutlined />} loading={modelSaving} htmlType="submit">保存配置</Button>
            </Form.Item>
          </Form>
        )}
      </div>

      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>
          <InfoCircleOutlined style={{ color: 'var(--accent)', fontSize: 16 }} />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)' }}>系统信息</span>
        </div>
        {systemLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : systemInfo ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            {Object.entries(systemInfo).map(([key, val]) => (
              <Card key={key} style={{ borderRadius: 'var(--radius)' }} styles={{ body: { padding: 16 } }}>
                <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6, textTransform: 'capitalize' }}>{({ api_version: 'API 版本', model_name: '模型名称', database: '数据库', redis: 'Redis', vector_db: '向量数据库', uptime: '运行时间', version: '系统版本', status: '状态', deepseek_connected: 'DeepSeek 连接', graph_db: '图谱数据库' } as Record<string, string>)[key] || key.replace(/_/g, ' ')}</div>
                <div style={{ fontSize: 14, color: 'var(--text-0)', fontWeight: 500, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                  {renderConfigValue(val)}
                </div>
              </Card>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-3)' }}>无法获取系统信息</div>
        )}
      </div>
    </div>
  );
};

export default Settings;
