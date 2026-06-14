import React, { useState, useEffect, useMemo } from 'react';
import {
  Tabs, Card, Statistic, Tag, Spin, Empty, Space, Button, Table, Descriptions,
} from 'antd';
import {
  HeartOutlined, CloudServerOutlined, CloudOutlined, ContainerOutlined,
  HistoryOutlined, DashboardOutlined, ReloadOutlined,
} from '@ant-design/icons';
import {
  LineChart, Line, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const renderConfigValue = (val: unknown): React.ReactNode => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'string' || typeof val === 'number') return String(val);
  if (typeof val === 'boolean') return val ? '是' : '否';
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    if ('status' in obj) {
      const parts = [String(obj.status)];
      if ('type' in obj) parts.push(String(obj.type));
      if ('host' in obj) parts.push(String(obj.host));
      if ('port' in obj) parts.push(String(obj.port));
      return parts.join(' · ');
    }
    if ('host' in obj && 'port' in obj) return `${obj.host}:${obj.port}`;
    return <span style={{ fontSize: 12 }}>{JSON.stringify(val, null, 2)}</span>;
  }
  return String(val);
};

const DeploymentManage: React.FC = () => {
  const message = useAntdMessage();
  const [health, setHealth] = useState<Record<string, unknown> | null>(null);
  const [services, setServices] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<Record<string, unknown>[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const [healthRes, detailRes] = await Promise.allSettled([
        api.deployment.health(),
        api.deployment.detailedHealth(),
      ]);
      if (healthRes.status === 'fulfilled') setHealth(healthRes.value as Record<string, unknown>);
      if (detailRes.status === 'fulfilled') {
        const d = detailRes.value as Record<string, unknown>;
        const raw = d?.services || d?.items || d?.data || [];
        setServices(Array.isArray(raw) ? raw as Record<string, unknown>[] : []);
      }
    } catch {} finally { setLoading(false); }
  };

  const fetchMetrics = async () => {
    setMetricsLoading(true);
    try {
      const res = await api.deployment.getMetricsHistory();
      const d = res as Record<string, unknown>;
      const rawM = d?.metrics || d?.items || d?.data || [];
      setMetrics(Array.isArray(rawM) ? rawM as Record<string, unknown>[] : []);
    } catch { setMetrics([]); } finally { setMetricsLoading(false); }
  };

  useEffect(() => { fetchHealth(); }, []);

  const isHealthy = health?.status === 'healthy' || health?.status === 'ok' || health?.status === 'UP';

  const metricsChartData = useMemo(() => metrics.map((m, i) => ({
    time: String(m.timestamp || m.time || m.created_at || `T+${i}`).slice(11, 16),
    cpu: Number(m.cpu_usage || m.cpu || 0),
    memory: Number(m.memory_usage || m.memory || 0),
    disk: Number(m.disk_usage || m.disk || 0),
    network: Number(m.network_usage || m.network || 0),
  })), [metrics]);

  const latestMetrics = useMemo(() => {
    if (metricsChartData.length === 0) return { cpu: 0, memory: 0, disk: 0, network: 0 };
    return metricsChartData[metricsChartData.length - 1];
  }, [metricsChartData]);

  const serviceColumns = [
    { title: '服务名', dataIndex: 'name', key: 'name', render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{text || '—'}</span> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => { const ok = status === 'healthy' || status === 'ok' || status === 'UP' || status === 'running'; return <Tag style={{ background: ok ? 'var(--green-dim)' : 'var(--red-dim)', color: ok ? 'var(--green)' : 'var(--red)', border: 'none' }}>{ok ? '正常' : '异常'}</Tag>; } },
    { title: '端口', dataIndex: 'port', key: 'port', width: 80, render: (text: unknown) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-2)', fontSize: 12 }}>{String(text || '—')}</span> },
    { title: '版本', dataIndex: 'version', key: 'version', width: 100, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>{text || '—'}</span> },
    { title: '运行时间', dataIndex: 'uptime', key: 'uptime', width: 120, render: (text: string) => <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{text || '—'}</span> },
  ];

  const tooltipStyle: React.CSSProperties = { background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-0)' };

  const tabItems = [
    {
      key: 'overview',
      label: <span><CloudServerOutlined style={{ marginRight: 4 }} />环境配置</span>,
      children: (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, padding: '12px 16px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            管理系统部署环境的配置信息，包括环境变量、服务端口和依赖版本
          </div>
          {health ? (
            <Descriptions bordered column={2} size="small" styles={{ label: { background: 'var(--bg-2)', color: 'var(--text-2)', fontWeight: 500, fontSize: 12 }, content: { fontSize: 13, color: 'var(--text-0)' } }}>
              <Descriptions.Item label="环境">{String(health.environment || health.env || '—')}</Descriptions.Item>
              <Descriptions.Item label="版本">{String(health.version || '—')}</Descriptions.Item>
              <Descriptions.Item label="API 地址">{String(health.api_url || health.api_endpoint || '—')}</Descriptions.Item>
              <Descriptions.Item label="数据库">{renderConfigValue(health.database || health.db_status)}</Descriptions.Item>
              <Descriptions.Item label="Redis">{renderConfigValue(health.redis || health.redis_status)}</Descriptions.Item>
              <Descriptions.Item label="最后部署">{String(health.last_deploy || health.deployed_at || '—')}</Descriptions.Item>
            </Descriptions>
          ) : (
            <Empty description={<span style={{ color: 'var(--text-3)' }}>无法获取环境配置信息</span>} />
          )}
        </div>
      ),
    },
    {
      key: 'docker',
      label: <span><ContainerOutlined style={{ marginRight: 4 }} />Docker</span>,
      children: (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, padding: '12px 16px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            查看 Docker 容器运行状态，管理容器生命周期
          </div>
          {services.length > 0 ? (
            <Table dataSource={services} columns={serviceColumns} rowKey={(record) => String(record.name || record.id || Math.random())} pagination={false} size="small" />
          ) : (
            <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无容器信息</span>} />
          )}
        </div>
      ),
    },
    {
      key: 'huawei',
      label: <span><CloudOutlined style={{ marginRight: 4 }} />华为云</span>,
      children: (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, padding: '12px 16px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            管理华为云 ECS、OBS、RDS 等云服务配置
          </div>
          {health?.huawei_cloud || health?.cloud ? (
            <Descriptions bordered column={2} size="small" styles={{ label: { background: 'var(--bg-2)', color: 'var(--text-2)', fontWeight: 500, fontSize: 12 }, content: { fontSize: 13, color: 'var(--text-0)' } }}>
              <Descriptions.Item label="区域">{String((health?.huawei_cloud as Record<string, unknown>)?.region || (health?.cloud as Record<string, unknown>)?.region || '—')}</Descriptions.Item>
              <Descriptions.Item label="ECS 实例">{String((health?.huawei_cloud as Record<string, unknown>)?.ecs_instance || (health?.cloud as Record<string, unknown>)?.ecs || '—')}</Descriptions.Item>
              <Descriptions.Item label="OBS 桶">{String((health?.huawei_cloud as Record<string, unknown>)?.obs_bucket || (health?.cloud as Record<string, unknown>)?.obs || '—')}</Descriptions.Item>
              <Descriptions.Item label="RDS 实例">{String((health?.huawei_cloud as Record<string, unknown>)?.rds_instance || (health?.cloud as Record<string, unknown>)?.rds || '—')}</Descriptions.Item>
            </Descriptions>
          ) : (
            <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无华为云配置信息</span>} />
          )}
        </div>
      ),
    },
    {
      key: 'deploy',
      label: <span><HistoryOutlined style={{ marginRight: 4 }} />部署记录</span>,
      children: (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, padding: '12px 16px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            查看系统部署历史记录和回滚操作
          </div>
          <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无部署记录</span>} />
        </div>
      ),
    },
    {
      key: 'monitor',
      label: <span><DashboardOutlined style={{ marginRight: 4 }} />监控</span>,
      children: (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 16, padding: '12px 16px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            实时监控系统资源使用情况，包括 CPU、内存、磁盘和网络
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
            <Button icon={<ReloadOutlined />} onClick={fetchMetrics} loading={metricsLoading}>刷新指标</Button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
            <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, textAlign: 'center' }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500, marginBottom: 8 }}>CPU 使用率</div>
              <Statistic value={latestMetrics.cpu} suffix="%" valueStyle={{ fontFamily: 'var(--font-mono)', color: latestMetrics.cpu > 80 ? 'var(--red)' : 'var(--blue)', fontWeight: 700 }} />
            </div>
            <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, textAlign: 'center' }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500, marginBottom: 8 }}>内存使用率</div>
              <Statistic value={latestMetrics.memory} suffix="%" valueStyle={{ fontFamily: 'var(--font-mono)', color: latestMetrics.memory > 80 ? 'var(--red)' : 'var(--green)', fontWeight: 700 }} />
            </div>
            <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, textAlign: 'center' }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500, marginBottom: 8 }}>磁盘使用率</div>
              <Statistic value={latestMetrics.disk} suffix="%" valueStyle={{ fontFamily: 'var(--font-mono)', color: latestMetrics.disk > 80 ? 'var(--red)' : 'var(--orange)', fontWeight: 700 }} />
            </div>
            <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, textAlign: 'center' }}>
              <div style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500, marginBottom: 8 }}>网络流量</div>
              <Statistic value={latestMetrics.network} suffix=" MB/s" valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--teal)', fontWeight: 700 }} />
            </div>
          </div>
          {metricsChartData.length > 0 ? (
            <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', padding: '16px 12px 8px' }}>
              <ResponsiveContainer width="100%" height={320}>
                <LineChart data={metricsChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="time" tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={false} tickLine={false} width={45} />
                  <RTooltip contentStyle={tooltipStyle} />
                  <Line type="monotone" dataKey="cpu" stroke="#2563EB" strokeWidth={1.5} dot={false} name="CPU" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                  <Line type="monotone" dataKey="memory" stroke="#16A34A" strokeWidth={1.5} dot={false} name="内存" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                  <Line type="monotone" dataKey="disk" stroke="#EA580C" strokeWidth={1.5} dot={false} name="磁盘" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                  <Line type="monotone" dataKey="network" stroke="#0D9488" strokeWidth={1.5} dot={false} name="网络" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div style={{ height: 320, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text-3)', fontSize: 13 }}>点击「刷新指标」获取监控数据</span>
            </div>
          )}
        </div>
      ),
    },
  ];

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>部署管理</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>管理系统部署环境、Docker容器和云服务配置</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 24, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          {loading ? <Spin /> : (
            <>
              <HeartOutlined style={{ fontSize: 48, color: isHealthy ? 'var(--green)' : 'var(--red)', marginBottom: 16 }} />
              <div style={{ fontSize: 20, fontWeight: 600, color: isHealthy ? 'var(--green)' : 'var(--red)', marginBottom: 8 }}>
                {isHealthy ? '系统正常' : '系统异常'}
              </div>
              <Tag style={{ background: isHealthy ? 'var(--green-dim)' : 'var(--red-dim)', color: isHealthy ? 'var(--green)' : 'var(--red)', border: 'none', fontSize: 13, padding: '4px 12px' }}>
                {String(health?.status || 'unknown').toUpperCase()}
              </Tag>
              <Button icon={<ReloadOutlined />} onClick={fetchHealth} style={{ marginTop: 16 }} size="small">刷新</Button>
            </>
          )}
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>服务状态</div>
          {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div> : services.length === 0 ? <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无服务状态信息</span>} /> : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {services.map((s, i) => {
                const ok = String(s.status) === 'healthy' || String(s.status) === 'ok' || String(s.status) === 'UP' || String(s.status) === 'running';
                return (
                  <div key={i} style={{ padding: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: `1px solid ${ok ? 'var(--border)' : 'var(--red)'}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-0)' }}>{String(s.name || '—')}</span>
                      <Tag style={{ background: ok ? 'var(--green-dim)' : 'var(--red-dim)', color: ok ? 'var(--green)' : 'var(--red)', border: 'none' }}>{ok ? '正常' : '异常'}</Tag>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>端口: {String(s.port || '—')}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 24 }}>
        <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />
      </div>
    </div>
  );
};

export default DeploymentManage;
