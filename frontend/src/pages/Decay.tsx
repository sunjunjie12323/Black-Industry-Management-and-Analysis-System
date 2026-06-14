import React, { useState, useEffect, useMemo } from 'react';
import { Input, Button, Table, Tag, Spin, Empty, Tabs, Slider, Progress, Card, Statistic } from 'antd';
import { SearchOutlined, LineChartOutlined, CheckSquareOutlined, BulbOutlined, ClockCircleOutlined, WarningOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const Decay: React.FC = () => {
  const message = useAntdMessage();
  const [intelId, setIntelId] = useState('');
  const [queryResult, setQueryResult] = useState<Record<string, unknown> | null>(null);
  const [curveResult, setCurveResult] = useState<Record<string, unknown> | null>(null);
  const [batchResult, setBatchResult] = useState<Record<string, unknown> | null>(null);
  const [recommendResult, setRecommendResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('query');
  const [stats, setStats] = useState({ total: 0, expired: 0, warning: 0 });

  useEffect(() => {
    (async () => {
      try {
        const res = await api.decay.recommendations();
        const items = (res.recommendations || res.items || []) as Record<string, unknown>[];
        const expired = items.filter(i => (i.action as string)?.includes('update') || (i.urgency as string) === 'high').length;
        const warning = items.filter(i => (i.urgency as string) === 'medium').length;
        setStats({ total: items.length, expired, warning });
      } catch {}
    })();
  }, []);

  const handleQuery = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setQueryResult(null);
    try { const res = await api.decay.getIntelligence(intelId.trim()); setQueryResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleCurve = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setCurveResult(null);
    try { const res = await api.decay.getCurve(intelId.trim()); setCurveResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleBatch = async () => {
    setLoading(true); setBatchResult(null);
    try { const res = await api.decay.batch(); setBatchResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleRecommend = async () => {
    setLoading(true); setRecommendResult(null);
    try { const res = await api.decay.recommendations(); setRecommendResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const curveData = useMemo(() => {
    if (!curveResult) return [];
    const points = (curveResult.curve || curveResult.data_points || curveResult.timeline || []) as Record<string, unknown>[];
    return points.map((p, i) => ({
      time: (p.time || p.date || p.day || p.period || `D${i + 1}`) as string,
      value: ((p.value || p.score || p.reliability || p.decay_value || 0) as number),
    }));
  }, [curveResult]);

  const batchItems = useMemo(() => {
    if (!batchResult) return [];
    return (batchResult.results || batchResult.items || batchResult.evaluations || []) as Record<string, unknown>[];
  }, [batchResult]);

  const recommendations = useMemo(() => {
    if (!recommendResult) return [];
    return (recommendResult.recommendations || recommendResult.items || []) as Record<string, unknown>[];
  }, [recommendResult]);

  const batchColumns = [
    { title: '情报ID', dataIndex: 'intelligence_id', key: 'intelligence_id', width: 120, render: (val: unknown) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--primary)' }}>{String(val || '-').slice(0, 8)}…</span> },
    { title: '时效评分', dataIndex: 'decay_score', key: 'decay_score', width: 140, render: (val: unknown, r: Record<string, unknown>) => { const score = (val || r.score || r.reliability || 0) as number; const color = score >= 0.7 ? 'var(--green)' : score >= 0.4 ? 'var(--yellow)' : 'var(--red)'; return <Progress percent={Math.round(score * 100)} size="small" strokeColor={color} />; } },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (val: unknown, r: Record<string, unknown>) => { const s = String(val || r.decay_status || 'unknown'); const colorMap: Record<string, string> = { fresh: 'var(--green)', valid: 'var(--green)', stale: 'var(--yellow)', expired: 'var(--red)', outdated: 'var(--red)' }; const bgMap: Record<string, string> = { fresh: 'var(--green-dim)', valid: 'var(--green-dim)', stale: 'var(--yellow-dim)', expired: 'var(--red-dim)', outdated: 'var(--red-dim)' }; return <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: bgMap[s] || 'var(--bg-3)', color: colorMap[s] || 'var(--text-2)', fontSize: 11, fontWeight: 500 }}>{s}</span>; } },
    { title: '建议', dataIndex: 'recommendation', key: 'recommendation', ellipsis: true, render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{String(val || r.action || '-')}</span> },
  ];

  const recommendColumns = [
    { title: '情报ID', dataIndex: 'intelligence_id', key: 'intelligence_id', width: 120, render: (val: unknown) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--primary)' }}>{String(val || '-').slice(0, 8)}…</span> },
    { title: '紧急度', dataIndex: 'urgency', key: 'urgency', width: 100, render: (val: unknown) => { const colorMap: Record<string, { color: string; bg: string }> = { high: { color: 'var(--red)', bg: 'var(--red-dim)' }, medium: { color: 'var(--yellow)', bg: 'var(--yellow-dim)' }, low: { color: 'var(--green)', bg: 'var(--green-dim)' } }; const cfg = colorMap[String(val)] || { color: 'var(--text-2)', bg: 'var(--bg-3)' }; return <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: cfg.bg, color: cfg.color, fontSize: 11, fontWeight: 500 }}>{String(val || 'low')}</span>; } },
    { title: '建议操作', dataIndex: 'action', key: 'action', ellipsis: true, render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-1)', fontSize: 12 }}>{String(val || r.recommendation || '-')}</span> },
    { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true, render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{String(val || r.description || '-')}</span> },
  ];

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>时效衰减</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>评估情报时效性，识别需要更新的过时信息</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>待评估情报</span>} value={stats.total} valueStyle={{ color: 'var(--text-0)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<ClockCircleOutlined />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>已过期</span>} value={stats.expired} valueStyle={{ color: 'var(--red)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<WarningOutlined />} />
        </Card>
        <Card style={{ borderRadius: 'var(--radius-lg)' }} styles={{ body: { padding: 20 } }}>
          <Statistic title={<span style={{ color: 'var(--text-2)', fontSize: 13 }}>即将过期</span>} value={stats.warning} valueStyle={{ color: 'var(--yellow)', fontWeight: 600, fontFamily: 'var(--font-mono)' }} prefix={<SafetyCertificateOutlined />} />
        </Card>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'query',
            label: '查询',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>查询单条情报的时效性评分和衰减状态</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID查询时效性" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleQuery} />
                  </div>
                  <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={handleQuery}>查询</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : queryResult ? (
                  <div style={{ padding: 20, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                    {queryResult.decay_score != null && (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>时效评分</div>
                        <Progress percent={Math.round((queryResult.decay_score as number) * 100)} strokeColor={(queryResult.decay_score as number) >= 0.7 ? 'var(--green)' : (queryResult.decay_score as number) >= 0.4 ? 'var(--yellow)' : 'var(--red)'} />
                      </div>
                    )}
                    {queryResult.status ? (
                      <div style={{ marginBottom: 12 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-3)', marginRight: 8 }}>状态：</span>
                        <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--bg-3)', color: 'var(--text-0)', fontSize: 11, fontWeight: 500 }}>{String(queryResult.status)}</span>
                      </div>
                    ) : null}
                    {queryResult.half_life ? (
                      <div style={{ marginBottom: 12 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-3)', marginRight: 8 }}>半衰期：</span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-0)', fontWeight: 500 }}>{String(queryResult.half_life)}</span>
                      </div>
                    ) : null}
                    {queryResult.recommendation ? (
                      <div style={{ padding: 12, background: 'var(--primary-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--primary-light)' }}>
                        <span style={{ fontSize: 12, color: 'var(--text-3)', marginRight: 8 }}>建议：</span>
                        <span style={{ fontSize: 13, color: 'var(--primary)', fontWeight: 500 }}>{String(queryResult.recommendation)}</span>
                      </div>
                    ) : null}
                  </div>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID查询时效性</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'curve',
            label: '衰减曲线',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>查看情报的时效性随时间衰减的曲线变化</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID查看衰减曲线" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleCurve} />
                  </div>
                  <Button type="primary" icon={<LineChartOutlined />} loading={loading} onClick={handleCurve}>查看曲线</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : curveResult ? (
                  curveData.length > 0 ? (
                    <div className="chart-reveal chart-d-1">
                      <ResponsiveContainer width="100%" height={320}>
                        <AreaChart data={curveData} margin={{ top: 10, right: 20, left: -10, bottom: 5 }}>
                        <defs>
                          <linearGradient id="decayGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="var(--primary-light)" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="var(--primary-light)" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="time" tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" />
                        <YAxis tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" domain={[0, 1]} />
                        <RTooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} />
                        <Area type="monotone" dataKey="value" stroke="var(--primary-light)" fill="url(#decayGrad)" strokeWidth={2} isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无衰减曲线数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID查看衰减曲线</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'batch',
            label: '批量评估',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>批量评估所有情报的时效性状态</p>
                <div style={{ marginBottom: 20 }}>
                  <Button type="primary" icon={<CheckSquareOutlined />} loading={loading} onClick={handleBatch}>批量评估</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : batchResult ? (
                  batchItems.length > 0 ? (
                    <Table dataSource={batchItems.map((item, i) => ({ ...item, key: i }))} columns={batchColumns} size="small" pagination={{ pageSize: 10, size: 'small' }} />
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无评估结果</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>点击批量评估按钮开始评估</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'recommend',
            label: '推荐操作',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>获取系统推荐的情报更新和重新验证操作</p>
                <div style={{ marginBottom: 20 }}>
                  <Button type="primary" icon={<BulbOutlined />} loading={loading} onClick={handleRecommend}>获取推荐</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : recommendResult ? (
                  recommendations.length > 0 ? (
                    <Table dataSource={recommendations.map((r, i) => ({ ...r, key: i }))} columns={recommendColumns} size="small" pagination={{ pageSize: 10, size: 'small' }} />
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无推荐操作</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>点击获取推荐操作</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
};

export default Decay;
