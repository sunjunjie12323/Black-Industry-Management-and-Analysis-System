import React, { useState, useEffect } from 'react';
import { Input, Button, Table, Tag, Progress, Spin, Empty, Tabs } from 'antd';
import { BugOutlined, SearchOutlined, SwapOutlined, DeploymentUnitOutlined } from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const { TextArea } = Input;

const ZeroDay: React.FC = () => {
  const message = useAntdMessage();
  const [detectText, setDetectText] = useState('');
  const [driftTerm, setDriftTerm] = useState('');
  const [migrationTerm, setMigrationTerm] = useState('');
  const [detectResult, setDetectResult] = useState<Record<string, unknown> | null>(null);
  const [driftResult, setDriftResult] = useState<Record<string, unknown> | null>(null);
  const [migrationResult, setMigrationResult] = useState<Record<string, unknown> | null>(null);
  const [recentData, setRecentData] = useState<Record<string, unknown> | null>(null);
  const [detectLoading, setDetectLoading] = useState(false);
  const [driftLoading, setDriftLoading] = useState(false);
  const [migrationLoading, setMigrationLoading] = useState(false);
  const [recentLoading, setRecentLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('detect');

  useEffect(() => {
    (async () => {
      try { const res = await api.zeroDay.getRecentDetections(20); setRecentData(res); }
      catch {} finally { setRecentLoading(false); }
    })();
  }, []);

  const handleDetect = async () => {
    if (!detectText.trim()) { message.warning('请输入待检测文本'); return; }
    setDetectLoading(true); setDetectResult(null);
    try { const res = await api.zeroDay.detect(detectText); setDetectResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setDetectLoading(false); }
  };

  const handleDrift = async () => {
    if (!driftTerm.trim()) { message.warning('请输入术语'); return; }
    setDriftLoading(true); setDriftResult(null);
    try { const res = await api.zeroDay.trackDrift(driftTerm); setDriftResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setDriftLoading(false); }
  };

  const handleMigration = async () => {
    if (!migrationTerm.trim()) { message.warning('请输入术语'); return; }
    setMigrationLoading(true); setMigrationResult(null);
    try { const res = await api.zeroDay.trackMigration(migrationTerm); setMigrationResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setMigrationLoading(false); }
  };

  const detectedTerms = (detectResult?.terms || detectResult?.detected_terms || detectResult?.results || []) as Record<string, unknown>[];
  const confidence = detectResult?.confidence as number | undefined;
  const recommendations = (detectResult?.recommendations || detectResult?.suggestions || []) as string[];

  const driftPoints = (() => {
    if (!driftResult) return [];
    const points = (driftResult.drift_points || driftResult.timeline || driftResult.history || []) as Record<string, unknown>[];
    return points.map((p, i) => ({
      time: (p.time || p.date || p.period || `T${i + 1}`) as string,
      score: ((p.score || p.similarity || p.value || p.drift_score || 0) as number),
    }));
  })();

  const migrationPaths = (() => {
    if (!migrationResult) return [];
    return (migrationResult.migrations || migrationResult.paths || migrationResult.platforms || []) as Record<string, unknown>[];
  })();

  const recentDetections = (() => {
    if (!recentData) return [];
    return (recentData.detections || recentData.items || recentData.results || []) as Record<string, unknown>[];
  })();

  const detectColumns = [
    { title: '术语', dataIndex: 'term', key: 'term', render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{String(val || r.name || r.word || '')}</span> },
    { title: '置信度', dataIndex: 'score', key: 'score', width: 140, render: (val: unknown) => { const score = (val || 0) as number; const color = score >= 0.7 ? 'var(--red)' : score >= 0.4 ? 'var(--yellow)' : 'var(--green)'; return <Progress percent={Math.round(score * 100)} size="small" strokeColor={color} />; } },
    { title: '类别', dataIndex: 'category', key: 'category', width: 120, render: (val: unknown) => <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--primary-dim)', color: 'var(--primary)', fontSize: 11, fontWeight: 500 }}>{String(val || '未知')}</span> },
  ];

  const migrationColumns = [
    { title: '平台/社区', dataIndex: 'platform', key: 'platform', render: (val: unknown, r: Record<string, unknown>) => <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--teal-dim)', color: 'var(--teal)', fontSize: 11, fontWeight: 500 }}>{String(val || r.community || r.source || '未知')}</span> },
    { title: '使用频率', dataIndex: 'frequency', key: 'frequency', width: 100, render: (val: unknown, r: Record<string, unknown>) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-0)' }}>{String(val || r.count || '-')}</span> },
    { title: '语义偏移', dataIndex: 'shift', key: 'shift', width: 100, render: (val: unknown, r: Record<string, unknown>) => { const val2 = (val || r.drift || 0) as number; const color = val2 > 0.5 ? 'var(--red)' : val2 > 0.2 ? 'var(--yellow)' : 'var(--green)'; return <span style={{ fontFamily: 'var(--font-mono)', color, fontWeight: 500 }}>{val2.toFixed(2)}</span>; } },
  ];

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>零日检测</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>识别新兴黑话和未知威胁术语，追踪语义漂移</p>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'detect',
            label: '检测',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>输入可疑文本，系统将识别其中的新兴黑话和未知威胁术语</p>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>待检测文本</label>
                  <TextArea rows={4} placeholder="输入待检测文本，识别潜在的零日漏洞特征..." value={detectText} onChange={e => setDetectText(e.target.value)} style={{ marginBottom: 12 }} />
                  <Button type="primary" icon={<SearchOutlined />} loading={detectLoading} onClick={handleDetect}>检测</Button>
                </div>
                {detectLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : detectResult ? (
                  <>
                    {confidence != null && (
                      <div style={{ padding: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: 16 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>检测置信度</div>
                        <Progress percent={Math.round(confidence * 100)} strokeColor={confidence >= 0.7 ? 'var(--red)' : 'var(--yellow)'} />
                      </div>
                    )}
                    {detectedTerms.length > 0 && (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }}>检测到的零日术语</div>
                        <Table dataSource={detectedTerms.map((t, i) => ({ ...t, key: i }))} columns={detectColumns} size="small" pagination={false} />
                      </div>
                    )}
                    {recommendations.length > 0 && (
                      <div style={{ padding: 16, background: 'var(--primary-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--primary-light)' }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }}>建议操作</div>
                        {recommendations.map((r, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                            <div style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--primary)', marginTop: 6, flexShrink: 0 }} />
                            <span style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6 }}>{r}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入文本并点击检测</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'drift',
            label: '漂移追踪',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>追踪术语在不同时期的语义变化，发现含义偏移趋势</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>追踪术语</label>
                    <Input placeholder="输入术语追踪语义漂移..." value={driftTerm} onChange={e => setDriftTerm(e.target.value)} onPressEnter={handleDrift} />
                  </div>
                  <Button type="primary" icon={<SwapOutlined />} loading={driftLoading} onClick={handleDrift}>追踪漂移</Button>
                </div>
                {driftLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : driftResult ? (
                  <>
                    {driftPoints.length > 0 ? (
                      <div className="chart-reveal chart-d-1">
                        <ResponsiveContainer width="100%" height={300}>
                          <LineChart data={driftPoints} margin={{ top: 10, right: 20, left: -10, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                          <XAxis dataKey="time" tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" />
                          <YAxis tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" domain={[0, 1]} />
                          <RTooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} />
                          <Line type="monotone" dataKey="score" stroke="var(--yellow)" strokeWidth={2} dot={{ fill: 'var(--yellow)', r: 3 }} activeDot={{ r: 5, fill: 'var(--yellow)' }} isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                        </LineChart>
                      </ResponsiveContainer>
                      </div>
                    ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无漂移数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                    {driftResult.drift_summary && (
                      <div style={{ marginTop: 16, padding: 16, background: 'var(--yellow-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--yellow)' }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>漂移摘要</div>
                        <div style={{ fontSize: 13, color: 'var(--yellow)', lineHeight: 1.6 }}>{String(driftResult.drift_summary)}</div>
                      </div>
                    )}
                  </>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入术语追踪语义变化</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'migration',
            label: '迁移追踪',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>追踪术语在不同平台和社区间的传播迁移路径</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>追踪术语</label>
                    <Input placeholder="输入术语追踪跨平台迁移..." value={migrationTerm} onChange={e => setMigrationTerm(e.target.value)} onPressEnter={handleMigration} />
                  </div>
                  <Button type="primary" icon={<DeploymentUnitOutlined />} loading={migrationLoading} onClick={handleMigration}>追踪迁移</Button>
                </div>
                {migrationLoading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : migrationResult ? (
                  <>
                    {migrationPaths.length > 0 ? (
                      <Table dataSource={migrationPaths.map((p, i) => ({ ...p, key: i }))} columns={migrationColumns} size="small" pagination={false} />
                    ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无迁移数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                    {migrationResult.migration_summary && (
                      <div style={{ marginTop: 16, padding: 16, background: 'var(--teal-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--teal)' }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>迁移摘要</div>
                        <div style={{ fontSize: 13, color: 'var(--teal)', lineHeight: 1.6 }}>{String(migrationResult.migration_summary)}</div>
                      </div>
                    )}
                  </>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入术语追踪跨平台迁移</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
};

export default ZeroDay;
