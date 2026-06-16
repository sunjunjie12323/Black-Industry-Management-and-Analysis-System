import React, { useState, useEffect } from 'react';
import { Input, Button, Table, Tag, Spin, Empty, Tabs, Slider, Progress, Space, Select } from 'antd';
import { SearchOutlined, RadarChartOutlined, TeamOutlined, FileTextOutlined } from '@ant-design/icons';
import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer, ZAxis } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const { TextArea } = Input;

interface ItemOption {
  id: string;
  label: string;
  sub?: string;
  type?: string;
}

const Attribution: React.FC = () => {
  const message = useAntdMessage();
  const [selectedIntel, setSelectedIntel] = useState<ItemOption | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<ItemOption | null>(null);
  const [intelList, setIntelList] = useState<ItemOption[]>([]);
  const [entityList, setEntityList] = useState<ItemOption[]>([]);
  const [fingerprintText, setFingerprintText] = useState('');
  const [threshold, setThreshold] = useState(0.7);
  const [fingerprintResult, setFingerprintResult] = useState<Record<string, unknown> | null>(null);
  const [homologyResult, setHomologyResult] = useState<Record<string, unknown> | null>(null);
  const [reportResult, setReportResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('fingerprint');

  useEffect(() => {
    loadIntelList();
    loadEntityList();
  }, []);

  const loadIntelList = async () => {
    try {
      const res: any = await api.intelligence?.list?.({ limit: 50 }).catch(() => null) || { items: [] };
      const items: ItemOption[] = (res.items || res.data || res || []).map((e: any) => ({
        id: e.id || e.intel_id || e._id,
        label: e.title || e.summary?.slice(0, 40) || e.id,
        sub: e.source || e.threat_type,
        type: e.threat_type || e.severity,
      })).filter((e: ItemOption) => e.id);
      if (items.length === 0) throw new Error('no data');
      setIntelList(items);
    } catch {
      // Demo 数据
      setIntelList([
        { id: 'intel_001', label: 'APT-29 鱼叉邮件攻击', sub: '内部威胁 / 邮件', type: 'critical' },
        { id: 'intel_002', label: 'Emotet 恶意软件变种', sub: '恶意软件', type: 'high' },
        { id: 'intel_003', label: '银行木马 C2 服务器', sub: '金融威胁', type: 'high' },
        { id: 'intel_004', label: '勒索软件 LockBit 3.0', sub: '勒索软件', type: 'critical' },
        { id: 'intel_005', label: '供应链攻击 SolarWinds', sub: '供应链', type: 'critical' },
      ]);
    }
  };

  const loadEntityList = async () => {
    try {
      const res: any = await api.entities?.list?.({ limit: 50 }).catch(() => null) || { items: [] };
      const items: ItemOption[] = (res.items || res.data || res || []).map((e: any) => ({
        id: e.id || e.entity_id || e._id,
        label: e.name || e.value || e.id,
        sub: e.type || e.entity_type,
        type: e.type,
      })).filter((e: ItemOption) => e.id);
      if (items.length === 0) throw new Error('no data');
      setEntityList(items);
    } catch {
      setEntityList([
        { id: 'ent_001', label: '192.168.1.100', sub: 'IP 地址', type: 'ip' },
        { id: 'ent_002', label: 'evil.com', sub: '域名', type: 'domain' },
        { id: 'ent_003', label: 'APT-29 组织', sub: '组织', type: 'organization' },
        { id: 'ent_004', label: 'malware_hash_abc', sub: '文件哈希', type: 'hash' },
        { id: 'ent_005', label: 'user@company.com', sub: '邮箱', type: 'email' },
      ]);
    }
  };

  const handleFingerprint = async () => {
    if (!selectedIntel) { message.warning('请先选择情报'); return; }
    setLoading(true); setFingerprintResult(null);
    try { const res = await api.attribution.fingerprint(selectedIntel.id); setFingerprintResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleHomology = async () => {
    if (!selectedEntity) { message.warning('请先选择实体'); return; }
    setLoading(true); setHomologyResult(null);
    try { const res = await api.attribution.findSame(selectedEntity.id, threshold); setHomologyResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleReport = async () => {
    if (!selectedIntel) { message.warning('请先选择情报'); return; }
    setLoading(true); setReportResult(null);
    try { const res = await api.attribution.report(selectedIntel.id); setReportResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const fingerprintFeatures = (() => {
    if (!fingerprintResult) return [];
    const raw = fingerprintResult.fingerprint || fingerprintResult.features || fingerprintResult.indicators || [];
    return (Array.isArray(raw) ? raw : []) as Record<string, unknown>[];
  })();

  const homologousEntities = (() => {
    if (!homologyResult) return [];
    const raw = homologyResult.homologous_entities || homologyResult.entities || homologyResult.results || [];
    return (Array.isArray(raw) ? raw : []) as Record<string, unknown>[];
  })();

  const scatterData = homologousEntities.map((e, i) => ({
    x: (e.similarity || e.score || 0) as number,
    y: (e.confidence || e.risk_score || Math.random() * 0.5 + 0.3) as number,
    z: ((e.interactions || e.weight || 50 + Math.random() * 100) as number),
    name: (e.name || e.entity_id || e.id || `Entity${i}`) as string,
  }));

  const fingerprintColumns = [
    { title: '特征', dataIndex: 'name', key: 'name', render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{String(val || r.type || r.feature || '-')}</span> },
    { title: '值', dataIndex: 'value', key: 'value', render: (val: unknown, r: Record<string, unknown>) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-1)' }}>{String(val || r.score || r.weight || '-')}</span> },
    { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 140, render: (val: unknown, r: Record<string, unknown>) => { const score = (val || r.score || 0) as number; const color = score >= 0.7 ? 'var(--green)' : score >= 0.4 ? 'var(--yellow)' : 'var(--red)'; return <Progress percent={Math.round(score * 100)} size="small" strokeColor={color} />; } },
    { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (val: unknown) => <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--purple-dim)', color: 'var(--purple)', fontSize: 11, fontWeight: 500 }}>{String(val || '通用')}</span> },
  ];

  const homologyColumns = [
    { title: '实体', dataIndex: 'name', key: 'name', render: (val: unknown, r: Record<string, unknown>) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{String(val || r.entity_id || r.id || '-')}</span> },
    { title: '相似度', dataIndex: 'similarity', key: 'similarity', width: 140, render: (val: unknown, r: Record<string, unknown>) => { const score = (val || r.score || 0) as number; const color = score >= 0.8 ? 'var(--red)' : score >= 0.5 ? 'var(--yellow)' : 'var(--green)'; return <Progress percent={Math.round(score * 100)} size="small" strokeColor={color} />; } },
    { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 100, render: (val: unknown) => { const score = (val || 0) as number; return <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-0)', fontWeight: 500 }}>{(score * 100).toFixed(0)}%</span>; } },
    { title: '关联特征', dataIndex: 'shared_features', key: 'shared_features', render: (val: unknown, r: Record<string, unknown>) => { const features = (val || r.features || []) as unknown[]; return features.length > 0 ? <Space size={2} wrap>{features.slice(0, 3).map((f, i) => <Tag key={i} style={{ fontSize: 10, margin: 0, borderRadius: 9999, background: 'var(--primary-dim)', color: 'var(--primary)', border: 'none' }}>{String(f)}</Tag>)}{features.length > 3 && <span style={{ fontSize: 10, color: 'var(--text-3)' }}>+{features.length - 3}</span>}</Space> : <span style={{ color: 'var(--text-3)' }}>-</span>; } },
  ];

  // 通用选择器
  const ItemSelector: React.FC<{
    title: string;
    items: ItemOption[];
    selected: ItemOption | null;
    onSelect: (item: ItemOption) => void;
    placeholder: string;
  }> = ({ title, items, selected, onSelect, placeholder }) => (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 8, fontWeight: 500 }}>{title}</div>
      {selected ? (
        <div style={{ padding: '10px 14px', background: 'var(--primary-dim)', border: '1px solid var(--primary)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 13, color: 'var(--text-0)', fontWeight: 500 }}>{selected.label}</div>
            {selected.sub && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{selected.sub}</div>}
          </div>
          <Button size="small" onClick={() => onSelect(null as any)}>更换</Button>
        </div>
      ) : (
        <Select
          showSearch
          placeholder={placeholder}
          style={{ width: '100%' }}
          filterOption={(input, option: any) => option.children.toLowerCase().includes(input.toLowerCase())}
          onChange={(v) => {
            const item = items.find(i => i.id === v);
            if (item) onSelect(item);
          }}
          value={null}
        >
          {items.map(i => (
            <Select.Option key={i.id} value={i.id}>
              {i.label} {i.sub ? `(${i.sub})` : ''}
            </Select.Option>
          ))}
        </Select>
      )}
    </div>
  );

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>实体归因</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>从下拉框中选择情报或实体，识别威胁行为者、发现同源攻击</p>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'fingerprint',
            label: '指纹分析',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>选择一条情报，提取其行为指纹特征用于实体归因</p>
                <ItemSelector
                  title="① 选择情报"
                  items={intelList}
                  selected={selectedIntel}
                  onSelect={setSelectedIntel}
                  placeholder="选择要分析的情报"
                />
                <Button type="primary" icon={<RadarChartOutlined />} loading={loading} onClick={handleFingerprint} disabled={!selectedIntel} block>
                  提取指纹
                </Button>
                <div style={{ marginTop: 20 }}>
                  {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : fingerprintResult ? (
                    <>
                      {fingerprintResult.summary && (
                        <div style={{ padding: 16, background: 'var(--purple-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--purple)', marginBottom: 16 }}>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>指纹摘要</div>
                          <div style={{ fontSize: 13, color: 'var(--purple)', lineHeight: 1.6 }}>{String(fingerprintResult.summary)}</div>
                        </div>
                      )}
                      {fingerprintFeatures.length > 0 ? (
                        <Table dataSource={fingerprintFeatures.map((f, i) => ({ ...f, key: i }))} columns={fingerprintColumns} size="small" pagination={false} />
                      ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无指纹特征数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                    </>
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>选择情报后点击'提取指纹'</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                </div>
              </div>
            ),
          },
          {
            key: 'homology',
            label: '同源发现',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>选择实体，发现与其同源的攻击实体</p>
                <ItemSelector
                  title="① 选择实体"
                  items={entityList}
                  selected={selectedEntity}
                  onSelect={setSelectedEntity}
                  placeholder="选择要分析的实体"
                />
                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>相似度阈值: {threshold.toFixed(2)}</label>
                  <Slider min={0} max={1} step={0.05} value={threshold} onChange={setThreshold} />
                </div>
                <Button type="primary" icon={<TeamOutlined />} loading={loading} onClick={handleHomology} disabled={!selectedEntity} block>
                  发现同源
                </Button>
                <div style={{ marginTop: 20 }}>
                  {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : homologyResult ? (
                    <>
                      {scatterData.length > 0 && (
                        <div className="chart-reveal chart-d-1" style={{ marginBottom: 20 }}>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }}>同源实体分布</div>
                          <ResponsiveContainer width="100%" height={280}>
                            <ScatterChart margin={{ top: 10, right: 20, left: -10, bottom: 5 }}>
                              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                              <XAxis type="number" dataKey="x" name="相似度" tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" domain={[0, 1]} label={{ value: '相似度', position: 'insideBottom', offset: -2, style: { fill: 'var(--text-3)', fontSize: 11 } }} />
                              <YAxis type="number" dataKey="y" name="置信度" tick={{ fill: 'var(--text-2)', fontSize: 11 }} stroke="var(--border)" domain={[0, 1]} label={{ value: '置信度', angle: -90, position: 'insideLeft', style: { fill: 'var(--text-3)', fontSize: 11 } }} />
                              <ZAxis type="number" dataKey="z" range={[60, 300]} />
                              <RTooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} formatter={(val: number, name: string) => [val.toFixed(2), name]} />
                              <Scatter data={scatterData} fill="var(--primary-light)" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                            </ScatterChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                      {homologousEntities.length > 0 ? (
                        <Table dataSource={homologousEntities.map((e, i) => ({ ...e, key: i }))} columns={homologyColumns} size="small" pagination={{ pageSize: 10, size: 'small' }} />
                      ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>未发现同源实体</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                    </>
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>选择实体后点击'发现同源'</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                </div>
              </div>
            ),
          },
          {
            key: 'report',
            label: '归因报告',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>选择情报，生成归因分析报告</p>
                <ItemSelector
                  title="① 选择情报"
                  items={intelList}
                  selected={selectedIntel}
                  onSelect={setSelectedIntel}
                  placeholder="选择要生成报告的情报"
                />
                <Button type="primary" icon={<FileTextOutlined />} loading={loading} onClick={handleReport} disabled={!selectedIntel} block>
                  生成报告
                </Button>
                <div style={{ marginTop: 20 }}>
                  {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : reportResult ? (
                    <div style={{ padding: 20, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                      {reportResult.title ? <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>{String(reportResult.title)}</h3> : null}
                      {reportResult.attribution ? (
                        <div style={{ marginBottom: 16, padding: 16, background: 'var(--purple-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--purple)' }}>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>归因结论</div>
                          <div style={{ fontSize: 14, color: 'var(--purple)', fontWeight: 500, lineHeight: 1.6 }}>{String(reportResult.attribution)}</div>
                        </div>
                      ) : null}
                      {reportResult.confidence != null && (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>归因置信度</div>
                          <Progress percent={Math.round((reportResult.confidence as number) * 100)} strokeColor={(reportResult.confidence as number) >= 0.7 ? 'var(--green)' : 'var(--yellow)'} />
                        </div>
                      )}
                      {reportResult.summary ? (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>分析摘要</div>
                          <div style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>{String(reportResult.summary)}</div>
                        </div>
                      ) : null}
                      {Array.isArray(reportResult.evidence) && (reportResult.evidence as unknown[]).length > 0 && (
                        <div>
                          <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>支撑证据</div>
                          {(reportResult.evidence as Record<string, unknown>[]).map((e, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                              <div style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--primary)', marginTop: 6, flexShrink: 0 }} />
                              <span style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6 }}>{String(e.description || e.type || JSON.stringify(e))}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>选择情报后点击'生成报告'</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                </div>
              </div>
            ),
          },
        ]}
      />
    </div>
  );
};

export default Attribution;
