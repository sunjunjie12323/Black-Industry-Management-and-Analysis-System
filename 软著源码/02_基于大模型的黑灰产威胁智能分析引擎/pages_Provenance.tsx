import React, { useState, useEffect } from 'react';
import { Input, Button, Steps, Timeline, Table, Tag, Spin, Empty, Tabs, Progress, Descriptions } from 'antd';
import { SafetyCertificateOutlined, AuditOutlined, WarningOutlined, SearchOutlined, LinkOutlined, FileSearchOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const STAGE_COLORS: Record<string, string> = {
  raw_collection: 'var(--primary)', cleaned: 'var(--green)', analyzed: 'var(--blue)',
  enriched: 'var(--yellow)', reported: 'var(--red)', pir_generated: 'var(--blue)',
};
const STAGE_ZH: Record<string, string> = {
  raw_collection: '原始采集', cleaned: '已清洗', analyzed: '已分析',
  enriched: '已增强', reported: '已报告', pir_generated: '已生成需求',
};

const Provenance: React.FC = () => {
  const message = useAntdMessage();
  const [intelId, setIntelId] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [verifyResult, setVerifyResult] = useState<Record<string, unknown> | null>(null);
  const [chainResult, setChainResult] = useState<Record<string, unknown> | null>(null);
  const [evolutionResult, setEvolutionResult] = useState<Record<string, unknown> | null>(null);
  const [hallucinationResult, setHallucinationResult] = useState<Record<string, unknown> | null>(null);
  const [searchResult, setSearchResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('verify');

  const handleVerify = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setVerifyResult(null);
    try { const res = await api.provenance.verify(intelId.trim()); setVerifyResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleChain = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setChainResult(null);
    try { const res = await api.provenance.chain(intelId.trim()); setChainResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleEvolution = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setEvolutionResult(null);
    try { const res = await api.provenance.evolution(intelId.trim()); setEvolutionResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleHallucination = async () => {
    if (!intelId.trim()) { message.warning('请输入情报ID'); return; }
    setLoading(true); setHallucinationResult(null);
    try { const res = await api.provenance.hallucinationCheck(intelId.trim()); setHallucinationResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) { message.warning('请输入搜索内容'); return; }
    setLoading(true); setSearchResult(null);
    try { const res = await api.provenance.searchByContent(searchQuery.trim()); setSearchResult(res as Record<string, unknown>); }
    catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  const chainSteps: { title: string; description: string; color: string }[] = (() => {
    if (!chainResult) return [];
    const steps = (chainResult.chain || chainResult.steps || chainResult.records || []) as Record<string, unknown>[];
    return steps.map((item, i) => ({
      title: (item.stage || item.type || item.action || `阶段 ${i + 1}`) as string,
      description: (item.description || item.detail || item.source || '') as string,
      color: STAGE_COLORS[(item.stage as string)] || 'var(--primary)',
    }));
  })();

  const evolutionSteps = (() => {
    if (!evolutionResult) return [];
    const steps = (evolutionResult.evolution || evolutionResult.steps || evolutionResult.stages || []) as Record<string, unknown>[];
    return steps.map((step, i) => ({
      title: (step.stage || step.phase || `阶段 ${i + 1}`) as string,
      description: (step.description || step.change || step.detail || '') as string,
      color: STAGE_COLORS[(step.stage as string)] || 'var(--blue)',
    }));
  })();

  const searchResults = (() => {
    if (!searchResult) return [];
    return (searchResult.results || searchResult.records || searchResult.items || []) as Record<string, unknown>[];
  })();

  const searchColumns = [
    { title: '情报ID', dataIndex: 'intelligence_id', key: 'intelligence_id', width: 120, render: (val: unknown) => <a onClick={() => setIntelId(String(val))} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--primary)' }}>{String(val).slice(0, 8)}…</a> },
    { title: '阶段', dataIndex: 'stage', key: 'stage', width: 120, render: (val: unknown) => { const color = STAGE_COLORS[String(val)] || 'var(--text-2)'; return <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: `${color}15`, color, fontSize: 11, fontWeight: 500 }}>{STAGE_ZH[String(val)] || String(val)}</span>; } },
    { title: '内容摘要', dataIndex: 'content', key: 'content', ellipsis: true, render: (val: unknown) => <span style={{ color: 'var(--text-2)', fontSize: 12 }}>{String(val || '-').slice(0, 80)}</span> },
  ];

  return (
    <div style={{ minHeight: '100%' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>溯源链</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>验证情报来源可靠性，追踪信息传播路径</p>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'verify',
            label: '验证',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>输入情报ID验证其来源可靠性和数据完整性</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID进行验证" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleVerify} />
                  </div>
                  <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={handleVerify}>验证</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : verifyResult ? (
                  <div style={{ padding: 20, background: verifyResult.is_valid || verifyResult.verified ? 'var(--green-dim)' : 'var(--red-dim)', borderRadius: 'var(--radius)', border: `1px solid ${verifyResult.is_valid || verifyResult.verified ? 'var(--green)' : 'var(--red)'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                      {verifyResult.is_valid || verifyResult.verified ? <CheckCircleOutlined style={{ fontSize: 20, color: 'var(--green)' }} /> : <CloseCircleOutlined style={{ fontSize: 20, color: 'var(--red)' }} />}
                      <span style={{ fontSize: 16, fontWeight: 600, color: verifyResult.is_valid || verifyResult.verified ? 'var(--green)' : 'var(--red)' }}>{verifyResult.is_valid || verifyResult.verified ? '验证通过' : '验证失败'}</span>
                    </div>
                    <Descriptions column={1} size="small" bordered>
                      {Object.entries(verifyResult).filter(([k]) => !['is_valid', 'verified'].includes(k)).slice(0, 8).map(([key, val]) => (
                        <Descriptions.Item key={key} label={<span style={{ color: 'var(--text-2)' }}>{key}</span>}><span style={{ color: 'var(--text-0)' }}>{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span></Descriptions.Item>
                      ))}
                    </Descriptions>
                  </div>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID进行溯源验证</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'chain',
            label: '溯源链',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>查看情报从采集到分析再到报告的完整溯源链路</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID查看完整溯源链" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleChain} />
                  </div>
                  <Button type="primary" icon={<LinkOutlined />} loading={loading} onClick={handleChain}>查看链路</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : chainResult ? (
                  chainSteps.length > 0 ? (
                    <Timeline items={chainSteps.map((step, i) => ({
                      color: step.color as 'blue' | 'green' | 'red' | 'gray' | undefined,
                      children: (
                        <div key={i} style={{ padding: '10px 14px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 13, fontWeight: 600, color: step.color, marginBottom: 4 }}>{step.title}</div>
                          <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{step.description}</div>
                        </div>
                      ),
                    }))} />
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无溯源链数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID查看溯源链</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'evolution',
            label: '演化',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>追踪情报在各处理阶段间的演化变化过程</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID追踪演化过程" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleEvolution} />
                  </div>
                  <Button type="primary" icon={<AuditOutlined />} loading={loading} onClick={handleEvolution}>追踪演化</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : evolutionResult ? (
                  evolutionSteps.length > 0 ? (
                    <Steps direction="vertical" size="small" current={evolutionSteps.length - 1} items={evolutionSteps.map((step, i) => ({
                      title: <span style={{ color: step.color, fontWeight: 500 }}>{step.title}</span>,
                      description: <span style={{ color: 'var(--text-2)' }}>{step.description}</span>,
                      icon: <div style={{ width: 24, height: 24, borderRadius: '50%', background: `${step.color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, color: step.color, fontWeight: 600, border: `1px solid ${step.color}30` }}>{i + 1}</div>,
                    }))} />
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无演化数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID追踪演化</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'hallucination',
            label: '幻觉检测',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>检测AI生成内容中是否存在幻觉或虚假信息</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>情报 ID</label>
                    <Input placeholder="输入情报ID检测AI幻觉" value={intelId} onChange={e => setIntelId(e.target.value)} onPressEnter={handleHallucination} />
                  </div>
                  <Button type="primary" icon={<WarningOutlined />} loading={loading} onClick={handleHallucination}>检测幻觉</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : hallucinationResult ? (
                  <div style={{ padding: 20, background: 'var(--red-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--red)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                      <WarningOutlined style={{ fontSize: 18, color: 'var(--red)' }} />
                      <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--red)' }}>幻觉检测结果</span>
                    </div>
                    {hallucinationResult.hallucination_score != null && (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>幻觉评分</div>
                        <Progress percent={Math.round((hallucinationResult.hallucination_score as number) * 100)} strokeColor={(hallucinationResult.hallucination_score as number) > 0.5 ? 'var(--red)' : 'var(--green)'} />
                      </div>
                    )}
                    {Array.isArray(hallucinationResult.hallucinations) && (hallucinationResult.hallucinations as unknown[]).length > 0 && (
                      <div>
                        <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>检测到的幻觉内容</div>
                        {(hallucinationResult.hallucinations as Record<string, unknown>[]).map((h, i) => (
                          <div key={i} style={{ padding: '8px 12px', background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: 6 }}>
                            <span style={{ fontSize: 12, color: 'var(--red)' }}>{String(h.content || h.description || h.type || JSON.stringify(h))}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入情报ID检测AI幻觉</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
          {
            key: 'search',
            label: '搜索',
            children: (
              <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
                <p style={{ fontSize: 13, color: 'var(--text-2)', margin: '0 0 16px' }}>按内容关键词搜索溯源记录</p>
                <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>搜索内容</label>
                    <Input placeholder="输入搜索内容..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} onPressEnter={handleSearch} />
                  </div>
                  <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={handleSearch}>搜索</Button>
                </div>
                {loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div> : searchResult ? (
                  searchResults.length > 0 ? (
                    <Table dataSource={searchResults.map((r, i) => ({ ...r, key: i }))} columns={searchColumns} size="small" pagination={{ pageSize: 10, size: 'small' }} />
                  ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>未找到匹配的溯源记录</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>输入关键词搜索溯源记录</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
};

export default Provenance;
