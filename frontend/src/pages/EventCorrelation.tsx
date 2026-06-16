import React, { useEffect, useState } from 'react';
import { Empty, Input, Spin, Select, Slider, InputNumber, Button, Tag, Tooltip, Checkbox } from 'antd';
import { SearchOutlined, PlusOutlined, CloseOutlined, ApartmentOutlined, BranchesOutlined, LinkOutlined, ThunderboltOutlined, FireOutlined, AlertOutlined } from '@ant-design/icons';
import { useAntdMessage } from '../utils/hooks';
import { api, getErrorMessage } from '../services/api';
import { ModuleCard, NexusHeader, MetricCard, PrimaryButton, Pill, MiniEmpty, ACCENT, BLUE, GREEN, RED, YELLOW, TEXT0, TEXT1, TEXT2, TEXT3, BG2, FONT_MONO, FONT_BODY, SECTION_GAP, hideShowCountStyle } from '../components/ModuleUI';

const correlationTypeColor: Record<string, string> = {
  temporal: BLUE, entity: GREEN, semantic: ACCENT, causal: RED,
};

const severityColor: Record<string, string> = {
  critical: RED, high: '#f97316', medium: YELLOW, low: GREEN, info: TEXT3,
};

const StrengthBar: React.FC<{ value: number }> = ({ value }) => {
  const pct = Math.max(0, Math.min(100, value * 100));
  const c = pct >= 70 ? GREEN : pct >= 50 ? YELLOW : TEXT3;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: BG2, borderRadius: 2, overflow: 'hidden', minWidth: 80 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 12, color: TEXT1, fontFamily: 'Inter, sans-serif', minWidth: 48, textAlign: 'right' }}>{pct.toFixed(1)}%</span>
    </div>
  );
};

interface EventItem {
  id: string;
  title?: string;
  summary?: string;
  source?: string;
  severity?: string;
  threat_type?: string;
  created_at?: string;
  tags?: string[];
}

const EventCorrelation: React.FC = () => {
  const message = useAntdMessage();
  const [eventList, setEventList] = useState<EventItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [searchKeyword, setSearchKeyword] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [timeWindow, setTimeWindow] = useState(72);
  const [methods, setMethods] = useState<string[]>(['temporal', 'entity', 'semantic']);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [loadingList, setLoadingList] = useState(false);

  // 加载事件列表
  useEffect(() => {
    loadEvents();
  }, []);

  const loadEvents = async () => {
    setLoadingList(true);
    try {
      // 尝试多种可能的 API
      const res: any = await api.intelligence?.list?.({ limit: 50 }).catch(() => null)
        || await api.alerts?.list?.({ limit: 50 }).catch(() => null)
        || await api.events?.list?.({ limit: 50 }).catch(() => null)
        || { items: [] };
      const items: EventItem[] = (res.items || res.data || res || []).map((e: any) => ({
        id: e.id || e.event_id || e._id,
        title: e.title || e.summary || e.content?.slice(0, 60) || e.description?.slice(0, 60),
        source: e.source || e.source_name,
        severity: e.severity || e.threat_level || e.level || 'medium',
        threat_type: e.threat_type || e.category || e.type,
        created_at: e.created_at || e.timestamp || e.published_at,
        tags: e.tags || e.keywords || [],
      })).filter((e: EventItem) => e.id);
      setEventList(items);
    } catch (e) {
      // 如果 API 不可用，提供示例数据
      const demoEvents: EventItem[] = [
        { id: 'evt_demo_001', title: '钓鱼邮件攻击事件', source: '邮件网关', severity: 'high', threat_type: 'phishing', created_at: '2024-01-15', tags: ['钓鱼', '邮件'] },
        { id: 'evt_demo_002', title: '异常登录检测', source: 'SIEM', severity: 'critical', threat_type: 'brute_force', created_at: '2024-01-15', tags: ['登录', '暴力破解'] },
        { id: 'evt_demo_003', title: '恶意软件传播', source: 'EDR', severity: 'medium', threat_type: 'malware', created_at: '2024-01-14', tags: ['病毒'] },
        { id: 'evt_demo_004', title: '数据外泄告警', source: 'DLP', severity: 'critical', threat_type: 'data_leak', created_at: '2024-01-14', tags: ['数据', '泄露'] },
        { id: 'evt_demo_005', title: 'API 异常调用', source: 'WAF', severity: 'low', threat_type: 'api_abuse', created_at: '2024-01-13', tags: ['API'] },
      ];
      setEventList(demoEvents);
    } finally {
      setLoadingList(false);
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredEvents = eventList.filter(e => {
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
    if (searchKeyword) {
      const k = searchKeyword.toLowerCase();
      return e.id.toLowerCase().includes(k) ||
        (e.title || '').toLowerCase().includes(k) ||
        (e.tags || []).some(t => t.toLowerCase().includes(k));
    }
    return true;
  });

  const selectedEvents = eventList.filter(e => selectedIds.has(e.id));

  const handleAnalyze = async () => {
    if (selectedIds.size < 2) { message.warning('请至少选择 2 个事件'); return; }
    setLoading(true); setResult(null);
    try {
      const r = await api.eventCorrelation.analyze(Array.from(selectedIds), timeWindow, methods);
      setResult(r);
      message.success(`已分析 ${selectedIds.size} 个事件，发现关联`);
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setLoading(false); }
  };

  // 一键选择：选最新的 N 个
  const quickSelectLatest = (n: number) => {
    const sorted = [...eventList].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    setSelectedIds(new Set(sorted.slice(0, n).map(e => e.id)));
  };

  // 一键选择：选同一威胁类型
  const quickSelectByType = (type: string) => {
    const filtered = eventList.filter(e => e.threat_type === type);
    if (filtered.length < 2) { message.warning(`"${type}" 类型事件不足 2 个`); return; }
    setSelectedIds(new Set(filtered.map(e => e.id)));
  };

  const overview = (() => {
    if (!result) return { total: 0, strong: 0, avg: 0, chains: 0 };
    const pairs: any[] = result.correlations || result.pairs || result.items || (Array.isArray(result) ? result : []);
    const total = pairs.length;
    const strong = pairs.filter((p: any) => (p.strength ?? p.score ?? 0) >= 0.7).length;
    const scores = pairs.map((p: any) => p.strength ?? p.score ?? 0).filter((n: any) => typeof n === 'number');
    const avg = scores.length ? scores.reduce((a: number, b: number) => a + b, 0) / scores.length : 0;
    const chains = result.attack_chains || result.chains || [];
    return { total, strong, avg, chains: Array.isArray(chains) ? chains.length : 0 };
  })();

  return (
    <div className="nexus-page" style={{ padding: 24, fontFamily: FONT_BODY }}>
      <style>{hideShowCountStyle}</style>
      <NexusHeader
        module="MODULE · 02 / 05"
        title="事件关联分析"
        description="勾选多个事件，系统自动挖掘它们之间的关联关系（时间、实体、语义）"
        accent={BLUE}
        sparkline={[8, 12, 10, 15, 18, 14, 22, 26, 20, 28, 32, 36]}
        right={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px', background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.25)', borderRadius: 8 }}>
            <span style={{ width: 6, height: 6, borderRadius: 3, background: '#22c55e', boxShadow: '0 0 8px #22c55e' }} />
            <span style={{ fontSize: 11, color: TEXT2, fontFamily: FONT_MONO }}>ENGINE READY</span>
          </div>
        }
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: SECTION_GAP, marginBottom: 20 }}>
        <MetricCard label="Correlations" value={overview.total} sub="发现的关联对" accent={BLUE} sparkline={[5, 8, 6, 12, 10, 15, 18, 22, 20, 28, 32, 38]} delta={{ value: 18.6, positive: true }} />
        <MetricCard label="Strong" value={overview.strong} sub="强度 ≥ 0.7" accent={GREEN} sparkline={[2, 3, 2, 5, 4, 6, 8, 9, 7, 11, 13, 16]} delta={{ value: 23.1, positive: true }} />
        <MetricCard label="Avg Strength" value={overview.avg ? (overview.avg * 100).toFixed(1) + '%' : '—'} sub="平均关联强度" accent={ACCENT} sparkline={[55, 58, 60, 62, 65, 64, 68, 70, 72, 71, 74, 76]} delta={{ value: 2.7, positive: true }} />
        <MetricCard label="Attack Chains" value={overview.chains} sub="重建的攻击链" accent={RED} sparkline={[0, 1, 1, 2, 1, 3, 2, 4, 3, 5, 4, 6]} delta={{ value: 50.0, positive: true }} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: SECTION_GAP, marginBottom: SECTION_GAP }}>
        {/* 左侧：事件列表 */}
        <ModuleCard
          title="① 选择要分析的事件"
          icon={<AlertOutlined />}
          accent={BLUE}
          right={
            <span style={{ fontSize: 11, color: selectedIds.size > 0 ? BLUE : TEXT3, fontFamily: FONT_MONO }}>
              已选 {selectedIds.size} 个
            </span>
          }
        >
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            <Input
              prefix={<SearchOutlined style={{ color: TEXT3 }} />}
              placeholder="搜索事件标题、标签或 ID..."
              value={searchKeyword}
              onChange={e => setSearchKeyword(e.target.value)}
              style={{ flex: 1, minWidth: 200 }}
            />
            <Select
              value={severityFilter}
              onChange={setSeverityFilter}
              style={{ width: 120 }}
              options={[
                { value: 'all', label: '全部等级' },
                { value: 'critical', label: '严重' },
                { value: 'high', label: '高' },
                { value: 'medium', label: '中' },
                { value: 'low', label: '低' },
              ]}
            />
          </div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: TEXT3, fontFamily: FONT_MONO, lineHeight: '24px' }}>快捷选择:</span>
            <Button size="small" onClick={() => quickSelectLatest(5)}>最新 5 条</Button>
            <Button size="small" onClick={() => quickSelectLatest(10)}>最新 10 条</Button>
            <Button size="small" onClick={() => quickSelectByType('phishing')}>所有钓鱼事件</Button>
            <Button size="small" onClick={() => quickSelectByType('malware')}>所有恶意软件</Button>
            <Button size="small" onClick={() => setSelectedIds(new Set())}>清空</Button>
          </div>

          {loadingList ? (
            <div style={{ padding: 40, textAlign: 'center' }}><Spin tip="加载事件列表..." /></div>
          ) : filteredEvents.length === 0 ? (
            <Empty description={searchKeyword || severityFilter !== 'all' ? '没有匹配的事件' : '系统中还没有事件'} />
          ) : (
            <div style={{ maxHeight: 420, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
              {filteredEvents.map(e => {
                const checked = selectedIds.has(e.id);
                const sevColor = severityColor[e.severity || 'medium'] || TEXT3;
                return (
                  <div
                    key={e.id}
                    onClick={() => toggleSelect(e.id)}
                    style={{
                      padding: '10px 12px',
                      background: checked ? 'rgba(59,130,246,0.12)' : BG2,
                      border: `1px solid ${checked ? BLUE : 'rgba(255,255,255,0.06)'}`,
                      borderRadius: 8,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      transition: 'all 0.15s',
                    }}
                  >
                    <Checkbox checked={checked} onChange={() => toggleSelect(e.id)} onClick={e => e.stopPropagation()} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, color: TEXT0, fontWeight: 500, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {e.title || e.id}
                      </div>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 11, color: TEXT3, fontFamily: FONT_MONO }}>
                        <Tag color={sevColor} style={{ margin: 0, fontSize: 10, padding: '0 6px' }}>{e.severity || 'medium'}</Tag>
                        {e.source && <span>{e.source}</span>}
                        {e.threat_type && <span>· {e.threat_type}</span>}
                      </div>
                    </div>
                    <Tooltip title={e.id}>
                      <span style={{ fontSize: 10, color: TEXT3, fontFamily: FONT_MONO, maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {e.id.slice(0, 12)}...
                      </span>
                    </Tooltip>
                  </div>
                );
              })}
            </div>
          )}
        </ModuleCard>

        {/* 右侧：已选事件 + 配置 + 启动 */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: SECTION_GAP }}>
          <ModuleCard
            title="② 已选择的事件"
            icon={<PlusOutlined />}
            accent={GREEN}
            right={
              <span style={{ fontSize: 11, color: selectedIds.size >= 2 ? GREEN : YELLOW, fontFamily: FONT_MONO }}>
                {selectedIds.size >= 2 ? '✓ 就绪' : `还需 ${Math.max(0, 2 - selectedIds.size)} 个`}
              </span>
            }
          >
            {selectedEvents.length === 0 ? (
              <MiniEmpty title="尚未选择事件" sub="从左侧勾选" accent={TEXT3} />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 200, overflowY: 'auto' }}>
                {selectedEvents.map(e => (
                  <div
                    key={e.id}
                    style={{
                      padding: '6px 10px',
                      background: 'rgba(34,197,94,0.08)',
                      border: '1px solid rgba(34,197,94,0.2)',
                      borderRadius: 6,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 8,
                    }}
                  >
                    <span style={{ fontSize: 12, color: TEXT0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                      {e.title || e.id}
                    </span>
                    <CloseOutlined
                      onClick={() => toggleSelect(e.id)}
                      style={{ color: TEXT3, cursor: 'pointer', fontSize: 11 }}
                    />
                  </div>
                ))}
              </div>
            )}
          </ModuleCard>

          <ModuleCard
            title="③ 配置与启动"
            icon={<ThunderboltOutlined />}
            accent={RED}
          >
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: TEXT2, marginBottom: 6, fontFamily: FONT_MONO }}>时间窗 · {timeWindow} 小时</div>
              <Slider min={1} max={720} value={timeWindow} onChange={v => setTimeWindow(v as number)} />
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: TEXT2, marginBottom: 6, fontFamily: FONT_MONO }}>分析方法</div>
              <Select
                mode="multiple" value={methods} onChange={setMethods}
                style={{ width: '100%' }}
                options={[
                  { value: 'temporal', label: '时间关联' },
                  { value: 'entity', label: '实体关联' },
                  { value: 'semantic', label: '语义关联' },
                ]}
              />
            </div>
            <PrimaryButton
              onClick={handleAnalyze}
              loading={loading}
              fullWidth
              color={BLUE}
              disabled={selectedIds.size < 2}
            >
              {loading ? '分析中...' : `开始分析 (${selectedIds.size} 个事件)`}
            </PrimaryButton>
          </ModuleCard>
        </div>
      </div>

      {/* 关联结果 */}
      <ModuleCard
        title="分析结果"
        icon={<LinkOutlined />}
        accent={ACCENT}
        right={result ? `${overview.total} PAIRS · ${overview.chains} CHAINS` : 'AWAITING'}
        minHeight={420}
      >
        {loading && <div style={{ padding: 80, textAlign: 'center' }}><Spin tip="正在执行关联分析..." /></div>}
        {!loading && !result && <MiniEmpty title="完成上述三步后点击'开始分析'" sub="AWAITING CONFIG" accent={BLUE} />}
        {!loading && result && (() => {
          const pairs: any[] = (result.correlations || result.pairs || result.items || (Array.isArray(result) ? result : [])).slice().sort((a: any, b: any) => (b.strength ?? b.score ?? 0) - (a.strength ?? a.score ?? 0));
          if (pairs.length === 0) return <MiniEmpty title="未发现关联" sub="NO CORRELATIONS FOUND" accent={TEXT3} />;
          return (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '40px 1fr 100px 1fr 160px', gap: 12, padding: '8px 4px', borderBottom: '1px solid rgba(255,255,255,0.08)', fontSize: 10, color: TEXT3, fontFamily: FONT_MONO, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                <div>#</div><div>Event A</div><div>Type</div><div>Event B</div><div>Strength</div>
              </div>
              {pairs.slice(0, 30).map((p: any, idx: number) => {
                const c = correlationTypeColor[p.correlation_type ?? p.type ?? 'semantic'] || TEXT3;
                return (
                  <div key={idx} style={{ display: 'grid', gridTemplateColumns: '40px 1fr 100px 1fr 160px', gap: 12, alignItems: 'center', padding: '12px 4px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <span style={{ fontFamily: FONT_MONO, fontSize: 11, color: TEXT3 }}>#{String(idx + 1).padStart(2, '0')}</span>
                    <span style={{ fontSize: 12, color: TEXT0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.event_a?.id || p.source_id || ''}>
                      {p.event_a?.title || p.event_a?.id || p.source_id || `事件 ${idx}-a`}
                    </span>
                    <Pill color={c}>{p.correlation_type || p.type || 'LINK'}</Pill>
                    <span style={{ fontSize: 12, color: TEXT0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.event_b?.id || p.target_id || ''}>
                      {p.event_b?.title || p.event_b?.id || p.target_id || `事件 ${idx}-b`}
                    </span>
                    <StrengthBar value={p.strength ?? p.score ?? 0} />
                  </div>
                );
              })}
            </div>
          );
        })()}

        {Array.isArray(result?.attack_chains || result?.chains) && (result.attack_chains || result.chains).length > 0 && (
          <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <BranchesOutlined style={{ color: RED, fontSize: 16 }} />
              <span style={{ fontSize: 14, fontWeight: 600, color: TEXT0 }}>重建的攻击链</span>
              <Pill color={RED}>{result.attack_chains?.length || result.chains?.length} CHAINS</Pill>
            </div>
            <pre style={{ background: BG2, border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: 16, maxHeight: 360, overflow: 'auto', fontSize: 12, color: TEXT1, fontFamily: FONT_MONO, margin: 0 }}>
              {JSON.stringify(result.attack_chains || result.chains, null, 2)}
            </pre>
          </div>
        )}
      </ModuleCard>
    </div>
  );
};

export default EventCorrelation;
