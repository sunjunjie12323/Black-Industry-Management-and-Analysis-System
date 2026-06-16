import React, { useState, useEffect, useCallback } from 'react';
import { Input, Button, Slider, Steps, Progress, Tag, Table, Spin, Empty, Tooltip, Collapse, Select, Checkbox, Tag as AntdTag } from 'antd';
import { AimOutlined, AlertOutlined, ExperimentOutlined, SearchOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer, Line } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

interface EntityItem {
  id: string;
  name: string;
  type?: string;
  risk_score?: number;
  category?: string;
}

const AttackPrediction: React.FC = () => {
  const message = useAntdMessage();
  const [selectedEntity, setSelectedEntity] = useState<EntityItem | null>(null);
  const [entityList, setEntityList] = useState<EntityItem[]>([]);
  const [entitySearch, setEntitySearch] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState<string>('all');
  const [depth, setDepth] = useState(5);
  const [steps, setSteps] = useState(5);
  const [predictResult, setPredictResult] = useState<Record<string, unknown> | null>(null);
  const [simulateResult, setSimulateResult] = useState<Record<string, unknown> | null>(null);
  const [warningResult, setWarningResult] = useState<Record<string, unknown> | null>(null);
  const [vizData, setVizData] = useState<Record<string, unknown> | null>(null);
  const [predictLoading, setPredictLoading] = useState(false);
  const [simulateLoading, setSimulateLoading] = useState(false);
  const [warningLoading, setWarningLoading] = useState(false);
  const [vizLoading, setVizLoading] = useState(true);
  const [loadingEntities, setLoadingEntities] = useState(false);
  const [history, setHistory] = useState<{ id?: string; action: string; input: string; time: string }[]>([]);

  useEffect(() => {
    (async () => {
      try { const res = await api.attackPrediction.getVisualization(); setVizData(res); }
      catch {} finally { setVizLoading(false); }
    })();
    loadEntities();
  }, []);

  const loadEntities = async () => {
    setLoadingEntities(true);
    try {
      const res: any = await api.entities?.list?.({ limit: 100 }).catch(() => null)
        || await api.graph?.getEntities?.({ limit: 100 }).catch(() => null)
        || { items: [] };
      const items: EntityItem[] = (res.items || res.data || res.entities || res || []).map((e: any) => ({
        id: e.id || e.entity_id || e._id,
        name: e.name || e.value || e.label || e.id,
        type: e.type || e.entity_type || e.category,
        risk_score: e.risk_score || e.score || e.confidence,
        category: e.category || e.sub_type,
      })).filter((e: EntityItem) => e.id);
      setEntityList(items);
    } catch (e) {
      // Demo 数据
      setEntityList([
        { id: 'ent_001', name: '192.168.1.100', type: 'ip', risk_score: 0.85 },
        { id: 'ent_002', name: 'evil.com', type: 'domain', risk_score: 0.92 },
        { id: 'ent_003', name: 'APT-29 组织', type: 'organization', risk_score: 0.78 },
        { id: 'ent_004', name: 'user@company.com', type: 'email', risk_score: 0.65 },
        { id: 'ent_005', name: 'malware_hash_abc', type: 'hash', risk_score: 0.88 },
        { id: 'ent_006', name: '10.0.0.5', type: 'ip', risk_score: 0.45 },
        { id: 'ent_007', name: 'phishing-site.cn', type: 'domain', risk_score: 0.71 },
      ]);
    } finally {
      setLoadingEntities(false);
    }
  };

  const addHistory = useCallback((action: string, input: string) => {
    setHistory(prev => [{ action, input, time: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }, ...prev].slice(0, 15));
  }, []);

  const handlePredict = async () => {
    if (!selectedEntity) { message.warning('请先选择一个实体'); return; }
    setPredictLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const res = await api.attackPrediction.predict(selectedEntity.id, depth);
      setPredictResult(res as Record<string, unknown>);
      addHistory('预测攻击链', selectedEntity.name);
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setPredictLoading(false); }
  };

  const handleSimulate = async () => {
    if (!selectedEntity) { message.warning('请先选择一个实体'); return; }
    setSimulateLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const res = await api.attackPrediction.simulate(selectedEntity.id, steps);
      setSimulateResult(res as Record<string, unknown>);
      addHistory('模拟推演', selectedEntity.name);
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setSimulateLoading(false); }
  };

  const handleEarlyWarning = async () => {
    if (!selectedEntity) { message.warning('请先选择一个实体'); return; }
    setWarningLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const res = await api.attackPrediction.earlyWarning(selectedEntity.id);
      setWarningResult(res as Record<string, unknown>);
      addHistory('早期预警', selectedEntity.name);
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setWarningLoading(false); }
  };

  const filteredEntities = entityList.filter(e => {
    if (entityTypeFilter !== 'all' && e.type !== entityTypeFilter) return false;
    if (entitySearch) {
      const k = entitySearch.toLowerCase();
      return e.name.toLowerCase().includes(k) || e.id.toLowerCase().includes(k);
    }
    return true;
  });

  const typeColor = (type?: string) => {
    const map: Record<string, string> = {
      ip: 'blue', domain: 'purple', email: 'cyan', hash: 'orange',
      organization: 'red', person: 'green', url: 'magenta',
    };
    return map[type || ''] || 'default';
  };

  const attackChain = (Array.isArray(predictResult?.attack_chain || predictResult?.steps || predictResult?.chain) ? (predictResult?.attack_chain || predictResult?.steps || predictResult?.chain) : []) as Record<string, unknown>[];
  const probability = predictResult?.probability as number | undefined;
  const warningLevel = warningResult?.warning_level as string | undefined;
  const warningScore = warningResult?.risk_score as number | undefined;
  const simulateSteps = (Array.isArray(simulateResult?.steps || simulateResult?.simulation_steps) ? (simulateResult?.steps || simulateResult?.simulation_steps) : []) as Record<string, unknown>[];

  const chartData = (() => {
    if (!vizData) return [];
    const nodes = (vizData.nodes || vizData.entities || []) as Record<string, unknown>[];
    if (nodes.length === 0) return [];
    return nodes.slice(0, 20).map((n, i) => ({
      name: (n.name || n.value || n.id || `Node${i}`) as string,
      score: ((n.score || n.risk_score || n.confidence || 0) as number) * 100,
      connections: ((n.degree || n.connections || n.relation_count || 0) as number),
    }));
  })();

  const stepItems = attackChain.map((step, i) => ({
    title: (step.stage || step.phase || step.type || `阶段 ${i + 1}`) as string,
    description: (step.description || step.action || step.target || '') as string,
    status: (i < attackChain.length - 1 ? 'finish' : 'process') as 'finish' | 'process',
  }));

  const simStepItems = simulateSteps.map((step, i) => ({
    title: (step.stage || step.step || `Step ${i + 1}`) as string,
    description: (step.description || step.action || step.entity || '') as string,
    status: (i < simulateSteps.length - 1 ? 'finish' : 'process') as 'finish' | 'process',
  }));

  const historyColumns = [
    { title: '操作', dataIndex: 'action', key: 'action', width: 120, render: (val: string) => {
      const colorMap: Record<string, string> = { '预测攻击链': 'var(--primary)', '模拟推演': 'var(--green)', '早期预警': 'var(--red)' };
      return <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--primary-dim)', color: colorMap[val] || 'var(--primary)', fontSize: 11, fontWeight: 500 }}>{val}</span>;
    }},
    { title: '输入', dataIndex: 'input', key: 'input', ellipsis: true, render: (val: string) => <span style={{ color: 'var(--text-1)' }}>{val}</span> },
    { title: '时间', dataIndex: 'time', key: 'time', width: 100, render: (val: string) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-2)' }}>{val}</span> },
  ];

  return (
    <div style={{ minHeight: '100%', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-0)', margin: 0, fontFamily: 'var(--font-body)' }}>攻击链预测</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>从实体列表中选择目标，系统将基于知识图谱预测可能的攻击路径</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: 16, marginBottom: 24 }}>
        {/* 左侧：实体选择 */}
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>① 选择实体</div>
          <Input
            prefix={<SearchOutlined style={{ color: 'var(--text-3)' }} />}
            placeholder="搜索实体名或 ID..."
            value={entitySearch}
            onChange={e => setEntitySearch(e.target.value)}
            style={{ marginBottom: 10 }}
          />
          <Select
            value={entityTypeFilter}
            onChange={setEntityTypeFilter}
            style={{ width: '100%', marginBottom: 12 }}
            options={[
              { value: 'all', label: '全部类型' },
              { value: 'ip', label: 'IP 地址' },
              { value: 'domain', label: '域名' },
              { value: 'email', label: '邮箱' },
              { value: 'hash', label: '文件哈希' },
              { value: 'organization', label: '组织' },
            ]}
          />
          {loadingEntities ? (
            <div style={{ padding: 30, textAlign: 'center' }}><Spin /></div>
          ) : filteredEntities.length === 0 ? (
            <Empty description="没有匹配的实体" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <div style={{ maxHeight: 360, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
              {filteredEntities.map(e => {
                const sel = selectedEntity?.id === e.id;
                return (
                  <div
                    key={e.id}
                    onClick={() => setSelectedEntity(e)}
                    style={{
                      padding: '10px 12px',
                      background: sel ? 'var(--primary-dim)' : 'var(--bg-2)',
                      border: `1px solid ${sel ? 'var(--primary)' : 'var(--border)'}`,
                      borderRadius: 8,
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 13, color: 'var(--text-0)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.name}</span>
                      {e.risk_score != null && (
                        <span style={{ fontSize: 11, color: e.risk_score > 0.7 ? 'var(--red)' : e.risk_score > 0.4 ? 'var(--accent)' : 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                          {(e.risk_score * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <AntdTag color={typeColor(e.type)} style={{ margin: 0, fontSize: 10, padding: '0 6px' }}>{e.type || 'unknown'}</AntdTag>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 右侧：配置 + 操作 */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>② 已选择</div>
            {selectedEntity ? (
              <div style={{ padding: 16, background: 'var(--bg-2)', borderRadius: 8, border: '1px solid var(--primary-light)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <AntdTag color={typeColor(selectedEntity.type)} style={{ margin: 0 }}>{selectedEntity.type}</AntdTag>
                  <span style={{ fontSize: 16, color: 'var(--text-0)', fontWeight: 600 }}>{selectedEntity.name}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>ID: {selectedEntity.id}</div>
              </div>
            ) : (
              <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>← 请从左侧选择</div>
            )}
          </div>

          <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>③ 参数与执行</div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>预测深度: {depth}</label>
              <Slider min={1} max={10} value={depth} onChange={setDepth} />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>模拟步数: {steps}</label>
              <Slider min={1} max={20} value={steps} onChange={setSteps} />
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Button type="primary" icon={<AimOutlined />} loading={predictLoading} onClick={handlePredict} disabled={!selectedEntity}>预测攻击链</Button>
              <Button icon={<ExperimentOutlined />} loading={simulateLoading} onClick={handleSimulate} disabled={!selectedEntity} style={{ background: 'var(--green-dim)', border: '1px solid var(--green)', color: 'var(--green)', fontWeight: 500 }}>模拟推演</Button>
              <Button icon={<AlertOutlined />} loading={warningLoading} onClick={handleEarlyWarning} disabled={!selectedEntity} style={{ background: 'var(--red-dim)', border: '1px solid var(--red)', color: 'var(--red)', fontWeight: 500 }}>早期预警</Button>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>攻击链路径</div>
          {predictLoading || simulateLoading || warningLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div>
          ) : predictResult ? (
            <>
              {stepItems.length > 0 ? (
                <Steps direction="vertical" size="small" current={stepItems.length - 1} items={stepItems.map((step, i) => ({
                  ...step,
                  icon: <div style={{ width: 24, height: 24, borderRadius: '50%', background: 'var(--primary-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, color: 'var(--primary)', fontWeight: 600, border: '1px solid var(--primary-light)' }}>{i + 1}</div>,
                }))} />
              ) : <div style={{ color: 'var(--text-2)', fontSize: 13 }}>攻击链数据为空</div>}
              {probability != null && (
                <div style={{ marginTop: 16, padding: 16, background: 'var(--bg-2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>预测概率</div>
                  <Progress percent={Math.round(probability * 100)} strokeColor="var(--primary)" />
                  <span style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--primary-dim)', color: 'var(--primary)', fontSize: 11, fontWeight: 500, marginTop: 8 }}>置信度 {(probability * 100).toFixed(1)}%</span>
                </div>
              )}
            </>
          ) : simulateResult ? (
            simStepItems.length > 0 ? (
              <Steps direction="vertical" size="small" current={simStepItems.length - 1} items={simStepItems.map((step, i) => ({
                ...step,
                icon: <div style={{ width: 24, height: 24, borderRadius: '50%', background: 'var(--green-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, color: 'var(--green)', fontWeight: 600, border: '1px solid var(--green)' }}>{i + 1}</div>,
              }))} />
            ) : <div style={{ color: 'var(--text-2)', fontSize: 13 }}>模拟数据为空</div>
          ) : warningResult ? (
            <div style={{ padding: 20, background: 'var(--red-dim)', borderRadius: 'var(--radius)', border: '1px solid var(--red)' }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--red)', marginBottom: 12 }}>预警等级：{warningLevel || '未知'}</div>
              {warningScore != null && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 6 }}>风险评分</div>
                  <Progress percent={Math.round(warningScore * 100)} strokeColor="var(--red)" />
                </div>
              )}
              {Array.isArray(warningResult.warnings) && (warningResult.warnings as unknown[]).length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 8 }}>预警详情</div>
                  {(warningResult.warnings as Record<string, unknown>[]).map((w, i) => (
                    <span key={i} style={{ display: 'inline-flex', padding: '2px 10px', borderRadius: 9999, background: 'var(--red-dim)', color: 'var(--red)', fontSize: 11, fontWeight: 500, marginBottom: 4, marginRight: 4 }}>{String(w.type || w.description || w.message || JSON.stringify(w))}</span>
                  ))}
                </div>
              )}
            </div>
          ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>选择实体并执行操作以查看结果</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        </div>

        <div className="chart-reveal chart-d-2" style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>风险可视化</div>
          {vizLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spin /></div>
          ) : chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                <defs>
                  <linearGradient id="gradAccent" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary-light)" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="var(--primary-light)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" tick={{ fill: 'var(--text-2)', fontSize: 10 }} stroke="var(--border)" />
                <YAxis tick={{ fill: 'var(--text-2)', fontSize: 10 }} stroke="var(--border)" />
                <RTooltip contentStyle={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-0)' }} />
                <Area type="monotone" dataKey="score" stroke="var(--primary-light)" fill="url(#gradAccent)" strokeWidth={1.5} isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                <Line type="monotone" dataKey="connections" stroke="var(--green)" strokeWidth={1} dot={false} isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
              </AreaChart>
            </ResponsiveContainer>
          ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>暂无可视化数据</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        </div>
      </div>

      <Collapse
        defaultActiveKey={['historyTable']}
        items={[{
          key: 'historyTable',
          label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>预测历史</span>,
          children: (
            <Table dataSource={history} columns={historyColumns} rowKey={(record) => `pred_${record.id || Math.random().toString(36).slice(2)}`} size="small" pagination={false} locale={{ emptyText: <span style={{ color: 'var(--text-2)' }}>暂无预测记录，执行预测操作后将在此显示</span> }} />
          ),
        }]}
      />
    </div>
  );
};

export default AttackPrediction;
