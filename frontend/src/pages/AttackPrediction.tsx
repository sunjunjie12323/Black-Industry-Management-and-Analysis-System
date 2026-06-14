import React, { useState, useEffect, useCallback } from 'react';
import { Input, Button, Slider, Steps, Progress, Tag, Table, Spin, Empty, Tooltip, Collapse } from 'antd';
import { AimOutlined, AlertOutlined, ExperimentOutlined, SearchOutlined } from '@ant-design/icons';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, ResponsiveContainer, Line } from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const AttackPrediction: React.FC = () => {
  const message = useAntdMessage();
  const [entityInput, setEntityInput] = useState('');
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
  const [history, setHistory] = useState<{ id?: string; action: string; input: string; time: string }[]>([]);

  useEffect(() => {
    (async () => {
      try { const res = await api.attackPrediction.getVisualization(); setVizData(res); }
      catch {} finally { setVizLoading(false); }
    })();
  }, []);

  const addHistory = useCallback((action: string, input: string) => {
    setHistory(prev => [{ action, input, time: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }, ...prev].slice(0, 15));
  }, []);

  const handlePredict = async () => {
    if (!entityInput.trim()) { message.warning('请输入实体ID或名称'); return; }
    setPredictLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const isId = /^[a-f0-9-]{8,}$/i.test(entityInput.trim());
      const res = isId ? await api.attackPrediction.predict(entityInput.trim(), depth) : await api.attackPrediction.predictByName(entityInput.trim(), depth);
      setPredictResult(res as Record<string, unknown>);
      addHistory('预测攻击链', entityInput.trim());
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setPredictLoading(false); }
  };

  const handleSimulate = async () => {
    if (!entityInput.trim()) { message.warning('请输入实体ID'); return; }
    setSimulateLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const res = await api.attackPrediction.simulate(entityInput.trim(), steps);
      setSimulateResult(res as Record<string, unknown>);
      addHistory('模拟推演', entityInput.trim());
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setSimulateLoading(false); }
  };

  const handleEarlyWarning = async () => {
    if (!entityInput.trim()) { message.warning('请输入实体ID'); return; }
    setWarningLoading(true); setPredictResult(null); setSimulateResult(null); setWarningResult(null);
    try {
      const res = await api.attackPrediction.earlyWarning(entityInput.trim());
      setWarningResult(res as Record<string, unknown>);
      addHistory('早期预警', entityInput.trim());
    } catch (e) { message.error(getErrorMessage(e)); }
    finally { setWarningLoading(false); }
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
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '4px 0 0', fontFamily: 'var(--font-body)' }}>基于知识图谱预测可能的攻击路径和威胁演化</p>
      </div>

      <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20, marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end', marginBottom: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>输入实体标识</label>
            <Input placeholder="输入实体ID或名称，如IP、域名、组织名" value={entityInput} onChange={e => setEntityInput(e.target.value)} onPressEnter={handlePredict} />
          </div>
          <div style={{ minWidth: 200 }}>
            <label style={{ fontSize: 12, color: 'var(--text-2)', display: 'block', marginBottom: 4 }}>预测深度</label>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Slider min={1} max={10} value={depth} onChange={setDepth} style={{ flex: 1, margin: 0 }} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--primary)', fontWeight: 500, minWidth: 20, textAlign: 'center' }}>{depth}</span>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Tooltip title="基于实体预测可能的攻击链路径">
            <Button type="primary" icon={<AimOutlined />} loading={predictLoading} onClick={handlePredict}>预测</Button>
          </Tooltip>
          <Tooltip title="模拟推演攻击演化过程">
            <Button icon={<ExperimentOutlined />} loading={simulateLoading} onClick={handleSimulate} style={{ background: 'var(--green-dim)', border: '1px solid var(--green)', color: 'var(--green)', fontWeight: 500 }}>模拟</Button>
          </Tooltip>
          <Tooltip title="生成早期预警信息">
            <Button icon={<AlertOutlined />} loading={warningLoading} onClick={handleEarlyWarning} style={{ background: 'var(--red-dim)', border: '1px solid var(--red)', color: 'var(--red)', fontWeight: 500 }}>预警</Button>
          </Tooltip>
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
          ) : <Empty description={<span style={{ color: 'var(--text-2)' }}>执行预测以查看攻击链路径</span>} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
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
