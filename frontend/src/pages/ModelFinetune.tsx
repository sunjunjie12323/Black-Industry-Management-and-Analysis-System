import React, { useState, useEffect, useMemo } from 'react';
import {
  Table, Button, Modal, Form, Select, Input, Tag, Space, Spin, Empty, Popconfirm, Tooltip, Collapse, Statistic,
} from 'antd';
import {
  PlusOutlined, PlayCircleOutlined,
  CloseCircleOutlined, LineChartOutlined, ExperimentOutlined,
  DeleteOutlined, RocketOutlined, ThunderboltOutlined, TrophyOutlined,
} from '@ant-design/icons';
import {
  LineChart, Line, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { api, getErrorMessage } from '../services/api';
import { useAntdMessage } from '../utils/hooks';

const STATUS_MAP: Record<string, { label: string; color: string; dim: string }> = {
  pending: { label: '待训练', color: '#EAB308', dim: 'var(--yellow-dim)' },
  training: { label: '训练中', color: '#2563EB', dim: 'var(--blue-dim)' },
  completed: { label: '已完成', color: '#16A34A', dim: 'var(--green-dim)' },
  failed: { label: '失败', color: '#DC2626', dim: 'var(--red-dim)' },
};

const METHOD_MAP: Record<string, { label: string; color: string; dim: string }> = {
  lora: { label: 'LoRA', color: '#2563EB', dim: 'var(--blue-dim)' },
  full: { label: '全参微调', color: '#7C3AED', dim: 'var(--purple-dim)' },
};

const BASE_MODELS = [
  { value: 'deepseek-chat', label: 'DeepSeek Chat' },
  { value: 'deepseek-coder', label: 'DeepSeek Coder' },
  { value: 'qwen2.5-7b', label: 'Qwen2.5-7B' },
  { value: 'llama3-8b', label: 'LLaMA3-8B' },
];

const ModelFinetune: React.FC = () => {
  const message = useAntdMessage();
  const [tasks, setTasks] = useState<Record<string, unknown>[]>([]);
  const [models, setModels] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState<string | undefined>(undefined);
  const [createOpen, setCreateOpen] = useState(false);
  const [metricsOpen, setMetricsOpen] = useState(false);
  const [evalOpen, setEvalOpen] = useState(false);
  const [metricsData, setMetricsData] = useState<Record<string, unknown>[]>([]);
  const [evalResult, setEvalResult] = useState<Record<string, unknown> | null>(null);
  const [selectedTask, setSelectedTask] = useState<Record<string, unknown> | null>(null);
  const [form] = Form.useForm();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [taskRes, modelRes] = await Promise.allSettled([
        api.finetune.listTasks({ search: search || undefined, method: methodFilter }),
        api.finetune.listModels(),
      ]);
      if (taskRes.status === 'fulfilled') {
        const d = taskRes.value as Record<string, unknown>;
        setTasks((d?.items || d?.data || []) as Record<string, unknown>[]);
      } else { setTasks([]); }
      if (modelRes.status === 'fulfilled') {
        const d = modelRes.value as Record<string, unknown>;
        setModels((d?.items || d?.models || d?.data || []) as Record<string, unknown>[]);
      } else { setModels([]); }
    } catch { setTasks([]); setModels([]); } finally { setLoading(false); }
  };

  useEffect(() => { fetchData(); }, [search, methodFilter]);

  const stats = useMemo(() => {
    const total = tasks.length;
    const training = tasks.filter(t => String(t.status).toLowerCase() === 'training').length;
    const completed = tasks.filter(t => String(t.status).toLowerCase() === 'completed').length;
    const modelCount = models.length;
    return { total, training, completed, modelCount };
  }, [tasks, models]);

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      await api.finetune.createTask(values);
      message.success('微调任务创建成功');
      setCreateOpen(false);
      form.resetFields();
      fetchData();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'errorFields' in err) return;
      message.error(getErrorMessage(err));
    }
  };

  const handleStart = async (id: string) => {
    try { await api.finetune.startTask(id); message.success('训练已启动'); fetchData(); } catch (err) { message.error(getErrorMessage(err)); }
  };

  const handleCancel = async (id: string) => {
    try { await api.finetune.cancelTask(id); message.success('训练已取消'); fetchData(); } catch (err) { message.error(getErrorMessage(err)); }
  };

  const handleEvaluate = async (task: Record<string, unknown>) => {
    const id = String(task.id || task.task_id);
    try {
      const res = await api.finetune.evaluate(id);
      const d = res as Record<string, unknown>;
      const unwrapped = (d?.metrics || d?.results || d?.evaluation || d) as Record<string, unknown>;
      setEvalResult(unwrapped);
      setEvalOpen(true);
    } catch (err) { message.error(getErrorMessage(err)); }
  };

  const handleMetrics = async (task: Record<string, unknown>) => {
    const id = String(task.id || task.task_id);
    setSelectedTask(task);
    try {
      const res = await api.finetune.getMetrics(id);
      const d = res as Record<string, unknown>;
      let rawMetrics = (d?.metrics || d?.items || d?.data || d?.history || []) as Record<string, unknown>[];
      if (!Array.isArray(rawMetrics) || rawMetrics.length === 0) {
        if (d && typeof d === 'object' && !Array.isArray(d)) {
          const keys = Object.keys(d);
          const firstVal = d[keys[0]];
          if (Array.isArray(firstVal)) {
            const len = firstVal.length;
            rawMetrics = Array.from({ length: len }, (_, i) => {
              const point: Record<string, unknown> = {};
              keys.forEach(k => { point[k] = (d[k] as unknown[])?.[i]; });
              return point;
            });
          }
        }
      }
      setMetricsData(rawMetrics);
    } catch { setMetricsData([]); }
    setMetricsOpen(true);
  };

  const handleDelete = async (id: string) => {
    try { await api.finetune.cancelTask(id); message.success('已删除'); fetchData(); } catch (err) { message.error(getErrorMessage(err)); }
  };

  const lossChartData = useMemo(() => {
    if (!metricsData.length) return [];
    return metricsData.map((m, i) => ({
      step: i + 1,
      train_loss: Number(m.loss || m.train_loss || 0),
      val_loss: Number(m.val_loss || m.eval_loss || 0),
    }));
  }, [metricsData]);

  const taskColumns = [
    { title: '任务名', dataIndex: 'name', key: 'name', ellipsis: true, render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{text || '—'}</span> },
    { title: '方法', dataIndex: 'method', key: 'method', width: 100, render: (method: string) => { const m = METHOD_MAP[method] || { label: method, color: 'var(--text-2)', dim: 'var(--bg-3)' }; return <Tag style={{ background: m.dim, color: m.color, border: 'none' }}>{m.label}</Tag>; } },
    { title: '基座模型', dataIndex: 'base_model', key: 'base_model', width: 140, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-2)', fontSize: 12 }}>{text || '—'}</span> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => { const s = STATUS_MAP[String(status).toLowerCase()] || STATUS_MAP.pending; return <Tag style={{ background: s.dim, color: s.color, border: 'none' }}>{s.label}</Tag>; } },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 140, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>{text ? String(text).slice(0, 10) : '—'}</span> },
    {
      title: '操作', key: 'actions', width: 180,
      render: (_: unknown, record: Record<string, unknown>) => {
        const id = String(record.id || record.task_id);
        const status = String(record.status).toLowerCase();
        return (
          <Space size={2}>
            {status === 'pending' && <Tooltip title="启动训练"><Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleStart(id)} /></Tooltip>}
            {status === 'training' && <Tooltip title="取消训练"><Button type="text" size="small" icon={<CloseCircleOutlined />} onClick={() => handleCancel(id)} /></Tooltip>}
            {(status === 'completed' || status === 'training') && <Tooltip title="评估"><Button type="text" size="small" icon={<ExperimentOutlined />} onClick={() => handleEvaluate(record)} /></Tooltip>}
            {(status === 'training' || status === 'completed') && <Tooltip title="训练指标"><Button type="text" size="small" icon={<LineChartOutlined />} onClick={() => handleMetrics(record)} /></Tooltip>}
            <Popconfirm title="确认删除此微调任务？" onConfirm={() => handleDelete(id)} okText="删除" cancelText="取消" okButtonProps={{ danger: true }}><Tooltip title="删除"><Button type="text" size="small" icon={<DeleteOutlined />} danger /></Tooltip></Popconfirm>
          </Space>
        );
      },
    },
  ];

  const modelColumns = [
    { title: '模型名', dataIndex: 'name', key: 'name', ellipsis: true, render: (text: string) => <span style={{ color: 'var(--text-0)', fontWeight: 500 }}>{text || '—'}</span> },
    { title: '基座模型', dataIndex: 'base_model', key: 'base_model', width: 140, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-2)', fontSize: 12 }}>{text || '—'}</span> },
    { title: '方法', dataIndex: 'method', key: 'method', width: 100, render: (method: string) => { const m = METHOD_MAP[method] || { label: method, color: 'var(--text-2)', dim: 'var(--bg-3)' }; return <Tag style={{ background: m.dim, color: m.color, border: 'none' }}>{m.label}</Tag>; } },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 140, render: (text: string) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-3)', fontSize: 12 }}>{text ? String(text).slice(0, 10) : '—'}</span> },
  ];

  const tooltipStyle: React.CSSProperties = { background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-0)' };

  return (
    <div style={{ padding: 32, background: 'var(--bg-0)', minHeight: '100vh', overflowX: 'hidden' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-body)', color: 'var(--text-0)', margin: 0, letterSpacing: '-0.02em' }}>模型微调</h1>
        <p style={{ fontSize: 14, color: 'var(--text-2)', margin: '8px 0 0', fontFamily: 'var(--font-body)' }}>使用LoRA或全参微调方法，在领域数据上优化DeepSeek模型</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}><RocketOutlined style={{ fontSize: 16, color: 'var(--primary)' }} /><span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>任务总数</span></div>
          <Statistic value={stats.total} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--text-0)', fontWeight: 700 }} />
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}><ThunderboltOutlined style={{ fontSize: 16, color: 'var(--blue)' }} /><span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>训练中</span></div>
          <Statistic value={stats.training} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--blue)', fontWeight: 700 }} />
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}><TrophyOutlined style={{ fontSize: 16, color: 'var(--green)' }} /><span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>已完成</span></div>
          <Statistic value={stats.completed} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontWeight: 700 }} />
        </div>
        <div style={{ background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}><ExperimentOutlined style={{ fontSize: 16, color: 'var(--purple)' }} /><span style={{ fontSize: 12, color: 'var(--text-2)', fontWeight: 500 }}>模型数</span></div>
          <Statistic value={stats.modelCount} valueStyle={{ fontFamily: 'var(--font-mono)', color: 'var(--purple)', fontWeight: 700 }} />
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Space size={8}>
          <Select placeholder="方法筛选" value={methodFilter} onChange={setMethodFilter} allowClear style={{ width: 120 }} options={Object.entries(METHOD_MAP).map(([k, v]) => ({ value: k, label: v.label }))} />
          <Input placeholder="搜索任务" value={search} onChange={(e) => setSearch(e.target.value)} style={{ width: 200 }} allowClear />
        </Space>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建任务</Button>
      </div>

      <Collapse
        defaultActiveKey={['tasks', 'models']}
        items={[
          {
            key: 'tasks',
            label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>训练任务</span>,
            children: loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div> : tasks.length === 0 ? <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无微调任务，点击「创建任务」开始</span>}><Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建任务</Button></Empty> : <Table dataSource={tasks} columns={taskColumns} rowKey={(record) => String(record.id || record.task_id || Math.random())} pagination={{ pageSize: 10, showSizeChanger: false }} />,
          },
          {
            key: 'models',
            label: <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>已训练模型</span>,
            children: loading ? <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div> : models.length === 0 ? <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无已训练模型</span>} /> : <Table dataSource={models} columns={modelColumns} rowKey={(record) => `model_${record.id || record.model_id || Math.random().toString(36).slice(2)}`} pagination={{ pageSize: 10, showSizeChanger: false }} />,
          },
        ]}
      />

      <Modal open={createOpen} onCancel={() => { setCreateOpen(false); form.resetFields(); }} onOk={handleCreate} width={600} okText="创建" cancelText="取消" title="创建微调任务">
        <Form form={form} layout="vertical" style={{ marginTop: 16 }} requiredMark={false}>
          <Form.Item name="name" label="任务名称" rules={[{ required: true, message: '请输入任务名称' }]}><Input placeholder="例如: threat-intel-lora-v2" /></Form.Item>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Form.Item name="method" label="微调方法" rules={[{ required: true, message: '请选择方法' }]}><Select placeholder="选择方法" options={Object.entries(METHOD_MAP).map(([k, v]) => ({ value: k, label: v.label }))} /></Form.Item>
            <Form.Item name="base_model" label="基座模型" rules={[{ required: true, message: '请选择模型' }]}><Select placeholder="选择模型" options={BASE_MODELS} /></Form.Item>
          </div>
          <Form.Item name="dataset_path" label="数据集路径"><Input placeholder="例如: /data/threat-intel-v1" /></Form.Item>
          <Form.Item name="config_json" label="训练配置 (JSON)"><Input.TextArea rows={6} placeholder={'{\n  "learning_rate": 0.0001,\n  "epochs": 3,\n  "batch_size": 8\n}'} style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} /></Form.Item>
        </Form>
      </Modal>

      <Modal open={metricsOpen} onCancel={() => setMetricsOpen(false)} width={760} footer={null} title={`训练指标 — ${String(selectedTask?.name || '')}`}>
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>Loss 曲线</div>
          {lossChartData.length > 0 ? (
            <div className="chart-reveal chart-d-1" style={{ background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', padding: '12px 8px 8px' }}>
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={lossChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="step" tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={false} tickLine={false} width={45} />
                  <RTooltip contentStyle={tooltipStyle} />
                  <Line type="monotone" dataKey="train_loss" stroke="#1E40AF" strokeWidth={1.5} dot={false} name="训练Loss" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                  <Line type="monotone" dataKey="val_loss" stroke="var(--text-2)" strokeWidth={1.5} dot={false} name="验证Loss" strokeDasharray="6 3" isAnimationActive={true} animationBegin={600} animationDuration={1200} animationEasing="ease-out" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div style={{ height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}><span style={{ color: 'var(--text-3)', fontSize: 13 }}>暂无训练指标数据</span></div>
          )}
        </div>
      </Modal>

      <Modal open={evalOpen} onCancel={() => setEvalOpen(false)} width={560} footer={null} title="评估结果">
        <div style={{ marginTop: 16 }}>
          {evalResult ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {[
                { label: 'Accuracy', key: 'accuracy', format: (v: number) => `${(v * 100).toFixed(2)}%` },
                { label: 'F1 Score', key: 'f1', format: (v: number) => v.toFixed(4) },
                { label: 'Loss', key: 'loss', format: (v: number) => v.toFixed(4) },
              ].map((item) => {
                const val = Number(evalResult[item.key] || 0);
                return (
                  <div key={item.key} style={{ padding: 24, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', textAlign: 'center' }}>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', marginBottom: 8 }}>{item.label}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color: 'var(--text-0)', fontWeight: 500 }}>{item.format(val)}</div>
                  </div>
                );
              })}
            </div>
          ) : <Empty description={<span style={{ color: 'var(--text-3)' }}>暂无评估结果</span>} />}
        </div>
      </Modal>
    </div>
  );
};

export default ModelFinetune;
