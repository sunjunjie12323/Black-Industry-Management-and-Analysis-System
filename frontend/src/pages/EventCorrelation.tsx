import React, { useState } from 'react';
import { Card, Input, Button, Table, Tag, message, Tabs, Space, Statistic, Row, Col, Timeline, Checkbox } from 'antd';
import { ApiOutlined, NodeIndexOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { TextArea } = Input;

const EventCorrelation: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('analyze');
  const [eventIds, setEventIds] = useState('');
  const [timeWindow, setTimeWindow] = useState(72);
  const [methods, setMethods] = useState(['temporal', 'entity', 'semantic']);
  const [analyzeResult, setAnalyzeResult] = useState<any>(null);
  const [temporalResult, setTemporalResult] = useState<any>(null);
  const [attackChainResult, setAttackChainResult] = useState<any>(null);
  const [singleEventId, setSingleEventId] = useState('');

  // 事件关联分析
  const handleAnalyze = async () => {
    if (!eventIds.trim()) {
      message.warning('请输入事件ID列表');
      return;
    }
    const ids = eventIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.eventCorrelation.analyze(ids, timeWindow, methods);
      setAnalyzeResult(result);
      message.success('关联分析完成');
    } catch (error: any) {
      message.error(error?.message || '分析失败');
    } finally {
      setLoading(false);
    }
  };

  // 时间关联查询
  const handleTemporalQuery = async () => {
    if (!singleEventId.trim()) {
      message.warning('请输入事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.eventCorrelation.getTemporalCorrelations(singleEventId, timeWindow);
      setTemporalResult(result);
      message.success('查询完成');
    } catch (error: any) {
      message.error(error?.message || '查询失败');
    } finally {
      setLoading(false);
    }
  };

  // 攻击链重建
  const handleReconstructChain = async () => {
    if (!eventIds.trim()) {
      message.warning('请输入事件ID列表');
      return;
    }
    const ids = eventIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.eventCorrelation.reconstructAttackChain(ids);
      setAttackChainResult(result);
      message.success('攻击链重建完成');
    } catch (error: any) {
      message.error(error?.message || '重建失败');
    } finally {
      setLoading(false);
    }
  };

  // 关联结果表格列
  const correlationColumns = [
    {
      title: '事件A',
      dataIndex: 'event_a',
      key: 'event_a',
      width: 150,
      render: (event: any) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {event?.id?.slice(0, 8)}...
        </span>
      )
    },
    {
      title: '事件B',
      dataIndex: 'event_b',
      key: 'event_b',
      width: 150,
      render: (event: any) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {event?.id?.slice(0, 8)}...
        </span>
      )
    },
    {
      title: '关联类型',
      dataIndex: 'correlation_type',
      key: 'correlation_type',
      width: 120,
      render: (type: string) => {
        const colorMap: Record<string, string> = {
          'temporal': 'blue',
          'entity': 'green',
          'semantic': 'purple',
          'causal': 'red'
        };
        return <Tag color={colorMap[type] || 'default'}>{type}</Tag>;
      }
    },
    {
      title: '关联强度',
      dataIndex: 'strength',
      key: 'strength',
      width: 120,
      render: (strength: number) => (
        <span style={{ color: strength >= 0.7 ? '#52c41a' : strength >= 0.5 ? '#faad14' : '#8c8c8c' }}>
          {(strength * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true
    }
  ];

  // 聚类结果表格列
  const clusterColumns = [
    {
      title: '聚类ID',
      dataIndex: 'cluster_id',
      key: 'cluster_id',
      width: 100
    },
    {
      title: '事件数量',
      dataIndex: 'event_count',
      key: 'event_count',
      width: 100
    },
    {
      title: '事件ID列表',
      dataIndex: 'event_ids',
      key: 'event_ids',
      render: (ids: string[]) => (
        <Space wrap>
          {ids?.map(id => (
            <Tag key={id} style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              {id.slice(0, 8)}...
            </Tag>
          ))}
        </Space>
      )
    },
    {
      title: '平均相似度',
      dataIndex: 'avg_similarity',
      key: 'avg_similarity',
      width: 120,
      render: (sim: number) => (
        <span style={{ color: sim >= 0.7 ? '#52c41a' : sim >= 0.5 ? '#faad14' : '#8c8c8c' }}>
          {(sim * 100).toFixed(1)}%
        </span>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>事件关联分析</h1>
      <p style={{ color: 'var(--text-2)', marginBottom: 24 }}>
        基于TF-IDF余弦相似度、时间衰减、Jaccard系数和因果推理分析事件关联性
      </p>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        {
          key: 'analyze',
          label: '关联分析',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  事件ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={eventIds}
                  onChange={e => setEventIds(e.target.value)}
                  placeholder="请输入事件ID，每行一个&#10;例如：&#10;event-001&#10;event-002&#10;event-003"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Row gutter={16} style={{ marginBottom: 16 }}>
                <Col span={12}>
                  <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                    时间窗口（小时）
                  </label>
                  <Input
                    type="number"
                    value={timeWindow}
                    onChange={e => setTimeWindow(Number(e.target.value))}
                    min={1}
                    max={720}
                  />
                </Col>
                <Col span={12}>
                  <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                    关联方法
                  </label>
                  <Checkbox.Group
                    value={methods}
                    onChange={vals => setMethods(vals as string[])}
                    style={{ width: '100%' }}
                  >
                    <Space direction="vertical">
                      <Checkbox value="temporal">时间关联</Checkbox>
                      <Checkbox value="entity">实体关联</Checkbox>
                      <Checkbox value="semantic">语义关联</Checkbox>
                    </Space>
                  </Checkbox.Group>
                </Col>
              </Row>

              <Space>
                <Button
                  type="primary"
                  icon={<ApiOutlined />}
                  loading={loading}
                  onClick={handleAnalyze}
                  size="large"
                >
                  开始分析
                </Button>
                <Button
                  icon={<ThunderboltOutlined />}
                  loading={loading}
                  onClick={handleReconstructChain}
                  size="large"
                >
                  重建攻击链
                </Button>
              </Space>

              {analyzeResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 24 }}>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="关联对数"
                          value={analyzeResult.correlations?.length || 0}
                          prefix={<ApiOutlined />}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="聚类数量"
                          value={analyzeResult.clusters?.length || 0}
                          prefix={<NodeIndexOutlined />}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="攻击链数量"
                          value={analyzeResult.attack_chains?.length || 0}
                          prefix={<ThunderboltOutlined />}
                        />
                      </Card>
                    </Col>
                  </Row>

                  <Card title="关联事件" style={{ marginBottom: 16 }}>
                    <Table
                      dataSource={analyzeResult.correlations || []}
                      columns={correlationColumns}
                      rowKey={(record: any) => `${record.event_a?.id}-${record.event_b?.id}`}
                      pagination={{ pageSize: 10 }}
                      size="middle"
                    />
                  </Card>

                  <Card title="事件聚类" style={{ marginBottom: 16 }}>
                    <Table
                      dataSource={analyzeResult.clusters || []}
                      columns={clusterColumns}
                      rowKey="cluster_id"
                      pagination={{ pageSize: 10 }}
                      size="middle"
                    />
                  </Card>

                  {analyzeResult.attack_chains && analyzeResult.attack_chains.length > 0 && (
                    <Card title="攻击链">
                      {analyzeResult.attack_chains.map((chain: any, idx: number) => (
                        <Card key={idx} style={{ marginBottom: 16 }}>
                          <h4>{chain.name || `攻击链 ${idx + 1}`}</h4>
                          <Timeline>
                            {chain.steps?.map((step: any, stepIdx: number) => (
                              <Timeline.Item
                                key={stepIdx}
                                color={step.severity === 'critical' ? 'red' : step.severity === 'high' ? 'orange' : 'blue'}
                              >
                                <div>
                                  <strong>{step.phase}</strong>
                                  <div style={{ color: 'var(--text-2)', fontSize: 12 }}>
                                    {step.description}
                                  </div>
                                  <div style={{ color: 'var(--text-3)', fontSize: 11, marginTop: 4 }}>
                                    事件: {step.event_id?.slice(0, 8)}...
                                  </div>
                                </div>
                              </Timeline.Item>
                            ))}
                          </Timeline>
                        </Card>
                      ))}
                    </Card>
                  )}
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'temporal',
          label: '时间关联',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  事件ID
                </label>
                <Space.Compact style={{ width: '100%' }}>
                  <Input
                    value={singleEventId}
                    onChange={e => setSingleEventId(e.target.value)}
                    placeholder="请输入事件ID"
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                  <Button type="primary" loading={loading} onClick={handleTemporalQuery}>
                    查询
                  </Button>
                </Space.Compact>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  时间窗口（小时）
                </label>
                <Input
                  type="number"
                  value={timeWindow}
                  onChange={e => setTimeWindow(Number(e.target.value))}
                  min={1}
                  max={720}
                  style={{ width: 200 }}
                />
              </div>

              {temporalResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="时间关联结果">
                    <Statistic
                      title="关联事件数"
                      value={temporalResult.total_related || 0}
                      style={{ marginBottom: 16 }}
                    />
                    <Table
                      dataSource={temporalResult.correlations || []}
                      columns={correlationColumns}
                      rowKey={(record: any) => `${record.event_a?.id}-${record.event_b?.id}`}
                      pagination={{ pageSize: 10 }}
                      size="middle"
                    />
                  </Card>
                </div>
              )}
            </Card>
          )
        }
      ]} />
    </div>
  );
};

export default EventCorrelation;
