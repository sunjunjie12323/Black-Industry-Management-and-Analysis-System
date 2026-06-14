import React, { useState } from 'react';
import { Card, Input, Button, Table, Tag, message, Tabs, Space, Statistic, Row, Col, Select, Progress, Descriptions } from 'antd';
import { ThunderboltOutlined, WarningOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { TextArea } = Input;

const RiskScoring: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('calculate');
  const [threatEventJson, setThreatEventJson] = useState('');
  const [calculateResult, setCalculateResult] = useState<any>(null);
  const [batchEventsJson, setBatchEventsJson] = useState('');
  const [batchResult, setBatchResult] = useState<any>(null);
  const [decayInitialScore, setDecayInitialScore] = useState(0.8);
  const [decayTimestamp, setDecayTimestamp] = useState('');
  const [decayModel, setDecayModel] = useState('exponential');
  const [decayResult, setDecayResult] = useState<any>(null);
  const [primaryEventId, setPrimaryEventId] = useState('');
  const [dependentEventIds, setDependentEventIds] = useState('');
  const [cascadeResult, setCascadeResult] = useState<any>(null);
  const [industry, setIndustry] = useState('finance');
  const [matrixResult, setMatrixResult] = useState<any>(null);

  // 计算风险评分
  const handleCalculate = async () => {
    if (!threatEventJson.trim()) {
      message.warning('请输入威胁事件JSON');
      return;
    }

    try {
      const threatEvent = JSON.parse(threatEventJson);
      setLoading(true);
      const result = await api.riskScoring.calculate(threatEvent);
      setCalculateResult(result);
      message.success('风险评分计算完成');
    } catch (error: any) {
      if (error instanceof SyntaxError) {
        message.error('JSON格式错误');
      } else {
        message.error(error?.message || '计算失败');
      }
    } finally {
      setLoading(false);
    }
  };

  // 批量计算风险评分
  const handleBatchCalculate = async () => {
    if (!batchEventsJson.trim()) {
      message.warning('请输入威胁事件JSON数组');
      return;
    }

    try {
      const events = JSON.parse(batchEventsJson);
      if (!Array.isArray(events)) {
        message.error('请输入JSON数组');
        return;
      }
      setLoading(true);
      const result = await api.riskScoring.batchCalculate(events);
      setBatchResult(result);
      message.success('批量计算完成');
    } catch (error: any) {
      if (error instanceof SyntaxError) {
        message.error('JSON格式错误');
      } else {
        message.error(error?.message || '计算失败');
      }
    } finally {
      setLoading(false);
    }
  };

  // 计算风险衰减
  const handleDecay = async () => {
    if (!decayTimestamp.trim()) {
      message.warning('请输入事件时间戳');
      return;
    }

    setLoading(true);
    try {
      const result = await api.riskScoring.calculateDecay(decayInitialScore, decayTimestamp, decayModel);
      setDecayResult(result);
      message.success('衰减计算完成');
    } catch (error: any) {
      message.error(error?.message || '计算失败');
    } finally {
      setLoading(false);
    }
  };

  // 分析级联风险
  const handleCascadeAnalysis = async () => {
    if (!primaryEventId.trim() || !dependentEventIds.trim()) {
      message.warning('请输入主要事件ID和依赖事件ID列表');
      return;
    }
    const ids = dependentEventIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的依赖事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.riskScoring.analyzeCascadeRisk(primaryEventId, ids);
      setCascadeResult(result);
      message.success('级联风险分析完成');
    } catch (error: any) {
      message.error(error?.message || '分析失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取风险矩阵
  const handleGetMatrix = async () => {
    setLoading(true);
    try {
      const result = await api.riskScoring.getRiskMatrix(industry);
      setMatrixResult(result);
      message.success('获取风险矩阵成功');
    } catch (error: any) {
      message.error(error?.message || '获取失败');
    } finally {
      setLoading(false);
    }
  };

  // 获取风险等级颜色
  const getRiskLevelColor = (level: string) => {
    const colorMap: Record<string, string> = {
      'critical': '#f5222d',
      'high': '#ff7a45',
      'medium': '#faad14',
      'low': '#52c41a'
    };
    return colorMap[level] || '#8c8c8c';
  };

  // 批量结果表格列
  const batchColumns = [
    {
      title: '事件ID',
      dataIndex: 'event_id',
      key: 'event_id',
      width: 120,
      render: (id: string) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {id?.slice(0, 8)}...
        </span>
      )
    },
    {
      title: '风险评分',
      dataIndex: 'risk_score',
      key: 'risk_score',
      width: 150,
      render: (score: number) => (
        <Progress
          percent={Math.round(score * 100)}
          size="small"
          strokeColor={getRiskLevelColor(
            score >= 0.8 ? 'critical' : score >= 0.6 ? 'high' : score >= 0.4 ? 'medium' : 'low'
          )}
        />
      )
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      key: 'risk_level',
      width: 100,
      render: (level: string) => (
        <Tag color={getRiskLevelColor(level)} style={{ fontWeight: 600 }}>
          {level.toUpperCase()}
        </Tag>
      )
    },
    {
      title: '建议',
      dataIndex: 'recommendation',
      key: 'recommendation',
      ellipsis: true
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>动态风险评分</h1>
      <p style={{ color: 'var(--text-2)', marginBottom: 24 }}>
        基于CVSS v3.1、指数衰减、级联风险和行业矩阵进行风险评估
      </p>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        {
          key: 'calculate',
          label: '风险计算',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  威胁事件JSON
                </label>
                <TextArea
                  rows={8}
                  value={threatEventJson}
                  onChange={e => setThreatEventJson(e.target.value)}
                  placeholder='请输入威胁事件JSON，例如：&#10;{&#10;  "id": "event-001",&#10;  "threat_type": "malware",&#10;  "severity": "high",&#10;  "affected_system": "server"&#10;}'
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<ThunderboltOutlined />}
                loading={loading}
                onClick={handleCalculate}
                size="large"
              >
                计算风险
              </Button>

              {calculateResult && (
                <div style={{ marginTop: 24 }}>
                  <Card
                    title="风险评分结果"
                    style={{
                      borderColor: getRiskLevelColor(calculateResult.risk_level)
                    }}
                  >
                    <Row gutter={16} style={{ marginBottom: 16 }}>
                      <Col span={8}>
                        <Statistic
                          title="风险评分"
                          value={(calculateResult.risk_score * 100).toFixed(1)}
                          suffix="%"
                          valueStyle={{
                            color: getRiskLevelColor(calculateResult.risk_level),
                            fontWeight: 700
                          }}
                        />
                      </Col>
                      <Col span={8}>
                        <Statistic
                          title="风险等级"
                          value={calculateResult.risk_level?.toUpperCase()}
                          valueStyle={{
                            color: getRiskLevelColor(calculateResult.risk_level),
                            fontWeight: 700
                          }}
                        />
                      </Col>
                      <Col span={8}>
                        <Statistic
                          title="时间戳"
                          value={calculateResult.timestamp}
                          valueStyle={{ fontSize: 14 }}
                        />
                      </Col>
                    </Row>

                    {calculateResult.risk_factors && (
                      <div style={{ marginTop: 16 }}>
                        <h4>风险因子</h4>
                        <Descriptions bordered column={2} size="small">
                          {Object.entries(calculateResult.risk_factors).map(([key, value]) => (
                            <Descriptions.Item key={key} label={key}>
                              {typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : String(value)}
                            </Descriptions.Item>
                          ))}
                        </Descriptions>
                      </div>
                    )}

                    {calculateResult.recommendation && (
                      <div style={{ marginTop: 16, padding: 16, background: 'var(--bg-2)', borderRadius: 8 }}>
                        <h4>建议</h4>
                        <p style={{ margin: 0, color: 'var(--text-1)' }}>
                          {calculateResult.recommendation}
                        </p>
                      </div>
                    )}
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'batch',
          label: '批量计算',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  威胁事件JSON数组
                </label>
                <TextArea
                  rows={10}
                  value={batchEventsJson}
                  onChange={e => setBatchEventsJson(e.target.value)}
                  placeholder='请输入威胁事件JSON数组，例如：&#10;[&#10;  {"id": "event-001", "threat_type": "malware"},&#10;  {"id": "event-002", "threat_type": "phishing"}&#10;]'
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<ThunderboltOutlined />}
                loading={loading}
                onClick={handleBatchCalculate}
                size="large"
              >
                批量计算
              </Button>

              {batchResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 24 }}>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="总事件数"
                          value={batchResult.summary?.total_events || 0}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="严重风险"
                          value={batchResult.summary?.critical_count || 0}
                          valueStyle={{ color: '#f5222d' }}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="高风险"
                          value={batchResult.summary?.high_count || 0}
                          valueStyle={{ color: '#ff7a45' }}
                        />
                      </Card>
                    </Col>
                    <Col span={6}>
                      <Card>
                        <Statistic
                          title="平均风险"
                          value={((batchResult.summary?.avg_risk_score || 0) * 100).toFixed(1)}
                          suffix="%"
                        />
                      </Card>
                    </Col>
                  </Row>

                  <Table
                    dataSource={batchResult.results || []}
                    columns={batchColumns}
                    rowKey="event_id"
                    pagination={{ pageSize: 10 }}
                    size="middle"
                  />
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'decay',
          label: '风险衰减',
          children: (
            <Card>
              <Row gutter={16} style={{ marginBottom: 16 }}>
                <Col span={8}>
                  <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                    初始风险评分
                  </label>
                  <Input
                    type="number"
                    value={decayInitialScore}
                    onChange={e => setDecayInitialScore(Number(e.target.value))}
                    min={0}
                    max={1}
                    step={0.01}
                  />
                </Col>
                <Col span={8}>
                  <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                    事件时间戳
                  </label>
                  <Input
                    value={decayTimestamp}
                    onChange={e => setDecayTimestamp(e.target.value)}
                    placeholder="2024-01-01T00:00:00Z"
                  />
                </Col>
                <Col span={8}>
                  <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                    衰减模型
                  </label>
                  <Select
                    value={decayModel}
                    onChange={setDecayModel}
                    style={{ width: '100%' }}
                    options={[
                      { value: 'exponential', label: '指数衰减' },
                      { value: 'linear', label: '线性衰减' },
                      { value: 'logarithmic', label: '对数衰减' }
                    ]}
                  />
                </Col>
              </Row>

              <Button
                type="primary"
                icon={<SafetyCertificateOutlined />}
                loading={loading}
                onClick={handleDecay}
                size="large"
              >
                计算衰减
              </Button>

              {decayResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="衰减计算结果">
                    <Descriptions bordered column={2}>
                      <Descriptions.Item label="初始评分">
                        {(decayResult.initial_score * 100).toFixed(1)}%
                      </Descriptions.Item>
                      <Descriptions.Item label="当前评分">
                        <span style={{
                          color: decayResult.current_score >= 0.6 ? '#f5222d' :
                                 decayResult.current_score >= 0.3 ? '#faad14' : '#52c41a',
                          fontWeight: 600
                        }}>
                          {(decayResult.current_score * 100).toFixed(1)}%
                        </span>
                      </Descriptions.Item>
                      <Descriptions.Item label="衰减率">
                        {(decayResult.decay_rate * 100).toFixed(2)}%/小时
                      </Descriptions.Item>
                      <Descriptions.Item label="经过时间">
                        {decayResult.hours_elapsed?.toFixed(1)} 小时
                      </Descriptions.Item>
                    </Descriptions>
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'cascade',
          label: '级联风险',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  主要事件ID
                </label>
                <Input
                  value={primaryEventId}
                  onChange={e => setPrimaryEventId(e.target.value)}
                  placeholder="请输入主要事件ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  依赖事件ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={dependentEventIds}
                  onChange={e => setDependentEventIds(e.target.value)}
                  placeholder="请输入依赖事件ID，每行一个"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<WarningOutlined />}
                loading={loading}
                onClick={handleCascadeAnalysis}
                size="large"
                danger
              >
                分析级联风险
              </Button>

              {cascadeResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="级联风险分析结果">
                    <Descriptions bordered column={2}>
                      <Descriptions.Item label="主要事件ID">
                        <span style={{ fontFamily: 'var(--font-mono)' }}>
                          {cascadeResult.primary_event_id}
                        </span>
                      </Descriptions.Item>
                      <Descriptions.Item label="主要事件风险">
                        <span style={{
                          color: getRiskLevelColor(
                            cascadeResult.primary_risk_score >= 0.8 ? 'critical' :
                            cascadeResult.primary_risk_score >= 0.6 ? 'high' :
                            cascadeResult.primary_risk_score >= 0.4 ? 'medium' : 'low'
                          ),
                          fontWeight: 600
                        }}>
                          {(cascadeResult.primary_risk_score * 100).toFixed(1)}%
                        </span>
                      </Descriptions.Item>
                      <Descriptions.Item label="总级联影响">
                        <span style={{
                          color: cascadeResult.total_cascade_impact >= 0.5 ? '#f5222d' : '#faad14',
                          fontWeight: 600
                        }}>
                          {(cascadeResult.total_cascade_impact * 100).toFixed(1)}%
                        </span>
                      </Descriptions.Item>
                    </Descriptions>

                    {cascadeResult.cascade_effects && cascadeResult.cascade_effects.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <h4>级联效应</h4>
                        <Table
                          dataSource={cascadeResult.cascade_effects}
                          columns={[
                            { title: '依赖事件', dataIndex: 'dependent_event_id', key: 'dependent_event_id' },
                            {
                              title: '影响程度',
                              dataIndex: 'impact',
                              key: 'impact',
                              render: (impact: number) => (
                                <span style={{
                                  color: impact >= 0.7 ? '#f5222d' : impact >= 0.4 ? '#faad14' : '#52c41a'
                                }}>
                                  {(impact * 100).toFixed(1)}%
                                </span>
                              )
                            }
                          ]}
                          rowKey="dependent_event_id"
                          pagination={false}
                          size="small"
                        />
                      </div>
                    )}

                    {cascadeResult.recommendations && cascadeResult.recommendations.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <h4>建议</h4>
                        <ul>
                          {cascadeResult.recommendations.map((rec: string, idx: number) => (
                            <li key={idx} style={{ color: 'var(--text-1)' }}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'matrix',
          label: '风险矩阵',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  行业
                </label>
                <Space.Compact style={{ width: '100%' }}>
                  <Select
                    value={industry}
                    onChange={setIndustry}
                    style={{ width: 200 }}
                    options={[
                      { value: 'finance', label: '金融' },
                      { value: 'healthcare', label: '医疗' },
                      { value: 'energy', label: '能源' },
                      { value: 'manufacturing', label: '制造' },
                      { value: 'retail', label: '零售' },
                      { value: 'technology', label: '科技' }
                    ]}
                  />
                  <Button type="primary" loading={loading} onClick={handleGetMatrix}>
                    获取矩阵
                  </Button>
                </Space.Compact>
              </div>

              {matrixResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title={`${matrixResult.industry}行业风险矩阵`}>
                    <pre style={{
                      background: 'var(--bg-2)',
                      padding: 16,
                      borderRadius: 8,
                      overflow: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12
                    }}>
                      {JSON.stringify(matrixResult.matrix, null, 2)}
                    </pre>
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

export default RiskScoring;
