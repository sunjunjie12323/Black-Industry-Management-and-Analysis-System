import React, { useState } from 'react';
import { Card, Input, Button, Table, Tag, message, Tabs, Space, Statistic, Row, Col, Slider, Descriptions } from 'antd';
import { UserOutlined, AimOutlined, WarningOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { TextArea } = Input;

const ThreatBehavior: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('profile');
  const [incidentIds, setIncidentIds] = useState('');
  const [profileResult, setProfileResult] = useState<any>(null);
  const [ttpText, setTtpText] = useState('');
  const [ttpResult, setTtpResult] = useState<any>(null);
  const [clusterIds, setClusterIds] = useState('');
  const [minSimilarity, setMinSimilarity] = useState(0.6);
  const [clusterResult, setClusterResult] = useState<any>(null);
  const [matchIncidentId, setMatchIncidentId] = useState('');
  const [matchResult, setMatchResult] = useState<any>(null);
  const [anomalyIncidentId, setAnomalyIncidentId] = useState('');
  const [anomalyBaselineId, setAnomalyBaselineId] = useState('');
  const [anomalyResult, setAnomalyResult] = useState<any>(null);

  // 构建行为画像
  const handleBuildProfile = async () => {
    if (!incidentIds.trim()) {
      message.warning('请输入事件ID列表');
      return;
    }
    const ids = incidentIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.threatBehavior.buildProfile(ids);
      setProfileResult(result);
      message.success('行为画像构建完成');
    } catch (error: any) {
      message.error(error?.message || '构建失败');
    } finally {
      setLoading(false);
    }
  };

  // 提取TTP
  const handleExtractTTPs = async () => {
    if (!ttpText.trim()) {
      message.warning('请输入文本内容');
      return;
    }

    setLoading(true);
    try {
      const result = await api.threatBehavior.extractTTPs(ttpText);
      setTtpResult(result);
      message.success('TTP提取完成');
    } catch (error: any) {
      message.error(error?.message || '提取失败');
    } finally {
      setLoading(false);
    }
  };

  // 聚类威胁行为者
  const handleClusterActors = async () => {
    if (!clusterIds.trim()) {
      message.warning('请输入画像ID列表');
      return;
    }
    const ids = clusterIds.split('\n').map(id => id.trim()).filter(id => id);
    if (ids.length === 0) {
      message.warning('请输入有效的画像ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.threatBehavior.clusterActors(ids, minSimilarity);
      setClusterResult(result);
      message.success('聚类完成');
    } catch (error: any) {
      message.error(error?.message || '聚类失败');
    } finally {
      setLoading(false);
    }
  };

  // 匹配已知威胁行为者
  const handleMatchActors = async () => {
    if (!matchIncidentId.trim()) {
      message.warning('请输入事件ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.threatBehavior.matchActors(matchIncidentId, 5);
      setMatchResult(result);
      message.success('匹配完成');
    } catch (error: any) {
      message.error(error?.message || '匹配失败');
    } finally {
      setLoading(false);
    }
  };

  // 检测行为异常
  const handleDetectAnomaly = async () => {
    if (!anomalyIncidentId.trim() || !anomalyBaselineId.trim()) {
      message.warning('请输入事件ID和基线画像ID');
      return;
    }

    setLoading(true);
    try {
      const result = await api.threatBehavior.detectAnomaly(anomalyIncidentId, anomalyBaselineId);
      setAnomalyResult(result);
      message.success('异常检测完成');
    } catch (error: any) {
      message.error(error?.message || '检测失败');
    } finally {
      setLoading(false);
    }
  };

  // TTP结果表格列
  const ttpColumns = [
    {
      title: '战术',
      dataIndex: 'tactic',
      key: 'tactic',
      width: 150
    },
    {
      title: '技术',
      dataIndex: 'technique',
      key: 'technique',
      width: 200
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 120,
      render: (conf: number) => (
        <span style={{ color: conf >= 0.7 ? '#52c41a' : conf >= 0.5 ? '#faad14' : '#8c8c8c' }}>
          {(conf * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '证据',
      dataIndex: 'evidence',
      key: 'evidence',
      ellipsis: true
    }
  ];

  // 匹配结果表格列
  const matchColumns = [
    {
      title: '行为者名称',
      dataIndex: 'actor_name',
      key: 'actor_name',
      width: 150
    },
    {
      title: '相似度',
      dataIndex: 'similarity',
      key: 'similarity',
      width: 120,
      render: (sim: number) => (
        <span style={{ color: sim >= 0.8 ? '#f5222d' : sim >= 0.6 ? '#faad14' : '#8c8c8c', fontWeight: 600 }}>
          {(sim * 100).toFixed(1)}%
        </span>
      )
    },
    {
      title: '匹配技术',
      dataIndex: 'matched_techniques',
      key: 'matched_techniques',
      render: (techs: string[]) => (
        <Space wrap>
          {techs?.map(tech => (
            <Tag key={tech} color="blue">{tech}</Tag>
          ))}
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>威胁行为画像</h1>
      <p style={{ color: 'var(--text-2)', marginBottom: 24 }}>
        基于TTP指纹、余弦相似度、层次聚类和Apriori算法分析威胁行为者
      </p>

      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        {
          key: 'profile',
          label: '行为画像',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  事件ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={incidentIds}
                  onChange={e => setIncidentIds(e.target.value)}
                  placeholder="请输入事件ID，每行一个&#10;例如：&#10;incident-001&#10;incident-002"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <Button
                type="primary"
                icon={<UserOutlined />}
                loading={loading}
                onClick={handleBuildProfile}
                size="large"
              >
                构建画像
              </Button>

              {profileResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title="行为画像结果">
                    <Descriptions bordered column={2}>
                      <Descriptions.Item label="行为者类型">
                        {profileResult.profile?.actor_type || '未知'}
                      </Descriptions.Item>
                      <Descriptions.Item label="技能等级">
                        <Tag color={
                          profileResult.profile?.skill_level === 'expert' ? 'red' :
                          profileResult.profile?.skill_level === 'advanced' ? 'orange' :
                          profileResult.profile?.skill_level === 'intermediate' ? 'blue' : 'default'
                        }>
                          {profileResult.profile?.skill_level || '未知'}
                        </Tag>
                      </Descriptions.Item>
                      <Descriptions.Item label="主要目标">
                        {profileResult.profile?.primary_targets?.join(', ') || '未知'}
                      </Descriptions.Item>
                      <Descriptions.Item label="常用工具">
                        {profileResult.profile?.tools?.join(', ') || '未知'}
                      </Descriptions.Item>
                    </Descriptions>

                    <div style={{ marginTop: 16 }}>
                      <h4>TTP指纹</h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {Object.entries(profileResult.ttp_fingerprint || {}).map(([tactic, techs]) => (
                          <Card key={tactic} size="small" style={{ width: 200 }}>
                            <div style={{ fontWeight: 600, marginBottom: 8 }}>{tactic}</div>
                            {(techs as string[])?.map((tech: string) => (
                              <Tag key={tech} color="blue" style={{ marginBottom: 4 }}>
                                {tech}
                              </Tag>
                            ))}
                          </Card>
                        ))}
                      </div>
                    </div>
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'ttp',
          label: 'TTP提取',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  文本内容
                </label>
                <TextArea
                  rows={8}
                  value={ttpText}
                  onChange={e => setTtpText(e.target.value)}
                  placeholder="请输入需要提取TTP的文本内容..."
                />
              </div>

              <Button
                type="primary"
                icon={<AimOutlined />}
                loading={loading}
                onClick={handleExtractTTPs}
                size="large"
              >
                提取TTP
              </Button>

              {ttpResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title={`提取结果（共 ${ttpResult.ttps_found || 0} 个TTP）`}>
                    <Table
                      dataSource={ttpResult.ttps || []}
                      columns={ttpColumns}
                      rowKey={(record: any) => `${record.tactic}-${record.technique}`}
                      pagination={{ pageSize: 10 }}
                      size="middle"
                    />
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'cluster',
          label: '行为者聚类',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  画像ID列表（每行一个）
                </label>
                <TextArea
                  rows={6}
                  value={clusterIds}
                  onChange={e => setClusterIds(e.target.value)}
                  placeholder="请输入画像ID，每行一个"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  最小相似度阈值: {(minSimilarity * 100).toFixed(0)}%
                </label>
                <Slider
                  min={0}
                  max={1}
                  step={0.05}
                  value={minSimilarity}
                  onChange={setMinSimilarity}
                  style={{ width: 300 }}
                />
              </div>

              <Button
                type="primary"
                icon={<UserOutlined />}
                loading={loading}
                onClick={handleClusterActors}
                size="large"
              >
                开始聚类
              </Button>

              {clusterResult && (
                <div style={{ marginTop: 24 }}>
                  <Row gutter={16} style={{ marginBottom: 16 }}>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="总画像数"
                          value={clusterResult.total_profiles || 0}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="聚类数量"
                          value={clusterResult.cluster_count || 0}
                        />
                      </Card>
                    </Col>
                    <Col span={8}>
                      <Card>
                        <Statistic
                          title="最小相似度"
                          value={(clusterResult.min_similarity * 100).toFixed(0)}
                          suffix="%"
                        />
                      </Card>
                    </Col>
                  </Row>

                  {clusterResult.clusters?.map((cluster: any, idx: number) => (
                    <Card key={idx} title={`聚类 ${idx + 1}`} style={{ marginBottom: 16 }}>
                      <Descriptions bordered column={2}>
                        <Descriptions.Item label="画像数量">
                          {cluster.profile_ids?.length || 0}
                        </Descriptions.Item>
                        <Descriptions.Item label="平均相似度">
                          <span style={{ color: cluster.avg_similarity >= 0.7 ? '#52c41a' : '#faad14' }}>
                            {(cluster.avg_similarity * 100).toFixed(1)}%
                          </span>
                        </Descriptions.Item>
                      </Descriptions>
                      <div style={{ marginTop: 16 }}>
                        <h4>包含画像</h4>
                        <Space wrap>
                          {cluster.profile_ids?.map((id: string) => (
                            <Tag key={id} style={{ fontFamily: 'var(--font-mono)' }}>
                              {id.slice(0, 8)}...
                            </Tag>
                          ))}
                        </Space>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'match',
          label: '行为者匹配',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  事件ID
                </label>
                <Input
                  value={matchIncidentId}
                  onChange={e => setMatchIncidentId(e.target.value)}
                  placeholder="请输入事件ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <Button
                type="primary"
                icon={<AimOutlined />}
                loading={loading}
                onClick={handleMatchActors}
                size="large"
              >
                匹配行为者
              </Button>

              {matchResult && (
                <div style={{ marginTop: 24 }}>
                  <Card title={`匹配结果（共 ${matchResult.matches?.length || 0} 个匹配）`}>
                    <Table
                      dataSource={matchResult.matches || []}
                      columns={matchColumns}
                      rowKey="actor_name"
                      pagination={{ pageSize: 10 }}
                      size="middle"
                    />
                  </Card>
                </div>
              )}
            </Card>
          )
        },
        {
          key: 'anomaly',
          label: '异常检测',
          children: (
            <Card>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  事件ID
                </label>
                <Input
                  value={anomalyIncidentId}
                  onChange={e => setAnomalyIncidentId(e.target.value)}
                  placeholder="请输入事件ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', marginBottom: 8, fontWeight: 500 }}>
                  基线画像ID
                </label>
                <Input
                  value={anomalyBaselineId}
                  onChange={e => setAnomalyBaselineId(e.target.value)}
                  placeholder="请输入基线画像ID"
                  style={{ fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <Button
                type="primary"
                icon={<WarningOutlined />}
                loading={loading}
                onClick={handleDetectAnomaly}
                size="large"
                danger
              >
                检测异常
              </Button>

              {anomalyResult && (
                <div style={{ marginTop: 24 }}>
                  <Card
                    title="异常检测结果"
                    style={{
                      borderColor: anomalyResult.is_anomaly ? '#f5222d' : '#52c41a'
                    }}
                  >
                    <Descriptions bordered column={2}>
                      <Descriptions.Item label="是否异常">
                        <Tag color={anomalyResult.is_anomaly ? 'red' : 'green'}>
                          {anomalyResult.is_anomaly ? '异常' : '正常'}
                        </Tag>
                      </Descriptions.Item>
                      <Descriptions.Item label="异常分数">
                        <span style={{
                          color: anomalyResult.anomaly_score >= 0.7 ? '#f5222d' :
                                 anomalyResult.anomaly_score >= 0.5 ? '#faad14' : '#52c41a',
                          fontWeight: 600
                        }}>
                          {(anomalyResult.anomaly_score * 100).toFixed(1)}%
                        </span>
                      </Descriptions.Item>
                    </Descriptions>

                    {anomalyResult.deviations && anomalyResult.deviations.length > 0 && (
                      <div style={{ marginTop: 16 }}>
                        <h4>偏离项</h4>
                        <ul>
                          {anomalyResult.deviations.map((dev: string, idx: number) => (
                            <li key={idx} style={{ color: 'var(--text-2)' }}>{dev}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {anomalyResult.explanation && (
                      <div style={{ marginTop: 16, padding: 16, background: 'var(--bg-2)', borderRadius: 8 }}>
                        <h4>解释</h4>
                        <p style={{ margin: 0, color: 'var(--text-1)' }}>
                          {anomalyResult.explanation}
                        </p>
                      </div>
                    )}
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

export default ThreatBehavior;
