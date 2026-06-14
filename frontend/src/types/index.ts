export interface User {
  id: string;
  username: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: User;
  must_change_password?: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface IntelligenceItem {
  id: string;
  source?: string | null;
  content: string;
  threat_level?: string | null;
  status: string;
  collected_at?: string | null;
  entities_count: number;
  blacktalk_count: number;
  type: 'raw' | 'cleaned' | 'analyzed';
}

export interface IntelligenceDetail {
  type: 'raw' | 'cleaned' | 'analyzed';
  data: Record<string, unknown>;
}

export interface IntelligenceStats {
  by_source: Record<string, number>;
  by_threat_level: Record<string, number>;
  by_status: Record<string, number>;
  total: number;
}

export interface DashboardStats {
  total_intelligence: number;
  active_pirs: number;
  threat_alerts: number;
  knowledge_graph: {
    node_count: number;
    edge_count: number;
  };
  blacktalk: {
    total_terms: number;
    categories: Record<string, number>;
  };
  threat_level_distribution: Record<string, number>;
  source_type_distribution: Record<string, number>;
  recent_intelligence: RecentIntelligence[];
  agent_statuses: AgentStatus[];
  recent_executions: RecentExecution[];
}

export interface RecentIntelligence {
  id: string;
  title?: string;
  content: string;
  source?: string | null;
  source_type?: string;
  threat_level?: string | null;
  collected_at?: string | null;
  is_processed?: boolean;
  entities?: unknown[];
  tags?: string[];
}

export interface AgentStatus {
  name: string;
  status: string;
  current_task?: string | null;
  execution_count?: number;
}

export interface RecentExecution {
  id?: string;
  execution_id?: string;
  query?: string;
  status?: string;
  started_at?: string;
  completed_at?: string;
  start_time?: string;
  end_time?: string;
  result_summary?: string | null;
  results_summary?: string | null;
  agent_name?: string;
  duration_seconds?: number;
  steps?: number;
  error?: string | null;
}

export interface BlackTalkTerm {
  id: string;
  term: string;
  meaning: string;
  context?: string;
  source?: string;
  category?: string;
  confidence?: number;
  created_at?: string;
  updated_at?: string;
}

export interface BlackTalkDecodeResult {
  original_text: string;
  decoded_text: string;
  decoded_terms: unknown[];
  terms_found: number;
  auto_learned: unknown[];
  found_terms: Array<{
    term: string;
    meaning: string;
    position: number[];
  }>;
}

export interface BlackTalkStats {
  total_terms: number;
  categories: Record<string, number>;
  sources: Record<string, number>;
  average_confidence: number;
}

export interface GraphEntity {
  id: string;
  type: string;
  value: string;
  context?: string | null;
  confidence?: number;
  first_seen?: string;
  last_seen?: string;
}

export interface GraphRelation {
  id: string;
  source_entity_id: string;
  target_entity_id: string;
  type: string;
  confidence?: number;
  evidence?: string | null;
  first_seen?: string;
  last_seen?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphNode {
  id: string;
  label: string;
  entity_type: string;
  properties: Record<string, unknown>;
  confidence?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation_type: string;
  properties: Record<string, unknown>;
  confidence?: number;
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  entity_types: Record<string, number>;
}

export interface CommunityResult {
  algorithm: string;
  communities: Array<{
    member_count: number;
    members: Array<{
      id: string;
      type: string;
      value: string;
    }>;
  }>;
  community_count: number;
}

export interface PathResult {
  source_id: string;
  target_id: string;
  paths: Array<Array<{
    id: string;
    type?: string;
    value?: string;
  }>>;
  path_count: number;
  message?: string;
}

export interface PIR {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  status: 'draft' | 'active' | 'executing' | 'fulfilled' | 'archived';
  keywords: string[];
  target_sources: string[];
  target_entities: unknown[];
  tasks: PIRTask[];
  fulfillment_score: number;
  generated_reports: unknown[];
  created_at?: string;
  updated_at?: string;
  results_summary?: string;
}

export interface PIRTask {
  id: string;
  pir_id: string;
  agent_type: string;
  task_description?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: Record<string, unknown> | null;
  created_at?: string;
  updated_at?: string;
}

export interface Report {
  id: string;
  title: string;
  report_type: string;
  status: string;
  content?: string | null;
  sections?: unknown[];
  related_intelligence?: unknown[];
  pir_ids?: string[];
  intelligence_ids?: string[];
  task_id?: string;
  created_at?: string;
  updated_at?: string;
}

export interface TaskStatus {
  task_id: string;
  status: string;
  message?: string;
  execution_id?: string;
  results?: unknown;
  results_summary?: string;
  progress?: number;
  current_step?: string;
}

export interface MarketState {
  sector: string;
  sector_name: string;
  threat_level: string;
  estimated_loss: number;
  loss_basis: string;
  activity_index: number;
  trend: string;
  last_updated: string;
  transaction_count: number;
  alert_count: number;
}

export interface EconomicDashboard {
  total_estimated_loss: number;
  active_markets: number;
  active_alerts: number;
  total_transactions: number;
  market_summary: MarketState[];
}

export interface EconomicTransaction {
  id: string;
  sector: string;
  tx_type: string;
  amount: number;
  price: number;
  total_value: number;
  risk_score: number;
  from_entity: string;
  to_entity: string;
  timestamp: string;
  description?: string;
}

export interface EconomicAlert {
  id: string;
  sector: string;
  severity: string;
  message: string;
  is_resolved: boolean;
  created_at: string;
  related_transactions?: string[];
}

export interface EconomicImpact {
  id: string;
  sector: string;
  threat_level: string;
  estimated_loss: number;
  loss_basis: string;
  affected_entities: number;
  timestamp: string;
}

export interface SectorFlow {
  sector: string;
  inflow: number;
  outflow: number;
  net_flow: number;
  top_entities: Array<{entity: string; volume: number}>;
}

export interface SimulateImpactRequest {
  threat_categories: string[];
  threat_level: string;
  intelligence_ids?: string[];
  content_summary?: string;
}

export interface SimulateImpactResponse {
  impacts: EconomicImpact[];
  alerts: EconomicAlert[];
  impacts_count: number;
  alerts_count: number;
}

export interface DataSourceInfo {
  sector: string;
  source: string;
  year: number;
  annual_loss_cny?: number;
  annual_loss_usd?: number;
  market_size_usd?: number;
  avg_cost_per_breach_usd?: number;
  annual_cases?: number;
  annual_attacks?: number;
}

export interface ExtractedEntity {
  type: string;
  value: string;
  context?: string;
}

export interface AttackPattern {
  name: string;
  description: string;
  indicators: string[];
  severity: string;
}

export interface ChainStage {
  stage: string;
  description: string;
  confidence: number;
}

export interface CleanResult {
  original_content: string;
  cleaned_content: string;
  entities: ExtractedEntity[];
  threat_level: string;
  threat_categories: string[];
  decoded_terms: Record<string, string>;
  dedup_stats?: {
    original_count: number;
    deduped_count: number;
    dedup_rate: number;
  };
}

export interface AnalysisResult {
  patterns: AttackPattern[];
  technical_chain: ChainStage[];
  threat_categories: string[];
  confidence: number;
  summary?: string;
}

export interface ReportResult {
  executive_summary: string;
  key_findings: string[];
  recommendations: string[];
  related_entities: ExtractedEntity[];
  stix_export?: Record<string, unknown>;
}

export type AnalysisType = 'zero_day' | 'attribution' | 'provenance' | 'decay' | 'attack_prediction' | 'deep_analysis';

export type AnalysisStatus = 'pending' | 'running' | 'completed' | 'failed' | 'timeout' | 'skipped';

export interface AnalysisResultItem {
  id: string;
  analysis_type: AnalysisType;
  target_id: string;
  target_type: string;
  result_summary: string;
  findings: unknown[];
  iocs: unknown[];
  recommendations: string[];
  result_data: Record<string, unknown>;
  confidence_score: number;
  status: AnalysisStatus;
  error_message: string | null;
  llm_tokens_used: number;
  input_content: string;
  model_name: string;
  analyzed_at: string;
  created_at: string;
}

export interface AnalysisStats {
  total_count: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  avg_confidence: number;
  scheduler_status: SchedulerStatus | null;
}

export interface AnalysisTypeStats {
  analysis_type: string;
  total_count: number;
  detection_count: number;
  avg_confidence: number;
  trend_data: Array<{ date: string; count: number }>;
  last_analyzed_at: string | null;
}

export interface DeepAnalysisRequestType {
  target_identifier: string;
  target_type: string;
  analysis_depth: 'quick' | 'standard' | 'deep';
  include_web_search: boolean;
  search_keywords: string[];
}

export interface DeepAnalysisResultType {
  result_id: string;
  threat_assessment: string;
  related_threats: Array<Record<string, unknown>>;
  risk_indicators: Array<Record<string, unknown>>;
  recommended_actions: string[];
  confidence_score: number;
  data_sources_used: string[];
}

export interface SchedulerStatus {
  is_running: boolean;
  last_run_time: string | null;
  next_run_time: string | null;
  total_runs: number;
  last_run_duration_seconds: number | null;
  last_run_items_processed: number;
  enabled_analysis_types: string[];
  schedule_interval_hours: number;
}

export interface TriggerAnalysisResponse {
  task_id: string;
  status: string;
  message: string;
}
