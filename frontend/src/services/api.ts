import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type {
  LoginResponse,
  DashboardStats,
  IntelligenceItem,
  IntelligenceDetail,
  IntelligenceStats,
  PaginatedResponse,
  BlackTalkTerm,
  BlackTalkDecodeResult,
  BlackTalkStats,
  GraphData,
  GraphEntity,
  GraphRelation,
  GraphStats,
  CommunityResult,
  PathResult,
  PIR,
  PIRTask,
  Report,
  TaskStatus,
  User,
  CleanResult,
  AnalysisResult,
  ReportResult,
  ExtractedEntity,
} from '../types';
import { tokenStorage } from '../utils/tokenStorage';

type MessageApi = {
  error: (content: string) => void;
  success: (content: string) => void;
  warning: (content: string) => void;
  info: (content: string) => void;
};

let _messageApi: MessageApi | null = null;

export function registerMessageApi(api: MessageApi) {
  _messageApi = api;
}

function showNetworkError(text: string) {
  if (_messageApi) {
    _messageApi.error(text);
  }
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;

let _abortController = new AbortController();

function cancelPendingRequests() {
  _abortController.abort();
  _abortController = new AbortController();
}

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  validateStatus: (status) => status >= 200 && status < 300,
});

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = tokenStorage.getToken();
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    config.signal = _abortController.signal;
    return config;
  },
  (error) => Promise.reject(error)
);

let _isRedirecting401 = false;

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.code === 'ECONNABORTED' || error.code === 'ERR_CANCELED') {
      showNetworkError('请求超时，请稍后重试');
      return Promise.reject(error);
    }
    if (!error.response) {
      showNetworkError('网络连接失败，请检查网络设置');
      return Promise.reject(error);
    }
    const status = error.response.status;
    if (status === 401) {
      if (_isRedirecting401) return Promise.reject(error);
      const token = tokenStorage.getToken();
      if (token === 'guest') return Promise.reject(error);
      const detail = (error.response.data as { detail?: string })?.detail;
      if (detail?.includes('已被撤销') || detail?.includes('无效令牌') || detail?.includes('expired')) {
        _isRedirecting401 = true;
        tokenStorage.clear();
        window.location.href = '/login';
      }
    } else if (status === 403) {
      showNetworkError('权限不足');
    } else if (status === 404) {
      showNetworkError('请求的资源不存在');
    } else if (status === 500) {
      showNetworkError('服务器内部错误');
    } else if (status >= 400 && status < 500) {
      const data = error.response.data as Record<string, unknown> | undefined;
      const detail = data?.detail || data?.message;
      if (typeof detail === 'string') {
        showNetworkError(detail);
      }
    }
    return Promise.reject(error);
  }
);

async function requestWithRetry<T>(fn: () => Promise<T>, retries = MAX_RETRIES): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0 && error instanceof AxiosError && !error.response) {
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      return requestWithRetry(fn, retries - 1);
    }
    throw error;
  }
}

function getErrorMessage(error: unknown): string {
  if (error instanceof AxiosError) {
    const data = error.response?.data as Record<string, unknown> | undefined;
    if (data) {
      if (typeof data.detail === 'string') return data.detail;
      const errObj = data.error as Record<string, unknown> | undefined;
      if (errObj && typeof errObj.message === 'string') return errObj.message;
    }
    if (error.message) return error.message;
  }
  if (error instanceof Error) return error.message;
  return '未知错误';
}

export { getErrorMessage };

// ─── Auth ───────────────────────────────────────────────────────────
export const authApi = {
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const { data } = await apiClient.post('/auth/login', { username, password });
    const user = data.user || { id: '', username: data.username || username, role: data.role || 'viewer', is_active: true, created_at: '' };
    tokenStorage.setToken(data.access_token);
    tokenStorage.setUser(user);
    return { ...data, user };
  },

  logout: async (): Promise<void> => {
    try { await apiClient.post('/auth/logout'); } catch { /* no-op */ }
    cancelPendingRequests();
    tokenStorage.clear();
    _isRedirecting401 = false;
  },

  getMe: async (): Promise<User> => {
    const { data } = await apiClient.get<User>('/auth/me');
    return data;
  },

  register: async (username: string, password: string, role?: string): Promise<User> => {
    const { data } = await apiClient.post<User>('/auth/register', { username, password, role: role ?? 'viewer' });
    return data;
  },

  changePassword: async (currentPassword: string, newPassword: string): Promise<void> => {
    await apiClient.put('/auth/password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  },

  updateProfile: async (payload: { display_name?: string; email?: string }): Promise<void> => {
    await apiClient.put('/auth/profile', payload);
  },
};

// ─── Dashboard ──────────────────────────────────────────────────────
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    return requestWithRetry(async () => {
      const { data } = await apiClient.get<DashboardStats>('/dashboard/stats');
      return data;
    });
  },

  getRecentIntelligence: async (limit?: number): Promise<PaginatedResponse<IntelligenceItem>> => {
    const { data } = await apiClient.get('/dashboard/recent', { params: { limit: limit ?? 10 } });
    return { items: data.items || [], total: data.total || 0, offset: data.offset ?? 0, limit: data.limit ?? 10 };
  },

  getThreatDistribution: async (): Promise<{ threat_levels: Record<string, number>; entity_types: Record<string, number> }> => {
    const { data } = await apiClient.get('/dashboard/threat-distribution');
    return { threat_levels: data.threat_levels || {}, entity_types: data.entity_types || {} };
  },

  getAgentStatus: async (): Promise<{ agents: unknown; recent_executions: unknown[] }> => {
    const { data } = await apiClient.get('/dashboard/agent-status');
    return { agents: data.agents, recent_executions: data.recent_executions || [] };
  },

  getTrend: async (days?: number): Promise<{ trend: Array<{ date: string; critical: number; high: number; medium: number; total: number }> }> => {
    const { data } = await apiClient.get('/dashboard/trend', { params: { days: days ?? 7 } });
    return { trend: data.trend || [] };
  },

  refreshData: async (): Promise<{ task_id: string; status: string }> => {
    const { data } = await apiClient.post('/dashboard/refresh-data');
    return { task_id: data.task_id, status: data.status };
  },

  getRefreshProgress: async (taskId: string): Promise<{ status: string; progress: number; message: string; new_count: number }> => {
    const { data } = await apiClient.get(`/dashboard/refresh-progress/${taskId}`);
    return { status: data.status, progress: data.progress ?? (data.status === 'completed' ? 100 : 50), message: data.message || '', new_count: data.new_count || 0 };
  },
};

// ─── Intelligence ───────────────────────────────────────────────────
export const intelligenceApi = {
  list: async (params?: {
    source?: string;
    threat_level?: string;
    status?: string;
    search?: string;
    offset?: number;
    limit?: number;
  }): Promise<PaginatedResponse<IntelligenceItem>> => {
    const { data } = await apiClient.get('/intelligence', { params: { source: params?.source, threat_level: params?.threat_level, status: params?.status, search: params?.search, offset: params?.offset ?? 0, limit: params?.limit ?? 50 } });
    const items: IntelligenceItem[] = (data.items || []).map((t: Record<string, unknown>) => ({
      id: t.id as string,
      content: (t.content || '') as string,
      source: (t.source || 'unknown') as string,
      threat_level: (t.threat_level || 'medium') as string | null,
      status: t.status as string,
      collected_at: (t.collected_at || t.created_at || null) as string | null,
      entities_count: (t.entities_count as number) || 0,
      blacktalk_count: (t.blacktalk_count as number) || 0,
      type: (t.type || 'raw') as 'raw' | 'cleaned' | 'analyzed',
    }));
    return { items, total: data.total || items.length, offset: data.offset ?? 0, limit: data.limit ?? 50 };
  },

  get: async (id: string): Promise<IntelligenceDetail> => {
    const { data } = await apiClient.get(`/intelligence/${id}`);
    return data;
  },

  create: async (intel: { source?: string; content: string; source_url?: string; metadata?: Record<string, unknown> }): Promise<IntelligenceItem> => {
    const { data } = await apiClient.post('/intelligence', {
      source: intel.source || 'manual',
      content: intel.content,
      source_url: intel.source_url,
      metadata: intel.metadata || {},
    });
    return data;
  },

  updateStatus: async (id: string, status: string): Promise<IntelligenceItem> => {
    const { data } = await apiClient.patch(`/intelligence/${id}/status`, { status });
    return data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/intelligence/${id}`);
  },

  getStats: async (): Promise<IntelligenceStats> => {
    const { data } = await apiClient.get('/intelligence/stats');
    return { total: data.total || 0, by_status: data.by_status || {}, by_source: data.by_source || {}, by_threat_level: data.by_threat_level || {} };
  },

  clean: async (content: string, source?: string): Promise<CleanResult> => {
    const { data } = await apiClient.post('/intelligence/pipeline/clean', { content, source: source || 'unknown' });
    return data;
  },

  analyze: async (content: string, cleanedData?: Record<string, unknown>): Promise<AnalysisResult> => {
    const { data } = await apiClient.post('/intelligence/pipeline/analyze', {
      content,
      cleaned_data: cleanedData,
    });
    return data;
  },

  getRecentPipeline: async (limit?: number): Promise<IntelligenceItem[]> => {
    const { data } = await apiClient.get('/intelligence/pipeline/recent', { params: { limit: limit || 20 } });
    return data.items || [];
  },

  getEntities: async (params?: { type?: string; keyword?: string; limit?: number }): Promise<ExtractedEntity[]> => {
    const { data } = await apiClient.get('/entities', { params: { type: params?.type, keyword: params?.keyword, limit: params?.limit ?? 50 } });
    return data.entities || [];
  },
};

// ─── BlackTalk ──────────────────────────────────────────────────────
export const blacktalkApi = {
  listTerms: async (params?: {
    category?: string;
    search?: string;
    offset?: number;
    limit?: number;
  }): Promise<PaginatedResponse<BlackTalkTerm>> => {
    const { data } = await apiClient.get('/blacktalk/terms', { params: { category: params?.category, search: params?.search, limit: params?.limit ?? 50 } });
    return { items: data.items || [], total: data.total || 0, offset: data.offset ?? 0, limit: data.limit ?? 50 };
  },

  addTerm: async (term: string, meaning: string, context?: string, source?: string, category?: string): Promise<BlackTalkTerm> => {
    const { data } = await apiClient.post<BlackTalkTerm>('/blacktalk/terms', { term, meaning, category: category || 'general' });
    return data;
  },

  decode: async (text: string): Promise<BlackTalkDecodeResult> => {
    const { data } = await apiClient.post<BlackTalkDecodeResult>('/blacktalk/decode', { text });
    return data;
  },

  search: async (q: string, n?: number): Promise<{ query: string; results: BlackTalkTerm[]; total: number }> => {
    const { data } = await apiClient.get('/blacktalk/search', { params: { q, limit: n ?? 10 } });
    return { query: q, results: data.results || [], total: data.total || 0 };
  },

  getStats: async (): Promise<BlackTalkStats> => {
    const { data } = await apiClient.get<BlackTalkStats>('/blacktalk/stats');
    return data;
  },
};

// ─── Graph ──────────────────────────────────────────────────────────
export const graphApi = {
  getData: async (params?: {
    entity_type?: string;
    search?: string;
    depth?: number;
    limit?: number;
  }): Promise<GraphData> => {
    const { data } = await apiClient.get<GraphData>('/graph/data', { params: { entity_type: params?.entity_type, search: params?.search, depth: params?.depth, limit: params?.limit ?? 100 } });
    return data;
  },

  getStats: async (): Promise<GraphStats> => {
    const { data } = await apiClient.get<GraphStats>('/graph/stats');
    return data;
  },

  listEntities: async (params?: {
    entity_type?: string;
    search?: string;
    offset?: number;
    limit?: number;
  }): Promise<PaginatedResponse<GraphEntity>> => {
    const { data } = await apiClient.get('/graph/entities', { params: { entity_type: params?.entity_type, search: params?.search, offset: params?.offset ?? 0, limit: params?.limit ?? 50 } });
    return { items: data.items || [], total: data.total || 0, offset: data.offset ?? 0, limit: data.limit ?? 50 };
  },

  getEntity: async (entityId: string): Promise<{ entity: GraphEntity; relations: GraphRelation[]; relation_count: number }> => {
    const { data } = await apiClient.get(`/graph/entities/${entityId}`);
    return data;
  },

  addEntity: async (type: string, value: string, context?: string, confidence?: number): Promise<{ id: string }> => {
    const { data } = await apiClient.post('/graph/entities', { type, value, context, confidence: confidence ?? 0.5 });
    return { id: data.id };
  },

  deleteEntity: async (entityId: string): Promise<void> => {
    await apiClient.delete(`/graph/entities/${entityId}`);
  },

  addRelation: async (sourceEntityId: string, targetEntityId: string, type: string, confidence?: number, evidence?: string): Promise<{ id: string }> => {
    const { data } = await apiClient.post('/graph/relations', {
      source_entity_id: sourceEntityId,
      target_entity_id: targetEntityId,
      type,
      confidence: confidence ?? 0.5,
      evidence,
    });
    return { id: data.id };
  },

  findPath: async (sourceId: string, targetId: string, maxDepth?: number): Promise<PathResult> => {
    const { data } = await apiClient.post<PathResult>('/graph/path', {
      source_id: sourceId, target_id: targetId, max_depth: maxDepth ?? 5,
    });
    return data;
  },

  findCommunities: async (algorithm?: string, minSize?: number): Promise<CommunityResult> => {
    const { data } = await apiClient.post<CommunityResult>('/graph/communities', {
      algorithm: algorithm ?? 'louvain', min_size: minSize ?? 2,
    });
    return data;
  },

  getSubgraph: async (entityId: string, depth?: number): Promise<GraphData> => {
    const { data } = await apiClient.get<GraphData>(`/graph/subgraph/${entityId}`, { params: { depth: depth ?? 1 } });
    return data;
  },
};

// ─── PIRs ───────────────────────────────────────────────────────────
export const pirsApi = {
  list: async (params?: {
    status?: string;
    priority?: string;
    offset?: number;
    limit?: number;
  }): Promise<PaginatedResponse<PIR>> => {
    const { data } = await apiClient.get('/pirs', { params: { status: params?.status, priority: params?.priority, offset: params?.offset ?? 0, limit: params?.limit ?? 50 } });
    return { items: data.items || [], total: data.total || 0, offset: data.offset ?? 0, limit: data.limit ?? 50 };
  },

  get: async (pirId: string): Promise<PIR> => {
    const { data } = await apiClient.get<PIR>(`/pirs/${pirId}`);
    return data;
  },

  create: async (pir: {
    title: string;
    description?: string;
    priority?: string;
    keywords?: string[];
    target_sources?: string[];
  }): Promise<PIR> => {
    const { data } = await apiClient.post<PIR>('/pirs', pir);
    return data;
  },

  update: async (pirId: string, updates: Partial<PIR>): Promise<PIR> => {
    const { data } = await apiClient.patch<PIR>(`/pirs/${pirId}`, updates);
    return data;
  },

  delete: async (pirId: string): Promise<void> => {
    await apiClient.delete(`/pirs/${pirId}`);
  },

  decompose: async (pirId: string): Promise<{ pir_id: string; tasks: PIRTask[]; task_count: number }> => {
    const { data } = await apiClient.post(`/pirs/${pirId}/decompose`);
    return data;
  },

  execute: async (pirId: string): Promise<{ task_id: string; pir_id: string; status: string }> => {
    const { data } = await apiClient.post(`/pirs/${pirId}/execute`);
    return { task_id: data.task_id || '', pir_id: pirId, status: data.status };
  },

  listTasks: async (pirId: string): Promise<PIRTask[]> => {
    const { data } = await apiClient.get(`/pirs/${pirId}/tasks`);
    return data.tasks || [];
  },
};

// ─── Reports ────────────────────────────────────────────────────────
export const reportsApi = {
  list: async (params?: {
    report_type?: string;
    status?: string;
    offset?: number;
    limit?: number;
  }): Promise<PaginatedResponse<Report>> => {
    const { data } = await apiClient.get('/reports', { params: { report_type: params?.report_type, status: params?.status, offset: params?.offset ?? 0, limit: params?.limit ?? 20 } });
    return { items: data.items || [], total: data.total || 0, offset: data.offset ?? 0, limit: data.limit ?? 20 };
  },

  get: async (reportId: string): Promise<Report> => {
    const { data } = await apiClient.get<Report>(`/reports/${reportId}`);
    return data;
  },

  generate: async (params: {
    title: string;
    report_type?: string;
    pir_ids?: string[];
    intelligence_ids?: string[];
    context?: string;
  }): Promise<Report> => {
    const { data } = await apiClient.post<Report>('/reports/generate', {
      title: params.title,
      report_type: params.report_type || 'comprehensive',
      pir_ids: params.pir_ids || [],
      intelligence_ids: params.intelligence_ids || [],
      context: params.context || '',
    });
    return data;
  },

  update: async (reportId: string, updates: Partial<Report>): Promise<Report> => {
    const { data } = await apiClient.patch<Report>(`/reports/${reportId}`, updates);
    return data;
  },

  delete: async (reportId: string): Promise<void> => {
    await apiClient.delete(`/reports/${reportId}`);
  },

  export: async (reportId: string, format?: string): Promise<{ report_id: string; title: string; format: string; content: string }> => {
    const { data } = await apiClient.post(`/reports/${reportId}/export`, null, { params: { format: format ?? 'markdown' } });
    return data;
  },
};

// ─── AI Agent ────────────────────────────────────────────────────────
export const agentApi = {
  submitQuery: async (query: string, context?: Record<string, unknown>, maxIterations?: number): Promise<TaskStatus> => {
    const { data } = await apiClient.post('/deepseek/chat', {
      message: query,
      context: context?.session_id || '',
    });
    return { task_id: '', status: 'completed', message: data.response || '' };
  },

  getStatus: async (): Promise<{ agents: unknown }> => {
    const { data } = await apiClient.get('/agent/status');
    return { agents: data.agents };
  },

  getHistory: async (limit?: number): Promise<{ items: unknown[]; total: number }> => {
    const { data } = await apiClient.get('/agent/history', { params: { limit: limit ?? 100 } });
    return { items: data.items || [], total: data.total || 0 };
  },

  getExecution: async (executionId: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get(`/agent/execution/${executionId}`);
    return data;
  },

  getTaskStatus: async (taskId: string): Promise<TaskStatus> => {
    const { data } = await apiClient.get(`/tasks/${taskId}`);
    return { task_id: data.id || taskId, status: data.status, message: data.error_message || '' };
  },

  triggerCollection: async (): Promise<TaskStatus> => {
    const { data } = await apiClient.post('/agent/collect');
    return { task_id: data.task_id, status: data.status, message: data.message || '' };
  },

  triggerAnalysis: async (): Promise<TaskStatus> => {
    const { data } = await apiClient.post('/agent/analyze');
    return { task_id: data.task_id, status: data.status, message: data.message || '' };
  },

  generateReport: async (params: { intelligence_id?: string; content?: string }): Promise<ReportResult> => {
    const { data } = await apiClient.post('/agent/report/report', {
      intelligence_id: params.intelligence_id,
      content: params.content,
    });
    return data;
  },
};

// ─── DeepSeek ───────────────────────────────────────────────────────
const deepseekApi = {
  getStatus: async (): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/status');
    return data;
  },
  analyze: async (analysisType?: string, limit?: number, source?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/analyze', {
      analysis_type: analysisType || 'classify',
      limit: limit || 20,
      source: source || 'all',
    }, { timeout: 120000 });
    return data;
  },
  analyzeSingle: async (content: string, analysisType?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/analyze-single', {
      content,
      analysis_type: analysisType || 'full',
    }, { timeout: 60000 });
    return data;
  },
  chat: async (message: string, context?: string, enableWebSearch?: boolean, enableIntelContext?: boolean): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/chat', {
      message,
      context: context || '',
      enable_web_search: enableWebSearch ?? false,
      enable_intel_context: enableIntelContext ?? true,
    }, { timeout: 90000 });
    return data;
  },
  categorySummary: async (limit?: number): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/category-summary', { params: { limit: limit ?? 30 } });
    return data;
  },
  validateData: async (limit?: number): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/validate-data', { params: { limit: limit ?? 20 } });
    return data;
  },
  translate: async (text: string, sourceLang?: string, targetLang?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/translate', {
      text,
      source_lang: sourceLang || 'auto',
      target_lang: targetLang || 'zh',
    }, { timeout: 60000 });
    return data;
  },
  generateBrief: async (limit?: number, title?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/generate-brief', {
      limit: limit || 20,
      title: title || '每日情报简报',
    }, { timeout: 120000 });
    return data;
  },
  promptExperiment: async (testText?: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/prompt-experiment', { params: { test_text: testText || '请分析当前情报态势' }, timeout: 120000 });
    return data;
  },
  analysisHistory: async (analysisType?: string, limit?: number, offset?: number): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/analysis-history', { params: { analysis_type: analysisType, limit, offset } });
    return data;
  },
  listModels: async (): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/models');
    return data;
  },
  switchModel: async (modelId: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/models/switch', { model_id: modelId });
    return data;
  },
  addCustomModel: async (config: { name: string; provider: string; base_url: string; api_key: string; model_name: string; temperature?: number; max_tokens?: number }): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.post('/deepseek/models/custom', config);
    return data;
  },
  removeCustomModel: async (modelId: string): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.delete(`/deepseek/models/custom/${modelId}`);
    return data;
  },
  getCurrentModel: async (): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/deepseek/models/current');
    return data;
  },
};

// ─── Combined API export ───────────────────────────────────────────
export const api = {
  auth: authApi,
  dashboard: dashboardApi,
  intelligence: intelligenceApi,
  blacktalk: blacktalkApi,
  graph: graphApi,
  pirs: pirsApi,
  reports: reportsApi,
  agent: agentApi,
  deepseek: deepseekApi,
  zeroDay: {
    detect: async (text: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/zero-day/detect', { text });
      return data;
    },
    trackDrift: async (term: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/zero-day/drift/${encodeURIComponent(term)}`);
      return data;
    },
    trackMigration: async (term: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/zero-day/migration/${encodeURIComponent(term)}`);
      return data;
    },
    getRecentDetections: async (limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/zero-day/recent-detections', { params: { limit: limit ?? 20 } });
      return data;
    },
  },
  attackPrediction: {
    predict: async (entityId: string, depth?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/attack-prediction/predict', { entity_id: entityId, depth: depth ?? 5 });
      return data;
    },
    predictByName: async (name: string, depth?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/attack-prediction/predict-by-name', { name, depth: depth ?? 5 });
      return data;
    },
    simulate: async (entityId: string, steps?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/attack-prediction/simulate', { entity_id: entityId, steps: steps ?? 5 });
      return data;
    },
    earlyWarning: async (entityId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/attack-prediction/early-warning', { entity_id: entityId });
      return data;
    },
    getVisualization: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/attack-prediction/visualization');
      return data;
    },
  },
  provenance: {
    record: async (params: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/provenance/record', params);
      return data;
    },
    verify: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/provenance/verify/${intelligenceId}`);
      return data;
    },
    evolution: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/provenance/evolution/${intelligenceId}`);
      return data;
    },
    hallucinationCheck: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/provenance/hallucination-check/${intelligenceId}`);
      return data;
    },
    chain: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/provenance/chain/${intelligenceId}`);
      return data;
    },
    searchByContent: async (query: string, limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/provenance/search-by-content', { params: { query, limit: limit ?? 10 } });
      return data;
    },
    getRecent: async (limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/provenance/recent', { params: { limit: limit ?? 20 } });
      return data;
    },
    trace: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/provenance/trace/${encodeURIComponent(intelligenceId)}`);
      return data;
    },
    sourcePreview: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/provenance/source-preview/${encodeURIComponent(intelligenceId)}`);
      return data;
    },
  },
  attribution: {
    fingerprint: async (entityId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/attribution/fingerprint/${entityId}`);
      return data;
    },
    findSame: async (entityId: string, threshold?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/attribution/find-same/${entityId}`, { params: { threshold: threshold ?? 0.7 } });
      return data;
    },
    findSameByName: async (name: string, threshold?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/attribution/find-same-by-name/${encodeURIComponent(name)}`, { params: { threshold: threshold ?? 0.7 } });
      return data;
    },
    report: async (entityId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/attribution/report/${entityId}`);
      return data;
    },
    getEmbeddings2D: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/attribution/embeddings-2d');
      return data;
    },
    getTopEntities: async (limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/attribution/top-entities', { params: { limit: limit ?? 20 } });
      return data;
    },
  },
  decay: {
    getIntelligence: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/decay/intelligence/${encodeURIComponent(intelligenceId)}`);
      return data;
    },
    getCurve: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/decay/curve/${encodeURIComponent(intelligenceId)}`);
      return data;
    },
    batch: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/decay/batch');
      return data;
    },
    recommendations: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/decay/recommendations');
      return data;
    },
  },
  innovation: {
    getStats: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/innovation/stats');
      return data;
    },
  },
  alerts: {
    getActive: async (severity?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/alerts/active', { params: severity ? { severity } : {} });
      return { alerts: data.alerts || [], total: data.total || 0 };
    },
    getStats: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/alerts/stats');
      return data;
    },
    acknowledge: async (alertId: string): Promise<Record<string, unknown>> => {
      try { await apiClient.post(`/alerts/${alertId}/acknowledge`); } catch { /* best effort */ } return { acknowledged: alertId };
    },
    getRules: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/alerts/rules');
      return data;
    },
    toggleRule: async (ruleId: string, enabled: boolean): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.put(`/alerts/rules/${encodeURIComponent(ruleId)}/toggle`, null, { params: { enabled } });
      return data;
    },
    testTrigger: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/alerts/test-trigger');
      return data;
    },
  },
  organism: {
    spawn: async (intelligenceId: string, species: string, initialData: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/spawn', { intelligence_id: intelligenceId, species, initial_data: initialData });
      return data;
    },
    evolve: async (organismId: string, newData?: Record<string, unknown>, trigger?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/evolve', {
        organism_id: organismId,
        new_data: newData ?? {},
        trigger: trigger ?? 'manual',
      });
      return data;
    },
    checkVitality: async (organismId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/organism/vitality/${encodeURIComponent(organismId)}`);
      return data;
    },
    getTimeline: async (organismId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/organism/timeline/${encodeURIComponent(organismId)}`);
      return data;
    },
    getOffspring: async (organismId: string, depth?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/organism/offspring/${encodeURIComponent(organismId)}`, { params: { depth: depth ?? 3 } });
      return data;
    },
    registerPrediction: async (entityId: string, predictedSteps: Record<string, unknown>[], validationWindowHours?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/prediction/register', { entity_id: entityId, predicted_steps: predictedSteps, validation_window_hours: validationWindowHours ?? 24 });
      return data;
    },
    validatePredictions: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/prediction/validate');
      return data;
    },
    getPredictionAccuracy: async (entityId?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/organism/prediction/accuracy', { params: entityId ? { entity_id: entityId } : {} });
      return data;
    },
    calibrateModel: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/prediction/calibrate');
      return data;
    },
    archiveOrganism: async (organismId: string, cause?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/organism/gene/archive/${encodeURIComponent(organismId)}`, null, { params: { cause: cause ?? 'expired' } });
      return data;
    },
    findGeneMatches: async (newIntelligenceData: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/gene/match', { new_intelligence_data: newIntelligenceData });
      return data;
    },
    inheritGenes: async (newOrganismId: string, parentGeneIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/gene/inherit', { new_organism_id: newOrganismId, parent_gene_ids: parentGeneIds });
      return data;
    },
    getGenealogy: async (organismId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/organism/genealogy/${encodeURIComponent(organismId)}`);
      return data;
    },
    runLifecycleCheck: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/organism/lifecycle-check');
      return data;
    },
    listOrganisms: async (species?: string, aliveOnly?: boolean): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/organism/organisms', { params: { species, alive_only: aliveOnly ?? true } });
    return data;
  },
  listGenes: async (): Promise<Record<string, unknown>> => {
    const { data } = await apiClient.get('/organism/genes');
    return data;
  },
  },
  promptEngine: {
    list: async (params?: { search?: string; category?: string; status?: string; offset?: number; limit?: number }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/prompt-engine/templates', { params });
      return data;
    },
    create: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/prompt-engine/templates', data);
      return res.data;
    },
    get: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/prompt-engine/templates/${id}`);
      return data;
    },
    update: async (id: string, data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.put(`/prompt-engine/templates/${id}`, data);
      return res.data;
    },
    delete: async (id: string): Promise<void> => {
      await apiClient.delete(`/prompt-engine/templates/${id}`);
    },
    render: async (id: string, variables: Record<string, string>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/prompt-engine/templates/${id}/render`, { variables });
      return data;
    },
    createVersion: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/prompt-engine/templates/${id}/versions`);
      return data;
    },
    getVersions: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/prompt-engine/templates/${id}/versions`);
      return data;
    },
    createABTest: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/prompt-engine/ab-test', data);
      return res.data;
    },
    getABTest: async (testId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/prompt-engine/ab-test/${testId}`);
      return data;
    },
  },
  dataPipeline: {
    listTasks: async (params?: { search?: string; type?: string; status?: string; offset?: number; limit?: number }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/data-pipeline/tasks', { params });
      return data;
    },
    createTask: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/data-pipeline/tasks', data);
      return res.data;
    },
    getTask: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/data-pipeline/tasks/${id}`);
      return data;
    },
    executeTask: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/data-pipeline/tasks/${id}/execute`);
      return data;
    },
    cancelTask: async (id: string): Promise<void> => {
      await apiClient.post(`/data-pipeline/tasks/${id}/cancel`);
    },
    deleteTask: async (id: string): Promise<void> => {
      await apiClient.delete(`/data-pipeline/tasks/${id}`);
    },
    runPipeline: async (steps: Record<string, unknown>[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/data-pipeline/pipeline/run', { steps });
      return data;
    },
    getPipelineStatus: async (pipelineId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/data-pipeline/pipeline/status/${pipelineId}`);
      return data;
    },
  },
  finetune: {
    listTasks: async (params?: { search?: string; method?: string; status?: string; offset?: number; limit?: number }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/finetune/tasks', { params });
      return data;
    },
    createTask: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/finetune/tasks', data);
      return res.data;
    },
    getTask: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/finetune/tasks/${id}`);
      return data;
    },
    startTask: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/finetune/tasks/${id}/start`);
      return data;
    },
    cancelTask: async (id: string): Promise<void> => {
      await apiClient.post(`/finetune/tasks/${id}/cancel`);
    },
    getMetrics: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/finetune/tasks/${id}/metrics`);
      return data;
    },
    evaluate: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/finetune/tasks/${id}/evaluate`);
      return data;
    },
    listModels: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/finetune/models');
      return data;
    },
  },
  smartqa: {
    listConversations: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/smartqa/conversations');
      return data;
    },
    createConversation: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/smartqa/conversations', data);
      return res.data;
    },
    getConversation: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/smartqa/conversations/${id}`);
      return data;
    },
    chat: async (id: string, message: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/smartqa/conversations/${id}/chat`, { message });
      return data;
    },
    deleteConversation: async (id: string): Promise<void> => {
      await apiClient.delete(`/smartqa/conversations/${id}`);
    },
    getIndustries: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/smartqa/industries');
      return data;
    },
  },
  contentGen: {
    list: async (params?: { content_type?: string; review_status?: string; search?: string; offset?: number; limit?: number }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/content-gen/contents', { params: { content_type: params?.content_type, review_status: params?.review_status, search: params?.search, offset: params?.offset, limit: params?.limit } });
      return data;
    },
    generate: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/content-gen/generate', data);
      return res.data;
    },
    get: async (id: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/content-gen/contents/${id}`);
      return data;
    },
    review: async (id: string, data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post(`/content-gen/contents/${id}/review`, data);
      return res.data;
    },
    delete: async (id: string): Promise<void> => {
      await apiClient.delete(`/content-gen/contents/${id}`);
    },
  },
  analytics: {
    query: async (query: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/data-analytics/query', { query });
      return data;
    },
    chartRecommend: async (query: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/data-analytics/chart-recommend', { analysis_type: query });
      return data;
    },
    anomalyDetection: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/data-analytics/anomaly-detect', {});
      return data;
    },
    trendPrediction: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/data-analytics/trend-predict', {});
      return data;
    },
    dashboardStats: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/data-analytics/dashboard/stats');
      return data;
    },
  },
  translation: {
    translate: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/translation/translate', data);
      return res.data;
    },
    batchTranslate: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/translation/batch-translate', data);
      return res.data;
    },
    getLanguages: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/translation/languages');
      return data;
    },
    getTerminology: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/translation/terminology');
      return data;
    },
    addTerminology: async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const res = await apiClient.post('/translation/terminology', data);
      return res.data;
    },
  },
  intelPipeline: {
    analyzeSingle: async (content: string, source?: string, useLlm?: boolean): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intel-pipeline/analyze', {
        content,
        source: source || 'manual',
        use_llm: useLlm ?? true,
      }, { timeout: 120000 });
      return data;
    },
    analyzeBatch: async (items: Array<Record<string, unknown>>, useLlm?: boolean, maxConcurrent?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intel-pipeline/analyze/batch', {
        items,
        use_llm: useLlm ?? true,
        max_concurrent: maxConcurrent ?? 5,
      }, { timeout: 300000 });
      return data;
    },
    importItems: async (items: Array<Record<string, unknown>>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intel-pipeline/import', items);
      return data;
    },
    importFile: async (file: File): Promise<Record<string, unknown>> => {
      const formData = new FormData();
      formData.append('file', file);
      const { data } = await apiClient.post('/intel-pipeline/import/file', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      });
      return data;
    },
    getPipelineStats: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/pipeline/stats');
      return data;
    },
    getSchedulerStats: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/scheduler/stats');
      return data;
    },
    listSources: async (status?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/scheduler/sources', { params: status ? { status } : {} });
      return data;
    },
    getSource: async (sourceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/intel-pipeline/scheduler/sources/${sourceId}`);
      return data;
    },
    createSource: async (sourceData: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intel-pipeline/scheduler/sources', sourceData);
      return data;
    },
    updateSource: async (sourceId: string, updates: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.patch(`/intel-pipeline/scheduler/sources/${sourceId}`, updates);
      return data;
    },
    deleteSource: async (sourceId: string): Promise<void> => {
      await apiClient.delete(`/intel-pipeline/scheduler/sources/${sourceId}`);
    },
    triggerSource: async (sourceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/intel-pipeline/scheduler/trigger/${sourceId}`);
      return data;
    },
    triggerAll: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intel-pipeline/scheduler/trigger-all');
      return data;
    },
    getCollectionHistory: async (limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/scheduler/history', { params: { limit: limit ?? 20 } });
      return data;
    },
    getCheatingScenarios: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/cheating-scenarios');
      return data;
    },
    getIntentLevels: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/intent-levels');
      return data;
    },
    getSlangDictionary: async (keyword?: string, limit?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/intel-pipeline/slang-dictionary', { params: { keyword, limit: limit ?? 100 } });
      return data;
    },
  },
  deployment: {
    health: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/health');
      return data;
    },
    detailedHealth: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/health/detailed');
      return data;
    },
    getConfig: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/config');
      return data;
    },
    updateConfig: async (envConfig: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.put('/deployment/config', envConfig);
      return data;
    },
    listEnvironments: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/config/environments');
      return data;
    },
    createEnvironment: async (envConfig: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/deployment/config/environments', envConfig);
      return data;
    },
    deleteEnvironment: async (envName: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.delete(`/deployment/config/environments/${envName}`);
      return data;
    },
    dockerDeploy: async (config: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/deployment/docker/deploy', config);
      return data;
    },
    listContainers: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/docker/containers');
      return data;
    },
    stopContainer: async (containerId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/deployment/docker/containers/${containerId}/stop`);
      return data;
    },
    restartContainer: async (containerId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post(`/deployment/docker/containers/${containerId}/restart`);
      return data;
    },
    huaweiCloudDeploy: async (config: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/deployment/huawei-cloud/deploy', config);
      return data;
    },
    getHuaweiCloudStatus: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/huawei-cloud/status');
      return data;
    },
    getMetrics: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/metrics');
      return data;
    },
    getMetricsHistory: async (hours?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/metrics/history', { params: { hours: hours ?? 24 } });
      return data;
    },
    rollback: async (targetVersion: string, reason?: string, force?: boolean): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/deployment/rollback', { target_version: targetVersion, reason, force: force ?? false });
      return data;
    },
    listDeployments: async (params?: { deploy_type?: string; status?: string; offset?: number; limit?: number }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/deployments', { params });
      return data;
    },
    getDeployment: async (deployId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/deployment/deployments/${deployId}`);
      return data;
    },
    listVersions: async (): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/deployment/versions');
      return data;
    },
    configureHealthCheck: async (config: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/deployment/health-check/config', config);
      return data;
    },
  },
  auditLog: {
    list: async (params?: { offset?: number; limit?: number; action?: string; username?: string; keyword?: string; date_from?: string; date_to?: string }): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/audit-log', { params });
      return data;
    },
    getStatistics: async (days?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get('/audit-log/statistics', { params: { days: days ?? 30 } });
      return data;
    },
  },
  // 5个新引擎API
  intelligenceQuality: {
    assess: async (intelligenceIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-quality/assess', { intelligence_ids: intelligenceIds });
      return data;
    },
    getSourceReputation: async (source: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/intelligence-quality/source-reputation/${encodeURIComponent(source)}`);
      return data;
    },
    updateSourceReputation: async (source: string, wasAccurate: boolean, weight?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-quality/update-source-reputation', null, {
        params: { source, was_accurate: wasAccurate, weight: weight ?? 0.1 }
      });
      return data;
    },
  },
  eventCorrelation: {
    analyze: async (eventIds: string[], timeWindowHours?: number, methods?: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/event-correlation/analyze', {
        event_ids: eventIds,
        time_window_hours: timeWindowHours ?? 72,
        methods: methods ?? ['temporal', 'entity', 'semantic']
      });
      return data;
    },
    getTemporalCorrelations: async (eventId: string, windowHours?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/event-correlation/temporal/${encodeURIComponent(eventId)}`, {
        params: { window_hours: windowHours ?? 72 }
      });
      return data;
    },
    reconstructAttackChain: async (eventIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/event-correlation/reconstruct-attack-chain', eventIds);
      return data;
    },
  },
  threatBehavior: {
    buildProfile: async (incidentIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/threat-behavior/profile', { incident_ids: incidentIds });
      return data;
    },
    extractTTPs: async (text: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/threat-behavior/extract-ttps', null, { params: { text } });
      return data;
    },
    clusterActors: async (profileIds: string[], minSimilarity?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/threat-behavior/cluster-actors', profileIds, {
        params: { min_similarity: minSimilarity ?? 0.6 }
      });
      return data;
    },
    matchActors: async (incidentId: string, topK?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/threat-behavior/match-actors/${encodeURIComponent(incidentId)}`, {
        params: { top_k: topK ?? 5 }
      });
      return data;
    },
    detectAnomaly: async (incidentId: string, baselineProfileId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/threat-behavior/detect-anomaly', null, {
        params: { incident_id: incidentId, baseline_profile_id: baselineProfileId }
      });
      return data;
    },
  },
  riskScoring: {
    calculate: async (threatEvent: Record<string, unknown>, context?: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/risk-scoring/calculate', { threat_event: threatEvent, context });
      return data;
    },
    batchCalculate: async (threatEvents: Record<string, unknown>[], context?: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/risk-scoring/batch-calculate', threatEvents, { params: { context } });
      return data;
    },
    calculateDecay: async (initialScore: number, eventTimestamp: string, decayModel?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/risk-scoring/decay', null, {
        params: { initial_score: initialScore, event_timestamp: eventTimestamp, decay_model: decayModel ?? 'exponential' }
      });
      return data;
    },
    analyzeCascadeRisk: async (primaryEventId: string, dependentEventIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/risk-scoring/cascade-analysis', null, {
        params: { primary_event_id: primaryEventId, dependent_event_ids: dependentEventIds }
      });
      return data;
    },
    getRiskMatrix: async (industry: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/risk-scoring/risk-matrix/${encodeURIComponent(industry)}`);
      return data;
    },
    getRiskThresholds: async (industry: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/risk-scoring/thresholds/${encodeURIComponent(industry)}`);
      return data;
    },
  },
  intelligenceFusion: {
    fuse: async (intelligenceIds: string[], strategy?: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-fusion/fuse', intelligenceIds, {
        params: { strategy: strategy ?? 'weighted_average' }
      });
      return data;
    },
    deduplicate: async (threshold?: number): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-fusion/deduplicate', null, {
        params: { threshold: threshold ?? 0.85 }
      });
      return data;
    },
    resolveConflicts: async (intelligenceIds: string[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-fusion/resolve-conflicts', intelligenceIds);
      return data;
    },
    aggregateEvidence: async (evidenceList: Record<string, unknown>[]): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.post('/intelligence-fusion/aggregate-evidence', evidenceList);
      return data;
    },
    detectContradictions: async (intelligenceId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/intelligence-fusion/contradictions/${encodeURIComponent(intelligenceId)}`);
      return data;
    },
    getProvenance: async (fusedId: string): Promise<Record<string, unknown>> => {
      const { data } = await apiClient.get(`/intelligence-fusion/provenance/${encodeURIComponent(fusedId)}`);
      return data;
    },
  },
};

export default apiClient;
