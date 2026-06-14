import { tokenStorage } from '../utils/tokenStorage';

const AI_BASE_URL = '/api/v1';

class AiApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = AI_BASE_URL;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const token = tokenStorage.getToken();
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const response = await fetch(`${this.baseUrl}${path}`, {
      headers: { ...headers, ...options?.headers as Record<string, string> },
      ...options,
    });
    if (!response.ok) throw new Error(`AI API error: ${response.status}`);
    const data = await response.json();
    return data.data;
  }

  createPrompt = (data: any) => this.request('/prompt-engine/templates', { method: 'POST', body: JSON.stringify(data) });
  listPrompts = (pageNum = 1, pageSize = 20) => this.request(`/prompt-engine/templates?pageNum=${pageNum}&pageSize=${pageSize}`);
  getPrompt = (id: string) => this.request(`/prompt-engine/templates/${id}`);
  updatePrompt = (id: string, data: any) => this.request(`/prompt-engine/templates/${id}`, { method: 'PUT', body: JSON.stringify(data) });
  deletePrompt = (id: string) => this.request(`/prompt-engine/templates/${id}`, { method: 'DELETE' });
  getPromptVersions = (id: string) => this.request(`/prompt-engine/templates/${id}/versions`);
  rollbackPrompt = (id: string, version: number) => this.request(`/prompt-engine/templates/${id}/versions/${version}/rollback`, { method: 'POST' });
  testPrompt = (id: string, variables: Record<string, string>) => this.request(`/prompt-engine/templates/${id}/render`, { method: 'POST', body: JSON.stringify(variables) });
  abTestPrompt = (id: string, versionA: number, versionB: number, variables: Record<string, string>) =>
    this.request('/prompt-engine/ab-test', { method: 'POST', body: JSON.stringify({ versionA, versionB, variables }) });

  createConversation = (data: any) => this.request('/smartqa/conversations', { method: 'POST', body: JSON.stringify(data) });
  listConversations = () => this.request('/smartqa/conversations');
  getMessages = (id: string) => this.request(`/smartqa/conversations/${id}`);
  deleteConversation = (id: string) => this.request(`/smartqa/conversations/${id}`, { method: 'DELETE' });
  switchIndustry = (id: string, industryContext: string) =>
    this.request(`/smartqa/conversations/${id}/industry`, { method: 'PUT', body: JSON.stringify({ industryContext }) });

  translate = (data: any) => this.request('/translation/translate', { method: 'POST', body: JSON.stringify(data) });
  batchTranslate = (data: any) => this.request('/translation/batch-translate', { method: 'POST', body: JSON.stringify(data) });
  getLanguages = () => this.request('/translation/languages');

  listContents = (status?: string) => this.request(`/content-gen/contents${status ? `?status=${status}` : ''}`);
  reviewContent = (id: string, data: any) => this.request(`/content-gen/contents/${id}/review`, { method: 'POST', body: JSON.stringify(data) });

  nlQuery = (data: any) => this.request('/data-analytics/query', { method: 'POST', body: JSON.stringify(data) });
  recommendChart = (data: any) => this.request('/data-analytics/chart-recommend', { method: 'POST', body: JSON.stringify(data) });
  getAnomalies = (industryCode: string) => this.request(`/data-analytics/anomaly-detect?industryCode=${industryCode}`, { method: 'POST' });
  predictTrend = (data: any) => this.request('/data-analytics/trend-predict', { method: 'POST', body: JSON.stringify(data) });
  getDashboard = (industryCode: string) => this.request(`/data-analytics/dashboard/stats?industryCode=${industryCode}`);

  listIndustries = () => this.request('/industry-scene/industries');
  getIndustryDetail = (code: string) => this.request(`/industry-scene/industries/${code}`);
  getIndustryCapabilities = (code: string) => this.request(`/industry-scene/industries/${code}/capabilities`);
  getIndustryDashboard = (code: string) => this.request(`/industry-scene/industries/${code}/dashboard`);

  deploy = (data: any) => this.request('/deployment/docker/deploy', { method: 'POST', body: JSON.stringify(data) });
  listDeployments = () => this.request('/deployment/deployments');
  healthCheck = (id: string) => this.request(`/deployment/health`);
  rollback = (id: string) => this.request('/deployment/rollback', { method: 'POST', body: JSON.stringify({ deployment_id: id }) });
}

export const aiApi = new AiApiService();
