import apiClient from './api';
import type {
  AnalysisResultItem,
  AnalysisStats,
  AnalysisTypeStats,
  DeepAnalysisRequestType,
  DeepAnalysisResultType,
  SchedulerStatus,
  TriggerAnalysisResponse,
} from '../types';

export async function getResults(params?: {
  limit?: number;
  offset?: number;
  analysis_type?: string;
  status?: string;
  target_id?: string;
  sort_by?: string;
  sort_order?: string;
}): Promise<{ items: AnalysisResultItem[]; total: number; limit: number; offset: number }> {
  const { data } = await apiClient.get('/analysis/results', { params });
  return data;
}

export async function getResultDetail(id: string): Promise<AnalysisResultItem> {
  const { data } = await apiClient.get(`/analysis/results/${id}`);
  return data;
}

export async function getStats(): Promise<AnalysisStats> {
  const { data } = await apiClient.get('/analysis/stats');
  return data;
}

export async function getTypeStats(type: string): Promise<AnalysisTypeStats> {
  const { data } = await apiClient.get(`/analysis/stats/${type}`);
  return data;
}

export async function triggerDeepAnalysis(request: DeepAnalysisRequestType): Promise<TriggerAnalysisResponse> {
  const { data } = await apiClient.post('/analysis/trigger', { deep_analysis: request });
  return data;
}

export async function triggerAnalysis(params: {
  analysis_type?: string;
  target_id?: string;
}): Promise<TriggerAnalysisResponse> {
  const { data } = await apiClient.post('/analysis/trigger', params);
  return data;
}

export async function getTaskStatus(taskId: string): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get(`/analysis/tasks/${taskId}`);
  return data;
}

export async function getSchedulerStatus(): Promise<SchedulerStatus> {
  const { data } = await apiClient.get('/analysis/scheduler/status');
  return data;
}
