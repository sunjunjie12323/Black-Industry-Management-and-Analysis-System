import { useState, useEffect, useCallback } from 'react';
import * as analysisApi from '../services/analysisApi';
import type {
  AnalysisTypeStats,
  AnalysisResultItem,
  DeepAnalysisRequestType,
  DeepAnalysisResultType,
} from '../types';

export function useAnalysisData(type: string, options?: { autoRefreshMs?: number }) {
  const [stats, setStats] = useState<AnalysisTypeStats | null>(null);
  const [results, setResults] = useState<AnalysisResultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [typeStats, resultsData] = await Promise.all([
        analysisApi.getTypeStats(type).catch(() => null),
        analysisApi.getResults({ analysis_type: type, limit: 20, sort_by: 'analyzed_at', sort_order: 'desc' }).catch(() => ({ items: [] as AnalysisResultItem[], total: 0, limit: 20, offset: 0 })),
      ]);
      setStats(typeStats);
      setResults(resultsData.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : '数据加载失败');
    } finally {
      setLoading(false);
    }
  }, [type]);

  useEffect(() => {
    refresh();
    const interval = options?.autoRefreshMs ?? 300000;
    const timer = setInterval(refresh, interval);
    return () => clearInterval(timer);
  }, [refresh, options?.autoRefreshMs]);

  return { stats, results, loading, error, refresh };
}

export function useDeepAnalysis() {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<DeepAnalysisResultType | null>(null);

  const trigger = useCallback(async (request: DeepAnalysisRequestType) => {
    setAnalyzing(true);
    setResult(null);
    try {
      const resp = await analysisApi.triggerDeepAnalysis(request);
      const taskId = resp.task_id;
      let attempts = 0;
      while (attempts < 60) {
        await new Promise((r) => setTimeout(r, 2000));
        const status = await analysisApi.getTaskStatus(taskId);
        if (status.status === 'completed') {
          setResult(status.result as DeepAnalysisResultType);
          setAnalyzing(false);
          return;
        }
        if (status.status === 'failed') {
          throw new Error((status.error as string) || '深度分析失败');
        }
        attempts++;
      }
      throw new Error('深度分析超时');
    } catch (err) {
      setAnalyzing(false);
      throw err;
    }
  }, []);

  return { analyzing, result, trigger };
}
