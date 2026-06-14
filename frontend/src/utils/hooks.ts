import { useState, useEffect, useRef, useCallback } from 'react';
import { App } from 'antd';
import { getErrorMessage } from '../services/api';

export function useAntdMessage() {
  const { message } = App.useApp();
  return message;
}

export function useDebounce<T>(value: T, delay: number = 300): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debouncedValue;
}

export function useDebouncedCallback<T extends (...args: never[]) => unknown>(
  callback: T,
  delay: number = 300,
): T {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const debounced = useRef((...args: Parameters<T>) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      callbackRef.current(...args);
    }, delay);
  }).current;

  return debounced as T;
}

export function useResponsive() {
  const [isWide, setIsWide] = useState(() => typeof window !== 'undefined' && window.innerWidth >= 1280);
  useEffect(() => {
    const handler = () => setIsWide(window.innerWidth >= 1280);
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }, []);
  return { isWide, isNarrow: !isWide };
}

export function useApiCall<T = unknown>() {
  const message = useAntdMessage();
  const [loading, setLoading] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => { mountedRef.current = false; };
  }, []);

  const execute = useCallback(async (
    apiFn: () => Promise<T>,
    options?: {
      onSuccess?: (data: T) => void;
      onError?: (error: unknown) => void;
      successMsg?: string;
      errorMsg?: string;
      showLoading?: boolean;
      throwError?: boolean;
    },
  ): Promise<T | null> => {
    const {
      onSuccess,
      onError,
      successMsg,
      errorMsg,
      showLoading = true,
      throwError = false,
    } = options || {};

    if (showLoading) setLoading(true);
    try {
      const result = await apiFn();
      if (!mountedRef.current) return result;
      if (successMsg) message.success(successMsg);
      onSuccess?.(result);
      return result;
    } catch (err) {
      if (!mountedRef.current) return null;
      const msg = errorMsg || getErrorMessage(err);
      message.error(msg);
      onError?.(err);
      if (throwError) throw err;
      return null;
    } finally {
      if (mountedRef.current && showLoading) setLoading(false);
    }
  }, [message]);

  return { loading, execute };
}

export function useFetchData<T>(
  fetchFn: () => Promise<T>,
  deps: React.DependencyList = [],
  options?: {
    initialData?: T;
    onError?: (error: unknown) => void;
  },
) {
  const [data, setData] = useState<T | undefined>(options?.initialData);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const mountedRef = useRef(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchFn();
      if (mountedRef.current) setData(result);
    } catch (err) {
      if (mountedRef.current) {
        setError(err);
        options?.onError?.(err);
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mountedRef.current = true;
    refresh();
    return () => { mountedRef.current = false; };
  }, [refresh]);

  return { data, loading, error, refresh, setData };
}
