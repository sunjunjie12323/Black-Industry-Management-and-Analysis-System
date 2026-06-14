export const THREAT_COLORS: Record<string, string> = {
  critical: '#cf1322',
  high: '#fa541c',
  medium: '#fa8c16',
  low: '#52c41a',
  info: '#1890ff',
};

export const THREAT_LEVEL_CONFIG: Record<string, { color: string; label: string }> = {
  critical: { color: THREAT_COLORS.critical, label: '严重' },
  high: { color: THREAT_COLORS.high, label: '高危' },
  medium: { color: THREAT_COLORS.medium, label: '中危' },
  low: { color: THREAT_COLORS.low, label: '低危' },
  info: { color: THREAT_COLORS.info, label: '信息' },
};

export function formatTime(isoString: string | null | undefined): string {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMinutes < 1) return '刚刚';
    if (diffMinutes < 60) return `${diffMinutes}分钟前`;
    if (diffHours < 24) return `${diffHours}小时前`;
    if (diffDays < 30) return `${diffDays}天前`;
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${year}年${month}月${day}日 ${hours}:${minutes}`;
  } catch {
    return '—';
  }
}

export function formatTimeFull(isoString: string | null | undefined): string {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${year}年${month}月${day}日 ${hours}:${minutes}`;
  } catch {
    return '—';
  }
}
