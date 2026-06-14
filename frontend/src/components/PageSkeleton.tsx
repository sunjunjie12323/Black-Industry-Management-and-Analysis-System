import React from 'react';

const shimmerStyle: React.CSSProperties = {
  background: 'linear-gradient(90deg, #1C1F35 25%, #252845 50%, #1C1F35 75%)',
  backgroundSize: '200% 100%',
  animation: 'skeleton-shimmer 1.5s ease-in-out infinite',
  borderRadius: 8,
};

const StatCardSkeleton: React.FC = () => (
  <div style={{ padding: '14px 16px', background: '#141625', borderRadius: 12, border: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 12 }}>
    <div style={{ width: 36, height: 36, borderRadius: 9, ...shimmerStyle }} />
    <div style={{ flex: 1 }}>
      <div style={{ width: 48, height: 11, marginBottom: 6, ...shimmerStyle }} />
      <div style={{ width: 64, height: 20, ...shimmerStyle }} />
    </div>
  </div>
);

const TableRowSkeleton: React.FC<{ cols?: number }> = ({ cols = 5 }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '12px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
    {Array.from({ length: cols }).map((_, i) => (
      <div key={i} style={{ flex: i === 0 ? 2 : 1, height: 14, ...shimmerStyle }} />
    ))}
  </div>
);

const TableSkeleton: React.FC<{ rows?: number; cols?: number }> = ({ rows = 6, cols = 5 }) => (
  <div style={{ background: '#141625', borderRadius: 14, border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}>
    <div style={{ padding: '12px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 16 }}>
      {Array.from({ length: cols }).map((_, i) => (
        <div key={i} style={{ flex: i === 0 ? 2 : 1, height: 12, ...shimmerStyle }} />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, i) => (
      <TableRowSkeleton key={i} cols={cols} />
    ))}
  </div>
);

const DetailSkeleton: React.FC = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 8 }}>
    <div style={{ height: 24, width: '60%', ...shimmerStyle }} />
    <div style={{ height: 16, width: '100%', ...shimmerStyle }} />
    <div style={{ height: 16, width: '85%', ...shimmerStyle }} />
    <div style={{ height: 16, width: '70%', ...shimmerStyle }} />
    <div style={{ height: 120, width: '100%', ...shimmerStyle }} />
  </div>
);

const SidebarSkeleton: React.FC = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
    <div style={{ padding: 18, background: '#141625', borderRadius: 14, border: '1px solid rgba(255,255,255,0.06)' }}>
      <div style={{ height: 14, width: '40%', marginBottom: 14, ...shimmerStyle }} />
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{ height: 6, width: 48, ...shimmerStyle }} />
          <div style={{ flex: 1, height: 6, ...shimmerStyle }} />
          <div style={{ height: 13, width: 24, ...shimmerStyle }} />
        </div>
      ))}
    </div>
    <div style={{ padding: 18, background: '#141625', borderRadius: 14, border: '1px solid rgba(255,255,255,0.06)' }}>
      <div style={{ height: 14, width: '50%', marginBottom: 12, ...shimmerStyle }} />
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' }}>
          <div style={{ width: 26, height: 26, borderRadius: 6, ...shimmerStyle }} />
          <div style={{ flex: 1 }}>
            <div style={{ height: 12, width: '80%', marginBottom: 4, ...shimmerStyle }} />
            <div style={{ height: 10, width: '40%', ...shimmerStyle }} />
          </div>
        </div>
      ))}
    </div>
  </div>
);

export const DashboardSkeleton: React.FC = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
      {Array.from({ length: 4 }).map((_, i) => <StatCardSkeleton key={i} />)}
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
      <TableSkeleton rows={8} cols={4} />
      <TableSkeleton rows={8} cols={3} />
    </div>
  </div>
);

export const TablePageSkeleton: React.FC<{ stats?: number; cols?: number; rows?: number; sidebar?: boolean }> = ({ stats = 4, cols = 5, rows = 6, sidebar = true }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${stats}, 1fr)`, gap: 12 }}>
      {Array.from({ length: stats }).map((_, i) => <StatCardSkeleton key={i} />)}
    </div>
    {sidebar ? (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 14 }}>
        <TableSkeleton rows={rows} cols={cols} />
        <SidebarSkeleton />
      </div>
    ) : (
      <TableSkeleton rows={rows} cols={cols} />
    )}
  </div>
);

export const AnalysisPageSkeleton: React.FC<{ modes?: number }> = ({ modes = 3 }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${modes}, 1fr)`, gap: 10 }}>
      {Array.from({ length: modes }).map((_, i) => (
        <div key={i} style={{ padding: 16, background: '#141625', borderRadius: 12, border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ height: 14, width: '60%', marginBottom: 8, ...shimmerStyle }} />
          <div style={{ height: 12, width: '80%', ...shimmerStyle }} />
        </div>
      ))}
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14 }}>
      <div style={{ padding: 20, background: '#141625', borderRadius: 14, border: '1px solid rgba(255,255,255,0.06)' }}>
        <DetailSkeleton />
      </div>
      <SidebarSkeleton />
    </div>
  </div>
);

export const ModalSkeleton: React.FC = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 8 }}>
    <div style={{ height: 20, width: '50%', ...shimmerStyle }} />
    <div style={{ height: 44, width: '100%', ...shimmerStyle }} />
    <div style={{ height: 44, width: '100%', ...shimmerStyle }} />
    <div style={{ height: 80, width: '100%', ...shimmerStyle }} />
  </div>
);

export { StatCardSkeleton, TableSkeleton, DetailSkeleton, SidebarSkeleton };
