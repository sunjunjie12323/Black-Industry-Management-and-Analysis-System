import React, { useRef, useEffect, useState } from 'react';
import { Table } from 'antd';
import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

interface IEnhancedTableProps {
  dataSource: Record<string, unknown>[];
  columns: Record<string, unknown>[];
  loading?: boolean;
  animateRows?: boolean;
  refreshedRowKeys?: Set<string>;
  onRowClick?: (record: Record<string, unknown>) => void;
  rowKey?: string;
  pagination?: false | Record<string, unknown>;
  scroll?: Record<string, unknown>;
}

const EnhancedTable: React.FC<IEnhancedTableProps> = ({
  dataSource,
  columns,
  loading = false,
  animateRows = true,
  refreshedRowKeys,
  onRowClick,
  rowKey = 'id',
  pagination,
  scroll,
}) => {
  const tableRef = useRef<HTMLDivElement>(null);
  const [prevLen, setPrevLen] = useState(0);

  useGSAP(() => {
    if (!animateRows || !tableRef.current || loading) return;
    if (dataSource.length === prevLen) return;
    setPrevLen(dataSource.length);

    const rows = tableRef.current.querySelectorAll('.ant-table-tbody > tr');
    if (rows.length === 0) return;

    gsap.fromTo(rows,
      { opacity: 0, y: 8 },
      {
        opacity: 1,
        y: 0,
        duration: ANIM_CONFIG.listRow.fadeInDuration,
        stagger: ANIM_CONFIG.listRow.staggerDelay,
        ease: 'power2.out',
      }
    );
  }, { scope: tableRef, dependencies: [dataSource, loading] });

  useEffect(() => {
    if (!refreshedRowKeys || !tableRef.current) return;
    const rows = tableRef.current.querySelectorAll('.ant-table-tbody > tr');
    rows.forEach((row) => {
      const keyAttr = row.getAttribute('data-row-key');
      if (keyAttr && refreshedRowKeys.has(keyAttr)) {
        gsap.fromTo(row,
          { background: 'rgba(30,64,175,0.08)' },
          {
            background: 'transparent',
            duration: 1.2,
            ease: 'power2.out',
          }
        );
      }
    });
  }, [refreshedRowKeys]);

  return (
    <div ref={tableRef} style={{ position: 'relative' }}>
      <Table
        dataSource={dataSource}
        columns={columns as any}
        loading={loading}
        rowKey={rowKey}
        pagination={pagination}
        scroll={scroll}
        onRow={onRowClick ? (record) => ({
          onClick: () => onRowClick(record),
          style: { cursor: 'pointer' },
        }) : undefined}
      />
      <style>{`
        .ant-table-tbody > tr:nth-child(odd) > td {
          background: var(--bg-subtle, #F3F4F6) !important;
        }
        .ant-table-tbody > tr:hover > td {
          background: linear-gradient(90deg, rgba(30,64,175,0.04), transparent) !important;
        }
        .ant-pagination-item {
          border-radius: var(--radius-xs, 8px);
        }
      `}</style>
    </div>
  );
};

export default EnhancedTable;
