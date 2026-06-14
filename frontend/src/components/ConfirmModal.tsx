import React from 'react';
import { Modal, Button } from 'antd';
import { ExclamationCircleOutlined, DeleteOutlined } from '@ant-design/icons';

interface ConfirmModalProps {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  title?: string;
  description?: string;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  loading?: boolean;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  open, onConfirm, onCancel,
  title = '确认操作', description = '此操作不可撤销，请确认是否继续？',
  confirmText = '确认', cancelText = '取消',
  danger = false, loading = false,
}) => (
  <Modal
    open={open}
    onCancel={onCancel}
    footer={null}
    width={420}
    styles={{ body: { padding: 0 }, header: { display: 'none' } }}
    centered
  >
    <div style={{ padding: '28px 28px 20px', textAlign: 'center' }}>
      <div style={{
        width: 56, height: 56, borderRadius: 16, margin: '0 auto 16px',
        background: danger ? 'rgba(185,28,28,0.08)' : 'rgba(30,64,175,0.08)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        {danger ? <DeleteOutlined style={{ fontSize: 24, color: '#B91C1C' }} /> : <ExclamationCircleOutlined style={{ fontSize: 24, color: '#1E40AF' }} />}
      </div>
      <h3 style={{ fontSize: 17, fontWeight: 700, color: '#0C0E12', margin: '0 0 8px', fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{title}</h3>
      <p style={{ fontSize: 13, color: '#6B7280', margin: 0, lineHeight: 1.6 }}>{description}</p>
    </div>
    <div style={{ display: 'flex', gap: 10, padding: '0 28px 24px', justifyContent: 'center' }}>
      <Button onClick={onCancel} style={{ borderRadius: 10, height: 40, minWidth: 100, fontWeight: 500 }}>{cancelText}</Button>
      <Button
        type="primary"
        danger={danger}
        loading={loading}
        onClick={onConfirm}
        style={{
          borderRadius: 10, height: 40, minWidth: 100, fontWeight: 600,
          boxShadow: danger ? '0 4px 12px rgba(185,28,28,0.25)' : '0 4px 12px rgba(30,64,175,0.25)',
        }}
      >{confirmText}</Button>
    </div>
  </Modal>
);

export default ConfirmModal;
