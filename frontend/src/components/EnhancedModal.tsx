import React, { useRef, useEffect } from 'react';
import { Modal } from 'antd';
import gsap from 'gsap';
import { ANIM_CONFIG } from '../config/animation';

interface IEnhancedModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  animated?: boolean;
  width?: number;
  footer?: React.ReactNode;
}

const EnhancedModal: React.FC<IEnhancedModalProps> = ({
  open, onClose, title, children,
  animated = true, width = 520, footer,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const prevOpen = useRef(false);

  useEffect(() => {
    if (!animated) return;

    const modalEl = document.querySelector('.ant-modal-content') as HTMLElement;
    const maskEl = document.querySelector('.ant-modal-mask') as HTMLElement;

    if (open && !prevOpen.current) {
      prevOpen.current = true;
      if (modalEl) {
        gsap.fromTo(modalEl,
          { scale: ANIM_CONFIG.modal.enterScale, opacity: 0 },
          { scale: 1, opacity: 1, duration: ANIM_CONFIG.modal.duration, ease: ANIM_CONFIG.modal.ease }
        );
      }
      if (maskEl) {
        gsap.fromTo(maskEl,
          { opacity: 0 },
          { opacity: 1, duration: 0.2 }
        );
      }
    } else if (!open && prevOpen.current) {
      prevOpen.current = false;
      if (modalEl) {
        gsap.to(modalEl, {
          scale: ANIM_CONFIG.modal.enterScale,
          opacity: 0,
          duration: 0.2,
          ease: 'power2.in',
        });
      }
    }
  }, [open, animated]);

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={title}
      width={width}
      footer={footer}
      centered
      destroyOnHidden
    >
      {children}
    </Modal>
  );
};

export default EnhancedModal;
