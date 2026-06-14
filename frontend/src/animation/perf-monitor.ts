import { ANIM_CONFIG } from '../config/animation';

type DegradeLevel = 'none' | 'minimal' | 'full';

class PerfMonitor {
  private fps = 60;
  private frameCount = 0;
  private lastTime = performance.now();
  private animFrameId: number | null = null;
  private lowFpsStart = 0;
  private highFpsStart = 0;
  private degradeLevel: DegradeLevel = 'none';
  private onDegradeCallbacks: Array<(level: DegradeLevel) => void> = [];
  private onRecoverCallbacks: Array<() => void> = [];
  private reducedMotion = false;

  constructor() {
    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (this.reducedMotion) {
      this.degradeLevel = 'full';
    }

    window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
      this.reducedMotion = e.matches;
      if (e.matches) {
        this.degradeLevel = 'full';
        this.notifyDegrade('full');
      } else {
        this.degradeLevel = 'none';
        this.notifyRecover();
      }
    });
  }

  start(): void {
    if (this.animFrameId !== null) return;
    this.lastTime = performance.now();
    this.frameCount = 0;

    const tick = () => {
      this.frameCount++;
      const now = performance.now();
      const elapsed = now - this.lastTime;

      if (elapsed >= 1000) {
        this.fps = Math.round((this.frameCount * 1000) / elapsed);
        this.frameCount = 0;
        this.lastTime = now;
        this.checkFps();
      }

      this.animFrameId = requestAnimationFrame(tick);
    };

    this.animFrameId = requestAnimationFrame(tick);
  }

  stop(): void {
    if (this.animFrameId !== null) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }

  private checkFps(): void {
    if (this.reducedMotion) return;

    const now = Date.now();

    if (this.fps < ANIM_CONFIG.perf.fpsThreshold) {
      if (this.lowFpsStart === 0) {
        this.lowFpsStart = now;
      } else if (now - this.lowFpsStart >= ANIM_CONFIG.perf.degradeDuration) {
        if (this.degradeLevel !== 'minimal') {
          this.degradeLevel = 'minimal';
          this.notifyDegrade('minimal');
        }
      }
      this.highFpsStart = 0;
    } else if (this.fps >= ANIM_CONFIG.perf.recoverThreshold) {
      if (this.highFpsStart === 0) {
        this.highFpsStart = now;
      } else if (now - this.highFpsStart >= ANIM_CONFIG.perf.recoverDuration) {
        if (this.degradeLevel !== 'none') {
          this.degradeLevel = 'none';
          this.notifyRecover();
        }
        this.lowFpsStart = 0;
        this.highFpsStart = 0;
      }
    }
  }

  private notifyDegrade(level: DegradeLevel): void {
    this.onDegradeCallbacks.forEach(cb => cb(level));
  }

  private notifyRecover(): void {
    this.onRecoverCallbacks.forEach(cb => cb());
  }

  onDegrade(callback: (level: DegradeLevel) => void): void {
    this.onDegradeCallbacks.push(callback);
  }

  onRecover(callback: () => void): void {
    this.onRecoverCallbacks.push(callback);
  }

  getFPS(): number {
    return this.fps;
  }

  shouldDegrade(): boolean {
    return this.degradeLevel !== 'none';
  }

  getDegradeLevel(): DegradeLevel {
    return this.degradeLevel;
  }

  isReducedMotionPreferred(): boolean {
    return this.reducedMotion;
  }
}

export const perfMonitor = new PerfMonitor();
export default PerfMonitor;
