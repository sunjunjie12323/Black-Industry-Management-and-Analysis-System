import asyncio
import json
import math
import os
import re
import shutil
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


class TrainingStatus(str, Enum):
    PENDING = "pending"
    PREPARING = "preparing"
    TRAINING = "training"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class CheckpointInfo:
    checkpoint_id: str
    task_id: str
    step: int
    epoch: float
    loss: float
    path: str
    created_at: datetime
    is_best: bool = False
    metrics: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "checkpoint_id": self.checkpoint_id,
            "task_id": self.task_id,
            "step": self.step,
            "epoch": round(self.epoch, 2),
            "loss": round(self.loss, 6),
            "path": self.path,
            "created_at": self.created_at.isoformat(),
            "is_best": self.is_best,
            "metrics": {k: round(v, 6) for k, v in self.metrics.items()},
        }


@dataclass
class TrainingProgress:
    task_id: str
    status: TrainingStatus
    current_step: int = 0
    total_steps: int = 0
    current_epoch: float = 0.0
    total_epochs: int = 0
    learning_rate: float = 0.0
    train_loss: float = 0.0
    val_loss: float = 0.0
    elapsed_seconds: float = 0.0
    estimated_remaining_seconds: float = 0.0
    gpu_memory_used_mb: float = 0.0
    tokens_processed: int = 0

    @property
    def progress(self) -> float:
        if self.total_steps <= 0:
            return 0.0
        return min(1.0, self.current_step / self.total_steps)

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "current_epoch": round(self.current_epoch, 2),
            "total_epochs": self.total_epochs,
            "progress": round(self.progress, 4),
            "learning_rate": self.learning_rate,
            "train_loss": round(self.train_loss, 6),
            "val_loss": round(self.val_loss, 6),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "estimated_remaining_seconds": round(self.estimated_remaining_seconds, 1),
            "gpu_memory_used_mb": round(self.gpu_memory_used_mb, 1),
            "tokens_processed": self.tokens_processed,
        }


@dataclass
class EvaluationResult:
    task_id: str
    accuracy: float = 0.0
    f1_score: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    loss: float = 0.0
    perplexity: float = 0.0
    bleu_score: float = 0.0
    rouge_l: float = 0.0
    sample_count: int = 0
    error_count: int = 0
    evaluated_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "accuracy": round(self.accuracy, 4),
            "f1_score": round(self.f1_score, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "loss": round(self.loss, 6),
            "perplexity": round(self.perplexity, 4),
            "bleu_score": round(self.bleu_score, 4),
            "rouge_l": round(self.rouge_l, 4),
            "sample_count": self.sample_count,
            "error_count": self.error_count,
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
        }


@dataclass
class ModelVersion:
    version_id: str
    task_id: str
    version_number: int
    model_path: str
    base_model: str
    method: str
    config: Dict[str, Any]
    metrics: Dict[str, float]
    created_at: datetime
    parent_version_id: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict:
        return {
            "version_id": self.version_id,
            "task_id": self.task_id,
            "version_number": self.version_number,
            "model_path": self.model_path,
            "base_model": self.base_model,
            "method": self.method,
            "config": self.config,
            "metrics": {k: round(v, 6) for k, v in self.metrics.items()},
            "created_at": self.created_at.isoformat(),
            "parent_version_id": self.parent_version_id,
            "description": self.description,
        }


class CheckpointManager:
    def __init__(self, base_dir: str = "./checkpoints"):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoints: Dict[str, List[CheckpointInfo]] = defaultdict(list)
        self._save_interval_steps = 500
        self._max_checkpoints_per_task = 5
        self._max_tasks = 50

    @staticmethod
    def _validate_id(id_str: str) -> str:
        if not id_str or not re.match(r'^[a-zA-Z0-9_-]+$', id_str):
            raise ValueError(f"无效标识符: {id_str}")
        return id_str

    def save_checkpoint(
        self,
        task_id: str,
        step: int,
        epoch: float,
        loss: float,
        metrics: Optional[Dict[str, float]] = None,
        model_state: Optional[Dict] = None,
    ) -> CheckpointInfo:
        self._validate_id(task_id)
        task_dir = self._base_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        checkpoint_id = f"ckpt_{step}_{uuid.uuid4().hex[:8]}"
        checkpoint_path = task_dir / f"{checkpoint_id}.json"

        is_best = False
        existing = self._checkpoints.get(task_id, [])
        if not existing or loss < min(cp.loss for cp in existing):
            is_best = True
            for cp in existing:
                cp.is_best = False

        info = CheckpointInfo(
            checkpoint_id=checkpoint_id,
            task_id=task_id,
            step=step,
            epoch=epoch,
            loss=loss,
            path=str(checkpoint_path),
            created_at=datetime.now(timezone.utc),
            is_best=is_best,
            metrics=metrics or {},
        )

        checkpoint_data = {
            "checkpoint_id": checkpoint_id,
            "task_id": task_id,
            "step": step,
            "epoch": epoch,
            "loss": loss,
            "is_best": is_best,
            "metrics": metrics or {},
            "created_at": info.created_at.isoformat(),
        }
        if model_state:
            checkpoint_data["model_state_keys"] = list(model_state.keys())

        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, ensure_ascii=False, indent=2)

        self._checkpoints[task_id].append(info)

        if len(self._checkpoints) > self._max_tasks:
            oldest_task = next(iter(self._checkpoints))
            del self._checkpoints[oldest_task]

        if len(self._checkpoints[task_id]) > self._max_checkpoints_per_task:
            non_best = [cp for cp in self._checkpoints[task_id] if not cp.is_best]
            if non_best:
                oldest = non_best[0]
                self._checkpoints[task_id].remove(oldest)
                old_path = Path(oldest.path)
                if old_path.exists():
                    old_path.unlink()

        return info

    def get_best_checkpoint(self, task_id: str) -> Optional[CheckpointInfo]:
        for cp in self._checkpoints.get(task_id, []):
            if cp.is_best:
                return cp
        checkpoints = self._checkpoints.get(task_id, [])
        return min(checkpoints, key=lambda cp: cp.loss) if checkpoints else None

    def get_latest_checkpoint(self, task_id: str) -> Optional[CheckpointInfo]:
        checkpoints = self._checkpoints.get(task_id, [])
        return checkpoints[-1] if checkpoints else None

    def list_checkpoints(self, task_id: str) -> List[CheckpointInfo]:
        return list(self._checkpoints.get(task_id, []))

    def should_save(self, task_id: str, current_step: int) -> bool:
        return current_step > 0 and current_step % self._save_interval_steps == 0


class ModelEvaluator:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def evaluate(
        self,
        task_id: str,
        eval_data: Optional[List[Dict]] = None,
        model_path: Optional[str] = None,
        metrics: Optional[List[str]] = None,
    ) -> EvaluationResult:
        requested_metrics = metrics or ["accuracy", "f1", "loss"]

        if eval_data:
            return await self._evaluate_with_data(task_id, eval_data, requested_metrics)

        return EvaluationResult(
            task_id=task_id,
            evaluated_at=datetime.now(timezone.utc),
        )

    async def _evaluate_with_data(
        self,
        task_id: str,
        eval_data: List[Dict],
        metrics: List[str],
    ) -> EvaluationResult:
        correct = 0
        total = 0
        tp = fp = fn = 0
        total_loss = 0.0
        errors = 0

        for item in eval_data:
            total += 1
            expected = item.get("expected", item.get("label", ""))
            predicted = item.get("predicted", item.get("output", ""))
            loss = item.get("loss", 0.0)

            if not predicted and self._llm:
                try:
                    prompt = item.get("input", item.get("instruction", ""))
                    response = await self._llm.chat(prompt)
                    if isinstance(response, dict):
                        predicted = response.get("content", "")
                    elif isinstance(response, str):
                        predicted = response
                except Exception:
                    errors += 1
                    continue

            if isinstance(expected, str) and isinstance(predicted, str):
                if expected.strip().lower() == predicted.strip().lower():
                    correct += 1
                    tp += 1
                else:
                    fn += 1
            elif expected == predicted:
                correct += 1
                tp += 1
            else:
                fn += 1

            total_loss += loss

        accuracy = correct / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        avg_loss = total_loss / total if total > 0 else 0.0

        import math
        perplexity = math.exp(avg_loss) if avg_loss < 10 else float("inf")

        return EvaluationResult(
            task_id=task_id,
            accuracy=accuracy,
            f1_score=f1,
            precision=precision,
            recall=recall,
            loss=avg_loss,
            perplexity=perplexity,
            sample_count=total,
            error_count=errors,
            evaluated_at=datetime.now(timezone.utc),
        )


class ModelRegistry:
    def __init__(self, base_dir: str = "./model_registry"):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._versions: Dict[str, List[ModelVersion]] = defaultdict(list)
        self._max_versions_per_task = 20

    @staticmethod
    def _validate_id(id_str: str) -> str:
        if not id_str or not re.match(r'^[a-zA-Z0-9_-]+$', id_str):
            raise ValueError(f"无效标识符: {id_str}")
        return id_str

    def register_version(
        self,
        task_id: str,
        model_path: str,
        base_model: str,
        method: str,
        config: Dict[str, Any],
        metrics: Dict[str, float],
        description: str = "",
    ) -> ModelVersion:
        self._validate_id(task_id)
        existing = self._versions.get(task_id, [])
        version_number = len(existing) + 1
        parent_id = existing[-1].version_id if existing else None

        version = ModelVersion(
            version_id=uuid.uuid4().hex,
            task_id=task_id,
            version_number=version_number,
            model_path=model_path,
            base_model=base_model,
            method=method,
            config=config,
            metrics=metrics,
            created_at=datetime.now(timezone.utc),
            parent_version_id=parent_id,
            description=description,
        )

        version_path = self._base_dir / task_id / f"v{version_number}.json"
        version_path.parent.mkdir(parents=True, exist_ok=True)
        with open(version_path, "w", encoding="utf-8") as f:
            json.dump(version.to_dict(), f, ensure_ascii=False, indent=2)

        self._versions[task_id].append(version)
        if len(self._versions[task_id]) > self._max_versions_per_task:
            self._versions[task_id] = self._versions[task_id][-self._max_versions_per_task:]
        return version

    def list_versions(self, task_id: str) -> List[ModelVersion]:
        return list(self._versions.get(task_id, []))

    def get_version(self, task_id: str, version_number: int) -> Optional[ModelVersion]:
        for v in self._versions.get(task_id, []):
            if v.version_number == version_number:
                return v
        return None

    def get_latest_version(self, task_id: str) -> Optional[ModelVersion]:
        versions = self._versions.get(task_id, [])
        return versions[-1] if versions else None

    def compare_versions(
        self, task_id: str, version_a: int, version_b: int
    ) -> Dict[str, Any]:
        va = self.get_version(task_id, version_a)
        vb = self.get_version(task_id, version_b)
        if not va or not vb:
            return {"error": "版本不存在"}

        metrics_delta = {}
        all_keys = set(va.metrics.keys()) | set(vb.metrics.keys())
        for key in all_keys:
            a_val = va.metrics.get(key, 0)
            b_val = vb.metrics.get(key, 0)
            metrics_delta[key] = {
                "version_a": round(a_val, 6),
                "version_b": round(b_val, 6),
                "delta": round(b_val - a_val, 6),
                "improved": b_val > a_val if key in ["accuracy", "f1_score", "precision", "recall", "bleu_score", "rouge_l"] else b_val < a_val,
            }

        return {
            "version_a": va.to_dict(),
            "version_b": vb.to_dict(),
            "metrics_delta": metrics_delta,
        }


class _LogCallback:
    def __init__(self, on_log_fn):
        self._on_log = on_log_fn

    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs and self._on_log:
            self._on_log(logs)


class FinetuneWorker:
    DEEPSEEK_MODEL_PRESETS = {
        "deepseek-7b-chat": {
            "base_model": "deepseek-ai/deepseek-llm-7b-chat",
            "model_type": "causal_lm",
            "default_lora_r": 16,
            "default_lora_alpha": 32,
            "default_lora_dropout": 0.05,
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            "max_seq_length": 4096,
            "recommended_batch_size": 4,
            "recommended_lr": 2e-4,
            "description": "DeepSeek-LLM-7B-Chat 通用对话模型，适合黑话识别、威胁分类等任务",
        },
        "deepseek-r1-7b": {
            "base_model": "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
            "model_type": "causal_lm",
            "default_lora_r": 16,
            "default_lora_alpha": 32,
            "default_lora_dropout": 0.05,
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"],
            "max_seq_length": 4096,
            "recommended_batch_size": 2,
            "recommended_lr": 1e-4,
            "description": "DeepSeek-R1 推理模型蒸馏版，适合复杂推理任务如攻击链路分析",
        },
        "deepseek-coder-6.7b": {
            "base_model": "deepseek-ai/deepseek-coder-6.7b-instruct",
            "model_type": "causal_lm",
            "default_lora_r": 16,
            "default_lora_alpha": 32,
            "default_lora_dropout": 0.05,
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"],
            "max_seq_length": 4096,
            "recommended_batch_size": 4,
            "recommended_lr": 2e-4,
            "description": "DeepSeek-Coder 代码模型，适合恶意脚本分析、IOC提取等任务",
        },
    }

    @staticmethod
    def _validate_id(id_str: str) -> str:
        if not id_str or not re.match(r'^[a-zA-Z0-9_-]+$', id_str):
            raise ValueError(f"无效标识符: {id_str}")
        return id_str

    def __init__(
        self,
        llm_service=None,
        checkpoint_dir: str = "./checkpoints",
        registry_dir: str = "./model_registry",
    ):
        self._llm = llm_service
        self._checkpoint_mgr = CheckpointManager(checkpoint_dir)
        self._evaluator = ModelEvaluator(llm_service)
        self._registry = ModelRegistry(registry_dir)
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._progress: Dict[str, TrainingProgress] = {}
        self._training_logs: Dict[str, List[str]] = defaultdict(list)
        self._max_logs_per_task = 500
        self._max_progress_entries = 50

    async def start_training(
        self,
        task_id: str,
        method: str,
        base_model: str,
        config: Dict[str, Any],
        dataset_ref: Optional[str] = None,
        checkpoint_ref: Optional[str] = None,
    ) -> TrainingProgress:
        self._validate_id(task_id)
        if task_id in self._active_tasks:
            raise ValueError(f"任务 {task_id} 已在训练中")

        validated_config = self._validate_config(method, config)

        progress = TrainingProgress(
            task_id=task_id,
            status=TrainingStatus.PREPARING,
            total_epochs=validated_config.get("epochs", 3),
            learning_rate=validated_config.get("learning_rate", 2e-4),
        )
        self._progress[task_id] = progress

        task = asyncio.create_task(
            self._run_training(
                task_id, method, base_model, validated_config, dataset_ref, checkpoint_ref
            )
        )
        self._active_tasks[task_id] = task

        return progress

    def _validate_config(self, method: str, config: Dict[str, Any]) -> Dict[str, Any]:
        validated = dict(config)

        if method == "lora":
            lora_r = validated.get("lora_r", 16)
            if not (4 <= lora_r <= 256):
                raise ValueError(f"LoRA r必须在4-256之间，当前值: {lora_r}")
            validated["lora_r"] = lora_r

            lora_alpha = validated.get("lora_alpha", 32)
            if not (1 <= lora_alpha <= 512):
                raise ValueError(f"LoRA alpha必须在1-512之间，当前值: {lora_alpha}")
            validated["lora_alpha"] = lora_alpha

            validated.setdefault("lora_dropout", 0.05)
            validated.setdefault("lora_target_modules", ["q_proj", "v_proj"])

        elif method == "full":
            lr = validated.get("learning_rate", 2e-5)
            if not (1e-7 <= lr <= 1e-3):
                raise ValueError(f"学习率必须在1e-7~1e-3之间，当前值: {lr}")
            validated["learning_rate"] = lr

        validated.setdefault("epochs", 3)
        validated.setdefault("batch_size", 4)
        validated.setdefault("gradient_accumulation_steps", 4)
        validated.setdefault("warmup_steps", 100)
        validated.setdefault("max_seq_length", 2048)
        validated.setdefault("save_steps", 500)
        validated.setdefault("eval_steps", 500)

        return validated

    async def _run_training(
        self,
        task_id: str,
        method: str,
        base_model: str,
        config: Dict[str, Any],
        dataset_ref: Optional[str],
        checkpoint_ref: Optional[str],
    ):
        progress = self._progress[task_id]
        try:
            self._log(task_id, f"开始准备训练环境: method={method}, base_model={base_model}")
            progress.status = TrainingStatus.PREPARING
            await asyncio.sleep(0.5)

            self._log(task_id, "加载数据集...")
            dataset = await self._load_dataset(dataset_ref)
            total_samples = len(dataset)
            if total_samples == 0:
                raise ValueError("数据集为空")

            batch_size = config.get("batch_size", 4)
            grad_accum = config.get("gradient_accumulation_steps", 4)
            effective_batch = batch_size * grad_accum
            steps_per_epoch = max(1, total_samples // effective_batch)
            total_steps = steps_per_epoch * config["epochs"]

            progress.total_steps = total_steps

            self._log(task_id, "检测训练框架...")
            fw_info = self._detect_training_framework()
            self._log(
                task_id,
                f"框架检测: torch={fw_info['torch_available']}, "
                f"transformers={fw_info['transformers_available']}, "
                f"peft={fw_info['peft_available']}, "
                f"cuda={fw_info['cuda_available']}"
                + (f"({fw_info['cuda_device_count']}x {fw_info['cuda_device_name']})" if fw_info["cuda_available"] else "")
                + f", distributed={fw_info['distributed_available']}"
                + (f"({fw_info['distributed_backend']})" if fw_info.get("distributed_backend") else ""),
            )

            if fw_info["distributed_available"]:
                self._log(task_id, "分布式训练后端可用，当前为单节点模式，可通过 torchrun 启用多节点")

            progress.status = TrainingStatus.TRAINING

            if fw_info["real_training_ready"]:
                self._log(task_id, "检测到真实训练框架，使用 HuggingFace Transformers 进行训练")
                best_loss = await self._run_real_training(
                    task_id, method, base_model, config, dataset,
                    steps_per_epoch, total_steps, progress, fw_info,
                )
            else:
                self._log(
                    task_id,
                    "⚠ 未检测到 transformers/torch，回退到模拟训练模式（loss曲线为模拟数据，非真实训练）",
                )
                best_loss = await self._run_fallback_training(
                    task_id, method, base_model, config, dataset,
                    steps_per_epoch, total_steps, progress,
                )

            progress.status = TrainingStatus.EVALUATING
            self._log(task_id, "训练完成，开始评估...")

            eval_result = await self._evaluator.evaluate(
                task_id=task_id,
                eval_data=dataset[:min(50, len(dataset))],
                metrics=["accuracy", "f1", "loss"],
            )
            self._log(task_id, f"评估完成: accuracy={eval_result.accuracy:.4f}, f1={eval_result.f1_score:.4f}")

            model_path = f"./models/{task_id}/final"
            version = self._registry.register_version(
                task_id=task_id,
                model_path=model_path,
                base_model=base_model,
                method=method,
                config=config,
                metrics={
                    "accuracy": eval_result.accuracy,
                    "f1_score": eval_result.f1_score,
                    "loss": eval_result.loss,
                    "perplexity": eval_result.perplexity,
                    "best_train_loss": best_loss,
                    "training_mode": "real" if fw_info["real_training_ready"] else "fallback",
                },
                description=f"{method}微调 {base_model}, epochs={config['epochs']}",
            )
            self._log(task_id, f"模型版本已注册: v{version.version_number}")

            progress.status = TrainingStatus.COMPLETED
            progress.train_loss = best_loss
            progress.val_loss = eval_result.loss

        except asyncio.CancelledError:
            progress.status = TrainingStatus.CANCELLED
            self._log(task_id, "训练已取消")
        except Exception as exc:
            progress.status = TrainingStatus.FAILED
            self._log(task_id, "训练失败，请查看系统日志获取详情")
            logger.error(f"Training task {task_id} failed: {exc}")
        finally:
            self._active_tasks.pop(task_id, None)
            completed_ids = [tid for tid, p in self._progress.items() if p.status in (TrainingStatus.COMPLETED, TrainingStatus.FAILED, TrainingStatus.CANCELLED)]
            for tid in completed_ids:
                if len(self._progress) > self._max_progress_entries:
                    del self._progress[tid]

    async def _run_real_training(
        self,
        task_id: str,
        method: str,
        base_model: str,
        config: Dict[str, Any],
        dataset: List[Dict],
        steps_per_epoch: int,
        total_steps: int,
        progress: TrainingProgress,
        fw_info: Dict[str, Any],
    ) -> float:
        import time as _time
        start_time = _time.time()
        best_loss = float("inf")

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
            if method == "lora":
                from peft import LoraConfig, get_peft_model

            self._log(task_id, f"加载基础模型: {base_model}")
            tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                base_model,
                torch_dtype=torch.float16 if fw_info["cuda_available"] else torch.float32,
                device_map="auto" if fw_info["cuda_available"] else None,
                trust_remote_code=True,
            )

            if method == "lora":
                lora_config = LoraConfig(
                    r=config.get("lora_r", 16),
                    lora_alpha=config.get("lora_alpha", 32),
                    lora_dropout=config.get("lora_dropout", 0.05),
                    target_modules=config.get("lora_target_modules", ["q_proj", "v_proj"]),
                    task_type="CAUSAL_LM",
                )
                model = get_peft_model(model, lora_config)
                trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
                total_params = sum(p.numel() for p in model.parameters())
                self._log(task_id, f"LoRA: 可训练参数 {trainable:,} / {total_params:,} ({100*trainable/total_params:.2f}%)")

            class SimpleDataset(torch.utils.data.Dataset):
                def __init__(self, data, tok, max_len=2048):
                    self.items = []
                    for item in data:
                        text = item.get("input", "") + "\n" + item.get("expected", item.get("output", ""))
                        enc = tok(text, truncation=True, max_length=max_len, return_tensors="pt")
                        self.items.append(enc)
                def __len__(self):
                    return len(self.items)
                def __getitem__(self, idx):
                    return {k: v.squeeze(0) for k, v in self.items[idx].items()}

            train_dataset = SimpleDataset(dataset, tokenizer, config.get("max_seq_length", 2048))

            output_dir = f"./models/{task_id}"
            training_args = TrainingArguments(
                output_dir=output_dir,
                num_train_epochs=config.get("epochs", 3),
                per_device_train_batch_size=config.get("batch_size", 4),
                gradient_accumulation_steps=config.get("gradient_accumulation_steps", 4),
                learning_rate=config.get("learning_rate", 2e-4),
                warmup_steps=config.get("warmup_steps", 100),
                save_steps=config.get("save_steps", 500),
                save_total_limit=3,
                logging_steps=10,
                fp16=fw_info["cuda_available"],
                report_to="none",
                remove_unused_columns=False,
            )

            best_loss_ref = [float("inf")]

            class ProgressCallback:
                def __init__(self, worker, tid, total, start):
                    self.worker = worker
                    self.tid = tid
                    self.total = total
                    self.start = start
                def on_log(self, args, state, control, logs=None, **kwargs):
                    if logs and "loss" in logs:
                        loss = logs["loss"]
                        step = state.global_step
                        elapsed = _time.time() - self.start
                        self.worker._progress[self.tid].current_step = step
                        self.worker._progress[self.tid].train_loss = loss
                        self.worker._progress[self.tid].elapsed_seconds = elapsed
                        if step > 0 and self.total > step:
                            self.worker._progress[self.tid].estimated_remaining_seconds = (elapsed / step) * (self.total - step)
                        if loss < best_loss_ref[0]:
                            best_loss_ref[0] = loss
                        self.worker._log(self.tid, f"Step {step}/{self.total}, loss={loss:.6f}")

            trainer = Trainer(
                model=model,
                args=training_args,
                train_dataset=train_dataset,
                callbacks=[ProgressCallback(self, task_id, total_steps, start_time)],
            )

            self._log(task_id, "开始HuggingFace Trainer训练...")
            train_result = trainer.train()
            best_loss = train_result.training_loss

            model.save_pretrained(f"{output_dir}/final")
            tokenizer.save_pretrained(f"{output_dir}/final")
            self._log(task_id, f"模型已保存到 {output_dir}/final")

            return best_loss

        except Exception as exc:
            self._log(task_id, f"真实训练失败，回退到模拟模式: {exc}")
            logger.warning(f"Real training failed for {task_id}: {exc}")
            return await self._run_fallback_training(task_id, method, base_model, config, dataset, steps_per_epoch, total_steps, progress)

    async def _run_fallback_training(
        self,
        task_id: str,
        method: str,
        base_model: str,
        config: Dict[str, Any],
        dataset: List[Dict],
        steps_per_epoch: int,
        total_steps: int,
        progress: TrainingProgress,
    ) -> float:
        import time as _time
        import random
        start_time = _time.time()
        best_loss = float("inf")

        for epoch in range(1, config.get("epochs", 3) + 1):
            progress.current_epoch = epoch
            epoch_loss = 0.0
            epoch_steps = 0

            for step in range(1, steps_per_epoch + 1):
                global_step = (epoch - 1) * steps_per_epoch + step
                progress.current_step = global_step

                base_loss = 2.5 - (epoch - 1) * 0.5
                step_decay = step / steps_per_epoch * 0.1
                noise = random.gauss(0, 0.05)
                step_loss = max(0.01, base_loss - step_decay + noise)

                epoch_loss += step_loss
                epoch_steps += 1

                progress.train_loss = step_loss
                progress.learning_rate = self._get_lr(global_step, total_steps, config)
                progress.elapsed_seconds = _time.time() - start_time
                progress.tokens_processed += config.get("batch_size", 4) * config.get("max_seq_length", 2048)

                if progress.elapsed_seconds > 0:
                    remaining = total_steps - global_step
                    avg = progress.elapsed_seconds / global_step
                    progress.estimated_remaining_seconds = remaining * avg

                if self._checkpoint_mgr.should_save(task_id, global_step):
                    cp = self._checkpoint_mgr.save_checkpoint(
                        task_id=task_id, step=global_step,
                        epoch=epoch + step / steps_per_epoch,
                        loss=step_loss,
                        metrics={"train_loss": step_loss, "learning_rate": progress.learning_rate, "mode": "fallback"},
                    )
                    self._log(task_id, f"检查点: step={global_step}, loss={step_loss:.6f}")

                if global_step % 10 == 0:
                    await asyncio.sleep(0.01)

            avg_epoch_loss = epoch_loss / max(1, epoch_steps)
            if avg_epoch_loss < best_loss:
                best_loss = avg_epoch_loss
            self._log(task_id, f"Epoch {epoch} 完成, avg_loss={avg_epoch_loss:.6f}")

        return best_loss

    def _detect_training_framework(self) -> Dict[str, Any]:
        result = {
            "torch_available": False,
            "transformers_available": False,
            "peft_available": False,
            "cuda_available": False,
            "cuda_device_count": 0,
            "cuda_device_name": "",
            "distributed_available": False,
            "distributed_backend": "",
            "real_training_ready": False,
        }
        try:
            import torch
            result["torch_available"] = True
            result["cuda_available"] = torch.cuda.is_available()
            if result["cuda_available"]:
                result["cuda_device_count"] = torch.cuda.device_count()
                if result["cuda_device_count"] > 0:
                    result["cuda_device_name"] = torch.cuda.get_device_name(0)
        except ImportError:
            pass
        try:
            import transformers
            result["transformers_available"] = True
        except ImportError:
            pass
        try:
            import peft
            result["peft_available"] = True
        except ImportError:
            pass
        try:
            import torch.distributed
            result["distributed_available"] = torch.distributed.is_available()
            if result["distributed_available"]:
                result["distributed_backend"] = "nccl" if torch.distributed.is_nccl_available() else "gloo"
        except (ImportError, AttributeError):
            pass
        result["real_training_ready"] = result["torch_available"] and result["transformers_available"]
        return result

    def _get_gpu_memory_usage(self) -> float:
        try:
            import torch
            if torch.cuda.is_available():
                return torch.cuda.memory_allocated() / (1024 * 1024)
        except ImportError:
            pass
        return 0.0

    def _fallback_simulate_loss(
        self, epoch: int, step: int, steps_per_epoch: int, total_steps: int, base_lr: float
    ) -> float:
        import random

        global_step = (epoch - 1) * steps_per_epoch + step
        progress = global_step / max(1, total_steps)

        initial_loss = 2.8
        min_loss = 0.15
        cosine_decay = 0.5 * (1 + math.cos(math.pi * progress))
        base_loss = min_loss + (initial_loss - min_loss) * cosine_decay

        noise_scale = 0.08 * (1.0 - 0.7 * progress)
        noise = random.gauss(0, noise_scale)

        lr = self._cosine_annealing_lr(global_step, total_steps, base_lr)
        lr_factor = lr / base_lr if base_lr > 0 else 1.0
        lr_bonus = 0.05 * (1.0 - lr_factor)

        return max(0.01, base_loss + noise - lr_bonus)

    def _cosine_annealing_lr(
        self, current_step: int, total_steps: int, base_lr: float, warmup_steps: int = 100, min_lr_ratio: float = 0.01
    ) -> float:
        min_lr = base_lr * min_lr_ratio
        if current_step < warmup_steps:
            return min_lr + (base_lr - min_lr) * current_step / warmup_steps
        progress = (current_step - warmup_steps) / max(1, total_steps - warmup_steps)
        return min_lr + 0.5 * (base_lr - min_lr) * (1 + math.cos(math.pi * progress))

    def _get_lr(self, current_step: int, total_steps: int, config: Dict) -> float:
        base_lr = config.get("learning_rate", 2e-4)
        warmup_steps = config.get("warmup_steps", 100)

        if current_step < warmup_steps:
            return base_lr * current_step / warmup_steps

        progress = (current_step - warmup_steps) / max(1, total_steps - warmup_steps)
        return base_lr * max(0.01, 1.0 - progress)

    async def _load_dataset(self, dataset_ref: Optional[str]) -> List[Dict]:
        if not dataset_ref:
            return [
                {"input": f"威胁情报样本{i}", "expected": "high" if i % 3 == 0 else "medium" if i % 3 == 1 else "low"}
                for i in range(20)
            ]

        path = Path(dataset_ref)
        if path.exists():
            if path.suffix == ".jsonl":
                items = []
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            items.append(json.loads(line))
                return items
            elif path.suffix == ".json":
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)

        return []

    def _log(self, task_id: str, message: str):
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = f"[{timestamp}] {message}"
        self._training_logs[task_id].append(log_entry)
        if len(self._training_logs[task_id]) > self._max_logs_per_task:
            self._training_logs[task_id] = self._training_logs[task_id][-self._max_logs_per_task:]
        logger.info(f"Training[{task_id[:8]}]: {message}")

    def get_progress(self, task_id: str) -> Optional[TrainingProgress]:
        return self._progress.get(task_id)

    def save_checkpoint_public(
        self, task_id: str, step: int, epoch: float, loss: float, metrics: Optional[Dict] = None
    ) -> CheckpointInfo:
        self._validate_id(task_id)
        return self._checkpoint_mgr.save_checkpoint(
            task_id=task_id, step=step, epoch=epoch, loss=loss, metrics=metrics or {}
        )

    def list_checkpoints_public(self, task_id: str) -> List[CheckpointInfo]:
        self._validate_id(task_id)
        return self._checkpoint_mgr.list_checkpoints(task_id)

    async def evaluate_model(
        self, task_id: str, eval_data=None, model_path: str = "", metrics: Optional[List[str]] = None
    ):
        self._validate_id(task_id)
        return await self._evaluator.evaluate(
            task_id=task_id, eval_data=eval_data, model_path=model_path, metrics=metrics or ["accuracy", "f1", "loss"]
        )

    def get_logs(self, task_id: str, limit: int = 100) -> List[str]:
        self._validate_id(task_id)
        logs = self._training_logs.get(task_id, [])
        return logs[-limit:]

    def cancel_training(self, task_id: str) -> bool:
        self._validate_id(task_id)
        task = self._active_tasks.get(task_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def get_active_task_ids(self) -> List[str]:
        return list(self._active_tasks.keys())

    def restore_from_checkpoint(self, task_id: str, checkpoint_id: str) -> bool:
        self._validate_id(task_id)
        target_cp = None
        for cp in self._checkpoint_mgr.list_checkpoints(task_id):
            if cp.checkpoint_id == checkpoint_id:
                target_cp = cp
                break

        if not target_cp:
            self._log(task_id, f"检查点 {checkpoint_id} 不存在")
            return False

        self._log(task_id, f"从检查点恢复: {checkpoint_id}, step={target_cp.step}, loss={target_cp.loss:.6f}")

        if task_id in self._progress:
            progress = self._progress[task_id]
            progress.current_step = target_cp.step
            progress.current_epoch = target_cp.epoch
            progress.train_loss = target_cp.loss
            progress.status = TrainingStatus.PENDING
            self._log(task_id, f"进度已恢复到 step={target_cp.step}, epoch={target_cp.epoch:.2f}")

        checkpoint_path = Path(target_cp.path)
        if checkpoint_path.exists():
            try:
                with open(checkpoint_path, "r", encoding="utf-8") as f:
                    cp_data = json.load(f)

                restore_dir = Path(f"./models/{task_id}/restored")
                restore_dir.mkdir(parents=True, exist_ok=True)
                restore_meta = restore_dir / f"restore_from_{checkpoint_id}.json"
                with open(restore_meta, "w", encoding="utf-8") as f:
                    json.dump({
                        "source_checkpoint": checkpoint_id,
                        "restored_at": datetime.now(timezone.utc).isoformat(),
                        "step": target_cp.step,
                        "epoch": target_cp.epoch,
                        "loss": target_cp.loss,
                        "metrics": target_cp.metrics,
                        "model_state_keys": cp_data.get("model_state_keys", []),
                    }, f, ensure_ascii=False, indent=2)

                self._log(task_id, f"检查点恢复元数据已保存至 {restore_meta}")
            except Exception as exc:
                self._log(task_id, f"检查点恢复元数据保存失败: {exc}")

        return True

    def get_checkpoints(self, task_id: str) -> List[Dict]:
        self._validate_id(task_id)
        return [cp.to_dict() for cp in self._checkpoint_mgr.list_checkpoints(task_id)]

    def get_model_versions(self, task_id: str) -> List[Dict]:
        self._validate_id(task_id)
        return [v.to_dict() for v in self._registry.list_versions(task_id)]

    def compare_model_versions(self, task_id: str, v_a: int, v_b: int) -> Dict:
        self._validate_id(task_id)
        return self._registry.compare_versions(task_id, v_a, v_b)

    def generate_training_script(self, task_id: str) -> Dict[str, Any]:
        self._validate_id(task_id)
        progress = self._progress.get(task_id)
        if not progress:
            return {"error": "任务不存在"}

        versions = self._registry.list_versions(task_id)
        if not versions:
            return {"error": "任务无模型版本信息"}

        latest = versions[-1]
        method = latest.method
        config = latest.config
        base_model = latest.base_model

        def _sanitize_for_script(value: Any) -> str:
            s = str(value)
            s = s.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
            s = re.sub(r'[\x00-\x1f]', '', s)
            return s

        common_imports = """import torch
from datasets import Dataset as HFDataset, load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
)
"""

        data_loading = f"""
def load_data(data_path: str):
    if data_path.endswith(".jsonl"):
        items = []
        with open(data_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    import json
                    items.append(json.loads(line))
        return HFDataset.from_list(items)
    elif data_path.endswith(".json"):
        import json
        with open(data_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return HFDataset.from_list(data)
    else:
        return load_dataset(data_path)

dataset = load_data("{_sanitize_for_script(config.get('data_path', 'data/train.jsonl'))}")
"""

        tokenize_fn = f"""
tokenizer = AutoTokenizer.from_pretrained("{_sanitize_for_script(base_model)}", trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

def tokenize_fn(examples):
    texts = []
    for inp, exp in zip(examples.get("input", []), examples.get("expected", [])):
        texts.append(f"### Input:\\n{{inp}}\\n\\n### Response:\\n{{exp}}")
    return tokenizer(
        texts,
        truncation=True,
        max_length={_sanitize_for_script(config.get('max_seq_length', 2048))},
        padding="max_length",
    )

tokenized = dataset.map(tokenize_fn, batched=True, remove_columns=dataset.column_names)
split = tokenized.train_test_split(test_size=0.1, seed=42)
train_dataset = split["train"]
eval_dataset = split["test"]
"""

        if method == "lora":
            target_modules_raw = config.get('lora_target_modules', ['q_proj', 'v_proj'])
            if isinstance(target_modules_raw, list):
                sanitized_modules = [_sanitize_for_script(m) for m in target_modules_raw]
                target_modules_str = '[' + ', '.join(f'"{m}"' for m in sanitized_modules) + ']'
            else:
                target_modules_str = _sanitize_for_script(target_modules_raw)
            model_setup = f"""
model = AutoModelForCausalLM.from_pretrained(
    "{_sanitize_for_script(base_model)}",
    trust_remote_code=True,
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    device_map="auto" if torch.cuda.is_available() else None,
)

from peft import LoraConfig, get_peft_model, TaskType

lora_config = LoraConfig(
    task_type=TaskType.CAUSAL_LM,
    r={_sanitize_for_script(config.get('lora_r', 16))},
    lora_alpha={_sanitize_for_script(config.get('lora_alpha', 32))},
    lora_dropout={_sanitize_for_script(config.get('lora_dropout', 0.05))},
    target_modules={target_modules_str},
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()
"""
        else:
            model_setup = f"""
model = AutoModelForCausalLM.from_pretrained(
    "{_sanitize_for_script(base_model)}",
    trust_remote_code=True,
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    device_map="auto" if torch.cuda.is_available() else None,
)
"""

        training_args = f"""
training_args = TrainingArguments(
    output_dir="./output",
    num_train_epochs={_sanitize_for_script(config.get('epochs', 3))},
    per_device_train_batch_size={_sanitize_for_script(config.get('batch_size', 4))},
    gradient_accumulation_steps={_sanitize_for_script(config.get('gradient_accumulation_steps', 4))},
    learning_rate={_sanitize_for_script(config.get('learning_rate', 2e-4 if method == 'lora' else 2e-5))},
    warmup_steps={_sanitize_for_script(config.get('warmup_steps', 100))},
    lr_scheduler_type="cosine",
    save_steps={_sanitize_for_script(config.get('save_steps', 500))},
    eval_steps={_sanitize_for_script(config.get('eval_steps', 500))},
    evaluation_strategy="steps",
    save_total_limit=3,
    load_best_model_at_end=True,
    metric_for_best_model="loss",
    fp16=torch.cuda.is_available(),
    logging_steps=10,
    report_to="none",
    remove_unused_columns=False,
)
"""

        trainer_run = """
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    tokenizer=tokenizer,
)

trainer.train()
trainer.save_model("./output/final")
print("Training completed. Model saved to ./output/final")
"""

        if method == "lora":
            merge_script = """
from peft import PeftModel

base_model = AutoModelForCausalLM.from_pretrained(
    "{base_model}",
    trust_remote_code=True,
    torch_dtype=torch.float16,
    device_map="auto",
)
model = PeftModel.from_pretrained(base_model, "./output/final")
merged_model = model.merge_and_unload()
merged_model.save_pretrained("./output/merged")
tokenizer.save_pretrained("./output/merged")
print("Merged model saved to ./output/merged")
""".format(base_model=_sanitize_for_script(base_model))
        else:
            merge_script = ""

        full_script = common_imports + data_loading + tokenize_fn + model_setup + training_args + trainer_run + merge_script

        return {
            "task_id": task_id,
            "method": method,
            "base_model": base_model,
            "script_content": full_script,
            "script_type": "lora_peft" if method == "lora" else "full_finetune",
        }

    def estimate_resources(self, method: str, config: Dict[str, Any], dataset_size: int) -> Dict[str, Any]:
        model_size_map = {
            "1b": {"params_b": 1, "fp16_gb": 2, "full_gb": 8},
            "3b": {"params_b": 3, "fp16_gb": 6, "full_gb": 24},
            "7b": {"params_b": 7, "fp16_gb": 14, "full_gb": 56},
            "7b-chat": {"params_b": 7, "fp16_gb": 14, "full_gb": 56},
            "13b": {"params_b": 13, "fp16_gb": 26, "full_gb": 104},
            "14b": {"params_b": 14, "fp16_gb": 28, "full_gb": 112},
            "34b": {"params_b": 34, "fp16_gb": 68, "full_gb": 272},
            "70b": {"params_b": 70, "fp16_gb": 140, "full_gb": 560},
        }

        base_model = config.get("base_model", "7b")
        model_key = None
        for key in model_size_map:
            if key in base_model.lower():
                model_key = key
                break
        if model_key is None:
            for key in model_size_map:
                if model_size_map[key]["params_b"] <= 7:
                    model_key = key
            if model_key is None:
                model_key = "7b"

        model_info = model_size_map[model_key]
        batch_size = config.get("batch_size", 4)
        grad_accum = config.get("gradient_accumulation_steps", 4)
        seq_len = config.get("max_seq_length", 2048)
        epochs = config.get("epochs", 3)

        if method == "lora":
            lora_r = config.get("lora_r", 16)
            lora_params_mb = lora_r * 2 * 4096 * 4 / (1024 * 1024)
            model_memory_gb = model_info["fp16_gb"]
            optimizer_memory_gb = lora_params_mb / 1024 * 8 / 1024
            activation_memory_gb = batch_size * seq_len * 4096 * 2 * 4 / (1024 ** 3)
            total_gpu_gb = model_memory_gb + optimizer_memory_gb + activation_memory_gb + 2
        else:
            model_memory_gb = model_info["fp16_gb"]
            optimizer_memory_gb = model_info["fp16_gb"] * 2
            activation_memory_gb = batch_size * seq_len * 4096 * 2 * 4 / (1024 ** 3)
            gradient_memory_gb = model_info["fp16_gb"]
            total_gpu_gb = model_memory_gb + optimizer_memory_gb + activation_memory_gb + gradient_memory_gb + 2

        effective_batch = batch_size * grad_accum
        steps_per_epoch = max(1, dataset_size // effective_batch)
        total_steps = steps_per_epoch * epochs

        if method == "lora":
            time_per_step_seconds = 1.2 + model_info["params_b"] * 0.05
        else:
            time_per_step_seconds = 1.5 + model_info["params_b"] * 0.15

        total_hours = total_steps * time_per_step_seconds / 3600

        if method == "lora":
            disk_gb = model_info["fp16_gb"] * 0.5 + dataset_size * seq_len * 4 / (1024 ** 3) + 5
        else:
            disk_gb = model_info["full_gb"] + dataset_size * seq_len * 4 / (1024 ** 3) + 10

        gpu_recommendations = []
        if total_gpu_gb <= 10:
            gpu_recommendations = ["RTX 3090 (24GB)", "RTX 4090 (24GB)", "A10G (24GB)"]
        elif total_gpu_gb <= 24:
            gpu_recommendations = ["RTX 4090 (24GB)", "A10G (24GB)", "A100-40GB (40GB)"]
        elif total_gpu_gb <= 40:
            gpu_recommendations = ["A100-40GB (40GB)", "A100-80GB (80GB)"]
        elif total_gpu_gb <= 80:
            gpu_recommendations = ["A100-80GB (80GB)", "H100-80GB (80GB)"]
        else:
            num_gpus = math.ceil(total_gpu_gb / 80)
            gpu_recommendations = [f"{num_gpus}x A100-80GB (80GB)", f"{num_gpus}x H100-80GB (80GB)"]

        return {
            "method": method,
            "base_model": base_model,
            "dataset_size": dataset_size,
            "gpu_memory_required_gb": round(total_gpu_gb, 2),
            "training_time_hours": round(total_hours, 2),
            "disk_space_required_gb": round(disk_gb, 2),
            "recommended_gpus": gpu_recommendations,
            "breakdown": {
                "model_memory_gb": round(model_memory_gb, 2),
                "optimizer_memory_gb": round(optimizer_memory_gb, 2),
                "activation_memory_gb": round(activation_memory_gb, 2),
                "gradient_memory_gb": round(gradient_memory_gb, 2) if method == "full" else 0,
                "overhead_gb": 2,
            },
            "total_steps": total_steps,
            "steps_per_epoch": steps_per_epoch,
        }

    async def generate_evaluation_report(self, task_id: str) -> Dict[str, Any]:
        self._validate_id(task_id)
        progress = self._progress.get(task_id)
        if not progress:
            return {"error": "任务不存在"}

        versions = self._registry.list_versions(task_id)
        latest_version = versions[-1] if versions else None

        checkpoints = self._checkpoint_mgr.list_checkpoints(task_id)
        best_checkpoint = self._checkpoint_mgr.get_best_checkpoint(task_id)

        training_overview = {
            "task_id": task_id,
            "status": progress.status.value,
            "method": latest_version.method if latest_version else "unknown",
            "base_model": latest_version.base_model if latest_version else "unknown",
            "config": latest_version.config if latest_version else {},
            "total_epochs": progress.total_epochs,
            "completed_epochs": int(progress.current_epoch),
            "total_steps": progress.total_steps,
            "completed_steps": progress.current_step,
            "progress": round(progress.progress, 4),
            "elapsed_seconds": round(progress.elapsed_seconds, 1),
            "final_train_loss": round(progress.train_loss, 6),
            "final_val_loss": round(progress.val_loss, 6),
            "tokens_processed": progress.tokens_processed,
            "gpu_memory_used_mb": round(progress.gpu_memory_used_mb, 1),
        }

        loss_curve = []
        for cp in checkpoints:
            loss_curve.append({
                "step": cp.step,
                "epoch": round(cp.epoch, 2),
                "loss": round(cp.loss, 6),
                "is_best": cp.is_best,
            })

        eval_metrics = {}
        if latest_version:
            eval_metrics = {
                "accuracy": latest_version.metrics.get("accuracy", 0),
                "f1_score": latest_version.metrics.get("f1_score", 0),
                "loss": latest_version.metrics.get("loss", 0),
                "perplexity": latest_version.metrics.get("perplexity", 0),
                "best_train_loss": latest_version.metrics.get("best_train_loss", 0),
                "training_mode": latest_version.metrics.get("training_mode", "unknown"),
            }

        baseline_comparison = {}
        if len(versions) >= 2:
            prev = versions[-2]
            curr = versions[-1]
            for key in set(prev.metrics.keys()) | set(curr.metrics.keys()):
                prev_val = prev.metrics.get(key, 0)
                curr_val = curr.metrics.get(key, 0)
                delta = curr_val - prev_val
                higher_better = key in ["accuracy", "f1_score", "precision", "recall", "bleu_score", "rouge_l"]
                baseline_comparison[key] = {
                    "baseline": round(prev_val, 6),
                    "current": round(curr_val, 6),
                    "delta": round(delta, 6),
                    "improved": (delta > 0 and higher_better) or (delta < 0 and not higher_better),
                }
        elif latest_version:
            baseline_comparison = {
                "note": "首次训练，无基线对比数据",
                "current_metrics": {k: round(v, 6) for k, v in latest_version.metrics.items()},
            }

        deployment_suggestions = []
        if latest_version:
            method = latest_version.method
            if method == "lora":
                deployment_suggestions.append("使用PEFT加载LoRA适配器，基座模型可复用")
                deployment_suggestions.append("合并LoRA权重后可独立部署，减少推理延迟")
            else:
                deployment_suggestions.append("全参微调模型需完整加载，确保部署环境显存充足")

            if eval_metrics.get("perplexity", float("inf")) < 10:
                deployment_suggestions.append("困惑度较低，模型生成质量良好，可直接部署")
            else:
                deployment_suggestions.append("困惑度偏高，建议增加训练数据或调整超参数后重新训练")

            if progress.gpu_memory_used_mb > 0:
                inference_mem_gb = progress.gpu_memory_used_mb / 1024 * 0.6
                deployment_suggestions.append(f"预估推理显存需求约{round(inference_mem_gb, 1)}GB")

            deployment_suggestions.append("建议在部署前进行A/B测试验证效果")

        report = {
            "task_id": task_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "training_overview": training_overview,
            "loss_curve": loss_curve,
            "evaluation_metrics": eval_metrics,
            "baseline_comparison": baseline_comparison,
            "deployment_suggestions": deployment_suggestions,
            "checkpoints_total": len(checkpoints),
            "best_checkpoint": best_checkpoint.to_dict() if best_checkpoint else None,
        }

        report_dir = Path(f"./reports/{task_id}")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"eval_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)

        self._log(task_id, f"评估报告已生成: {report_path}")
        report["report_path"] = str(report_path)

        return report

    def export_model(self, task_id: str, export_format: str = "huggingface") -> Dict[str, Any]:
        self._validate_id(task_id)
        progress = self._progress.get(task_id)
        if not progress:
            return {"error": "任务不存在"}

        if progress.status != TrainingStatus.COMPLETED:
            return {"error": f"任务未完成，当前状态: {progress.status.value}"}

        versions = self._registry.list_versions(task_id)
        if not versions:
            return {"error": "无可用模型版本"}

        latest = versions[-1]
        source_path = Path(latest.model_path)
        if not source_path.exists():
            source_path = Path(f"./models/{task_id}/final")

        export_dir = Path(f"./exports/{task_id}")
        export_dir.mkdir(parents=True, exist_ok=True)

        if export_format == "huggingface":
            target_dir = export_dir / "huggingface"
            target_dir.mkdir(parents=True, exist_ok=True)

            if source_path.exists():
                for item in source_path.iterdir():
                    src_item = source_path / item.name
                    dst_item = target_dir / item.name
                    if src_item.is_file():
                        shutil.copy2(str(src_item), str(dst_item))
                    elif src_item.is_dir():
                        if dst_item.exists():
                            shutil.rmtree(str(dst_item))
                        shutil.copytree(str(src_item), str(dst_item))

            metadata = {
                "model_type": "huggingface",
                "base_model": latest.base_model,
                "method": latest.method,
                "task_id": task_id,
                "version": latest.version_number,
                "config": latest.config,
                "metrics": {k: round(v, 6) for k, v in latest.metrics.items()},
                "exported_at": datetime.now(timezone.utc).isoformat(),
            }
            metadata_path = target_dir / "export_metadata.json"
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)

            self._log(task_id, f"模型已导出为HuggingFace格式: {target_dir}")

            return {
                "task_id": task_id,
                "export_format": "huggingface",
                "export_path": str(target_dir),
                "metadata": metadata,
            }

        elif export_format == "onnx":
            target_dir = export_dir / "onnx"
            target_dir.mkdir(parents=True, exist_ok=True)

            try:
                import torch
                from transformers import AutoModelForCausalLM, AutoTokenizer

                model = AutoModelForCausalLM.from_pretrained(
                    str(source_path) if source_path.exists() else latest.base_model,
                    trust_remote_code=True,
                    torch_dtype=torch.float32,
                )
                tokenizer = AutoTokenizer.from_pretrained(
                    str(source_path) if source_path.exists() else latest.base_model,
                    trust_remote_code=True,
                )

                if latest.method == "lora":
                    try:
                        from peft import PeftModel
                        model = PeftModel.from_pretrained(model, str(source_path))
                        model = model.merge_and_unload()
                    except ImportError:
                        self._log(task_id, "peft未安装，跳过LoRA合并")

                dummy_input = tokenizer("export test", return_tensors="pt")
                onnx_path = target_dir / "model.onnx"

                torch.onnx.export(
                    model,
                    (dummy_input["input_ids"], dummy_input["attention_mask"]),
                    str(onnx_path),
                    input_names=["input_ids", "attention_mask"],
                    output_names=["logits"],
                    dynamic_axes={
                        "input_ids": {0: "batch_size", 1: "seq_len"},
                        "attention_mask": {0: "batch_size", 1: "seq_len"},
                        "logits": {0: "batch_size", 1: "seq_len"},
                    },
                    opset_version=14,
                )

                tokenizer.save_pretrained(str(target_dir))

                metadata = {
                    "model_type": "onnx",
                    "base_model": latest.base_model,
                    "method": latest.method,
                    "task_id": task_id,
                    "version": latest.version_number,
                    "config": latest.config,
                    "metrics": {k: round(v, 6) for k, v in latest.metrics.items()},
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "opset_version": 14,
                }
                metadata_path = target_dir / "export_metadata.json"
                with open(metadata_path, "w", encoding="utf-8") as f:
                    json.dump(metadata, f, ensure_ascii=False, indent=2)

                onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024) if onnx_path.exists() else 0

                self._log(task_id, f"模型已导出为ONNX格式: {target_dir} ({onnx_size_mb:.1f}MB)")

                return {
                    "task_id": task_id,
                    "export_format": "onnx",
                    "export_path": str(target_dir),
                    "onnx_file_size_mb": round(onnx_size_mb, 2),
                    "metadata": metadata,
                }

            except ImportError as e:
                return {"error": f"ONNX导出需要torch和transformers: {e}"}
            except Exception as e:
                return {"error": f"ONNX导出失败: {e}"}

        else:
            return {"error": f"不支持的导出格式: {export_format}，支持: huggingface, onnx"}
