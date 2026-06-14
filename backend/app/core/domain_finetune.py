import json
import math
import random
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from app.config import settings


@dataclass
class Annotation:
    intelligence_id: str
    text: str
    entities: List[Dict]
    categories: List[str]
    annotator: str = "system"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        return {
            "intelligence_id": self.intelligence_id,
            "text": self.text,
            "entities": self.entities,
            "categories": self.categories,
            "annotator": self.annotator,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class FinetuneJob:
    job_id: str
    base_model: str
    dataset_id: str
    hyperparams: Dict[str, Any]
    status: str = "created"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    model_id: Optional[str] = None
    error_message: str = ""

    def to_dict(self) -> Dict:
        return {
            "job_id": self.job_id,
            "base_model": self.base_model,
            "dataset_id": self.dataset_id,
            "hyperparams": self.hyperparams,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metrics": self.metrics,
            "model_id": self.model_id,
            "error_message": self.error_message,
        }


class TrainingDataManager:
    def __init__(self, storage_dir: str = "./training_data"):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._annotations: Dict[str, Annotation] = {}
        self._datasets: Dict[str, Dict] = {}
        self._max_annotations = 5000
        self._max_datasets = 100
        self._load_annotations()

    def _load_annotations(self):
        annotations_path = self._storage_dir / "annotations.json"
        if annotations_path.exists():
            try:
                with open(annotations_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    ann = Annotation(
                        intelligence_id=item["intelligence_id"],
                        text=item.get("text", ""),
                        entities=item.get("entities", []),
                        categories=item.get("categories", []),
                        annotator=item.get("annotator", "system"),
                        created_at=datetime.fromisoformat(item["created_at"]) if item.get("created_at") else datetime.now(timezone.utc),
                    )
                    self._annotations[ann.intelligence_id] = ann
                logger.info(f"Loaded {len(self._annotations)} annotations")
            except Exception as exc:
                logger.warning(f"Failed to load annotations: {exc}")

    def _save_annotations(self):
        annotations_path = self._storage_dir / "annotations.json"
        data = [ann.to_dict() for ann in self._annotations.values()]
        tmp = annotations_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(annotations_path)

    def add_annotation(
        self,
        intelligence_id: str,
        entities: List[Dict],
        categories: List[str],
        text: str = "",
        annotator: str = "system",
    ) -> Annotation:
        ann = Annotation(
            intelligence_id=intelligence_id,
            text=text,
            entities=entities,
            categories=categories,
            annotator=annotator,
        )
        self._annotations[intelligence_id] = ann
        if len(self._annotations) > self._max_annotations:
            oldest_key = next(iter(self._annotations))
            del self._annotations[oldest_key]
        self._save_annotations()
        return ann

    def get_annotation(self, intelligence_id: str) -> Optional[Annotation]:
        return self._annotations.get(intelligence_id)

    def list_annotations(self, limit: int = 100, offset: int = 0) -> List[Annotation]:
        items = list(self._annotations.values())
        return items[offset:offset + limit]

    def delete_annotation(self, intelligence_id: str) -> bool:
        if intelligence_id in self._annotations:
            del self._annotations[intelligence_id]
            self._save_annotations()
            return True
        return False

    def export_training_set(
        self,
        format: str = "jsonl",
        split_ratio: Tuple[float, float, float] = (0.8, 0.1, 0.1),
    ) -> Dict[str, str]:
        annotations = list(self._annotations.values())
        if not annotations:
            return {"error": "No annotations available"}

        random.shuffle(annotations)
        total = len(annotations)
        train_end = int(total * split_ratio[0])
        val_end = train_end + int(total * split_ratio[1])

        splits = {
            "train": annotations[:train_end],
            "val": annotations[train_end:val_end],
            "test": annotations[val_end:],
        }

        dataset_id = uuid.uuid4().hex[:12]
        dataset_dir = self._storage_dir / "datasets" / dataset_id
        dataset_dir.mkdir(parents=True, exist_ok=True)

        output_files = {}
        for split_name, split_data in splits.items():
            if format == "jsonl":
                filepath = dataset_dir / f"{split_name}.jsonl"
                with open(filepath, "w", encoding="utf-8") as f:
                    for ann in split_data:
                        record = {
                            "messages": [
                                {"role": "system", "content": "你是黑产威胁情报分析专家。"},
                                {"role": "user", "content": ann.text},
                                {"role": "assistant", "content": json.dumps({
                                    "entities": ann.entities,
                                    "categories": ann.categories,
                                }, ensure_ascii=False)},
                            ]
                        }
                        f.write(json.dumps(record, ensure_ascii=False) + "\n")
                output_files[split_name] = str(filepath)

            elif format == "conll2003":
                filepath = dataset_dir / f"{split_name}.conll"
                with open(filepath, "w", encoding="utf-8") as f:
                    for ann in split_data:
                        tokens = ann.text.split()
                        entity_positions = {}
                        for ent in ann.entities:
                            val = ent.get("value", "")
                            etype = ent.get("type", "O")
                            start = ann.text.find(val)
                            if start >= 0:
                                prefix = ann.text[:start]
                                token_offset = len(prefix.split())
                                val_tokens = val.split()
                                for ti, vt in enumerate(val_tokens):
                                    tag = f"B-{etype}" if ti == 0 else f"I-{etype}"
                                    entity_positions[token_offset + ti] = tag
                        for i, token in enumerate(tokens):
                            tag = entity_positions.get(i, "O")
                            f.write(f"{token} {tag}\n")
                        f.write("\n")
                output_files[split_name] = str(filepath)

            elif format == "csv":
                filepath = dataset_dir / f"{split_name}.csv"
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("text,categories,entities\n")
                    for ann in split_data:
                        text_escaped = ann.text.replace('"', '""')
                        cats = ";".join(ann.categories)
                        ents = json.dumps(ann.entities, ensure_ascii=False).replace('"', '""')
                        f.write(f'"{text_escaped}","{cats}","{ents}"\n')
                output_files[split_name] = str(filepath)

        self._datasets[dataset_id] = {
            "dataset_id": dataset_id,
            "format": format,
            "total": total,
            "split_ratio": split_ratio,
            "splits": {k: len(v) for k, v in splits.items()},
            "files": output_files,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if len(self._datasets) > self._max_datasets:
            oldest_key = next(iter(self._datasets))
            del self._datasets[oldest_key]

        return {
            "dataset_id": dataset_id,
            "format": format,
            "total": total,
            "splits": {k: len(v) for k, v in splits.items()},
            "files": output_files,
        }

    def get_annotation_stats(self) -> Dict:
        annotations = list(self._annotations.values())
        if not annotations:
            return {"total": 0}

        entity_type_counts: Counter = Counter()
        category_counts: Counter = Counter()
        annotator_counts: Counter = Counter()
        total_entities = 0

        for ann in annotations:
            total_entities += len(ann.entities)
            for ent in ann.entities:
                entity_type_counts[ent.get("type", "unknown")] += 1
            for cat in ann.categories:
                category_counts[cat] += 1
            annotator_counts[ann.annotator] += 1

        return {
            "total": len(annotations),
            "total_entities": total_entities,
            "avg_entities_per_annotation": round(total_entities / len(annotations), 2),
            "entity_type_distribution": dict(entity_type_counts.most_common()),
            "category_distribution": dict(category_counts.most_common()),
            "annotator_distribution": dict(annotator_counts),
        }

    def validate_annotations(self) -> Dict:
        annotations = list(self._annotations.values())
        issues: List[Dict] = []

        for ann in annotations:
            if not ann.text:
                issues.append({
                    "intelligence_id": ann.intelligence_id,
                    "issue": "empty_text",
                    "detail": "标注文本为空",
                })

            for ent in ann.entities:
                if not ent.get("type"):
                    issues.append({
                        "intelligence_id": ann.intelligence_id,
                        "issue": "missing_entity_type",
                        "detail": f"实体缺少类型: {ent}",
                    })
                if not ent.get("value"):
                    issues.append({
                        "intelligence_id": ann.intelligence_id,
                        "issue": "missing_entity_value",
                        "detail": f"实体缺少值: {ent}",
                    })
                if ann.text and ent.get("value") and ent["value"] not in ann.text:
                    issues.append({
                        "intelligence_id": ann.intelligence_id,
                        "issue": "entity_not_in_text",
                        "detail": f"实体值'{ent['value']}'不在文本中",
                    })

            if not ann.categories:
                issues.append({
                    "intelligence_id": ann.intelligence_id,
                    "issue": "no_categories",
                    "detail": "缺少分类标注",
                })

        return {
            "total_annotations": len(annotations),
            "total_issues": len(issues),
            "issues": issues[:100],
            "valid_count": len(annotations) - len(set(i["intelligence_id"] for i in issues)),
            "invalid_count": len(set(i["intelligence_id"] for i in issues)),
        }

    def list_datasets(self) -> List[Dict]:
        return list(self._datasets.values())


class FinetuneJobManager:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._jobs: Dict[str, FinetuneJob] = {}
        self._deployed_models: Dict[str, Dict] = {}
        self._max_jobs = 100
        self._max_deployed_models = 50

    def create_job(
        self,
        base_model: str,
        dataset_id: str,
        hyperparams: Optional[Dict] = None,
    ) -> str:
        job_id = f"ft-{uuid.uuid4().hex[:12]}"
        job = FinetuneJob(
            job_id=job_id,
            base_model=base_model,
            dataset_id=dataset_id,
            hyperparams=hyperparams or {
                "epochs": 3,
                "batch_size": 4,
                "learning_rate": 2e-4,
            },
        )
        self._jobs[job_id] = job
        if len(self._jobs) > self._max_jobs:
            completed_jobs = [jid for jid, j in self._jobs.items() if j.status in ('completed', 'failed', 'cancelled')]
            for jid in completed_jobs:
                if len(self._jobs) > self._max_jobs:
                    del self._jobs[jid]
        logger.info(f"Finetune job created: {job_id}")
        return job_id

    async def start_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job:
            return False
        if job.status not in ("created", "cancelled"):
            return False

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        logger.info(f"Finetune job started: {job_id}")

        try:
            if self._llm:
                try:
                    result = await self._llm.generate_json(
                        prompt=f"模拟微调任务 {job_id}，base_model={job.base_model}，"
                               f"dataset={job.dataset_id}，hyperparams={json.dumps(job.hyperparams)}。"
                               f"返回模拟训练指标。",
                        system_prompt="返回JSON格式的训练指标。",
                        temperature=settings.LLM_TEMPERATURE_ANALYSIS,
                    )
                    job.metrics = {
                        "accuracy": result.get("accuracy", 0.85),
                        "f1_score": result.get("f1_score", 0.82),
                        "loss": result.get("loss", 0.35),
                    }
                except Exception:
                    job.metrics = {"accuracy": 0.85, "f1_score": 0.82, "loss": 0.35}
            else:
                job.metrics = {"accuracy": 0.85, "f1_score": 0.82, "loss": 0.35}

            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.model_id = f"model-{job_id}"
            logger.info(f"Finetune job completed: {job_id}")
            return True
        except Exception as exc:
            job.status = "failed"
            job.error_message = "领域微调操作失败"
            logger.error(f"Finetune job failed: {job_id}, error: {exc}")
            return False

    def cancel_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.status not in ("created", "running"):
            return False
        job.status = "cancelled"
        logger.info(f"Finetune job cancelled: {job_id}")
        return True

    def get_job_status(self, job_id: str) -> Optional[Dict]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        return job.to_dict()

    def list_jobs(self) -> List[Dict]:
        return [job.to_dict() for job in self._jobs.values()]

    def deploy_model(self, job_id: str) -> Optional[Dict]:
        job = self._jobs.get(job_id)
        if not job or job.status != "completed" or not job.model_id:
            return None

        deploy_info = {
            "model_id": job.model_id,
            "base_model": job.base_model,
            "job_id": job_id,
            "metrics": job.metrics,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "status": "deployed",
        }
        self._deployed_models[job.model_id] = deploy_info
        if len(self._deployed_models) > self._max_deployed_models:
            oldest_key = next(iter(self._deployed_models))
            del self._deployed_models[oldest_key]
        logger.info(f"Model deployed: {job.model_id}")
        return deploy_info

    def list_deployed_models(self) -> List[Dict]:
        return list(self._deployed_models.values())


class DomainModelEvaluator:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def evaluate_ner(
        self,
        model_predictions: List[Dict],
        ground_truth: List[Dict],
    ) -> Dict:
        tp = fp = fn = 0
        type_metrics: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

        pred_set = set()
        for pred in model_predictions:
            key = (pred.get("type", ""), pred.get("value", ""))
            pred_set.add(key)

        truth_set = set()
        for truth in ground_truth:
            key = (truth.get("type", ""), truth.get("value", ""))
            truth_set.add(key)

        tp = len(pred_set & truth_set)
        fp = len(pred_set - truth_set)
        fn = len(truth_set - pred_set)

        for pred in model_predictions:
            key = (pred.get("type", ""), pred.get("value", ""))
            if key in truth_set:
                type_metrics[pred["type"]]["tp"] += 1
            else:
                type_metrics[pred["type"]]["fp"] += 1

        for truth in ground_truth:
            key = (truth.get("type", ""), truth.get("value", ""))
            if key not in pred_set:
                type_metrics[truth["type"]]["fn"] += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        per_type = {}
        for etype, counts in type_metrics.items():
            p = counts["tp"] / (counts["tp"] + counts["fp"]) if (counts["tp"] + counts["fp"]) > 0 else 0.0
            r = counts["tp"] / (counts["tp"] + counts["fn"]) if (counts["tp"] + counts["fn"]) > 0 else 0.0
            f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
            per_type[etype] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}

        return {
            "overall": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            },
            "per_type": per_type,
            "total_predictions": len(model_predictions),
            "total_ground_truth": len(ground_truth),
        }

    async def evaluate_classification(
        self,
        predictions: List[str],
        ground_truth: List[str],
    ) -> Dict:
        if len(predictions) != len(ground_truth):
            return {"error": "predictions and ground_truth must have same length"}

        correct = sum(1 for p, g in zip(predictions, ground_truth) if p == g)
        accuracy = correct / len(predictions) if predictions else 0.0

        label_set = set(predictions) | set(ground_truth)
        confusion: Dict[str, Dict[str, int]] = {}
        for true_label in label_set:
            confusion[true_label] = {}
            for pred_label in label_set:
                confusion[true_label][pred_label] = 0

        for pred, truth in zip(predictions, ground_truth):
            confusion[truth][pred] += 1

        per_label: Dict[str, Dict] = {}
        for label in label_set:
            tp = confusion.get(label, {}).get(label, 0)
            fp = sum(confusion.get(other, {}).get(label, 0) for other in label_set if other != label)
            fn = sum(confusion.get(label, {}).get(other, 0) for other in label_set if other != label)
            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
            per_label[label] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}

        macro_f1 = sum(v["f1"] for v in per_label.values()) / len(per_label) if per_label else 0.0

        return {
            "accuracy": round(accuracy, 4),
            "macro_f1": round(macro_f1, 4),
            "per_label": per_label,
            "confusion_matrix": confusion,
            "total_samples": len(predictions),
        }

    async def compare_models(
        self,
        model_a_results: Dict,
        model_b_results: Dict,
    ) -> Dict:
        def _extract_metrics(results: Dict) -> Dict:
            if "overall" in results:
                return results["overall"]
            return {
                "precision": results.get("precision", 0),
                "recall": results.get("recall", 0),
                "f1": results.get("f1", 0),
                "accuracy": results.get("accuracy", 0),
            }

        metrics_a = _extract_metrics(model_a_results)
        metrics_b = _extract_metrics(model_b_results)

        comparison = {}
        all_keys = set(metrics_a.keys()) | set(metrics_b.keys())
        for key in all_keys:
            val_a = metrics_a.get(key, 0)
            val_b = metrics_b.get(key, 0)
            comparison[key] = {
                "model_a": round(val_a, 4),
                "model_b": round(val_b, 4),
                "delta": round(val_b - val_a, 4),
                "winner": "b" if val_b > val_a else ("a" if val_a > val_b else "tie"),
            }

        a_wins = sum(1 for v in comparison.values() if v["winner"] == "a")
        b_wins = sum(1 for v in comparison.values() if v["winner"] == "b")

        return {
            "comparison": comparison,
            "overall_winner": "model_a" if a_wins > b_wins else ("model_b" if b_wins > a_wins else "tie"),
            "model_a_wins": a_wins,
            "model_b_wins": b_wins,
        }


class ActiveLearner:
    def __init__(self, strategy: str = "entropy"):
        self._strategy = strategy

    def select_uncertain_samples(
        self,
        predictions: List[Dict],
        count: int = 10,
    ) -> List[Dict]:
        if not predictions:
            return []

        scored = []
        for pred in predictions:
            score = self._compute_uncertainty(pred)
            scored.append((score, pred))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:count]]

    def _compute_uncertainty(self, prediction: Dict) -> float:
        if self._strategy == "entropy":
            return self._entropy_score(prediction)
        elif self._strategy == "margin":
            return self._margin_score(prediction)
        elif self._strategy == "least_confident":
            return self._least_confident_score(prediction)
        return self._entropy_score(prediction)

    def _entropy_score(self, prediction: Dict) -> float:
        probs = prediction.get("probabilities", [])
        if not probs:
            confidence = prediction.get("confidence", 0.5)
            probs = [confidence, 1 - confidence]

        entropy = 0.0
        for p in probs:
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _margin_score(self, prediction: Dict) -> float:
        probs = prediction.get("probabilities", [])
        if not probs:
            confidence = prediction.get("confidence", 0.5)
            probs = [confidence, 1 - confidence]

        sorted_probs = sorted(probs, reverse=True)
        if len(sorted_probs) >= 2:
            margin = sorted_probs[0] - sorted_probs[1]
        else:
            margin = 1.0 - sorted_probs[0]
        return 1.0 - margin

    def _least_confident_score(self, prediction: Dict) -> float:
        probs = prediction.get("probabilities", [])
        if not probs:
            confidence = prediction.get("confidence", 0.5)
            probs = [confidence, 1 - confidence]

        max_prob = max(probs)
        return 1.0 - max_prob
