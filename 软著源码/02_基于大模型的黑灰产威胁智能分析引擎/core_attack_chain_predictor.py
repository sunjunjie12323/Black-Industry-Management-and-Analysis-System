import asyncio
import json
import os
import pickle
import random
import secrets
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

from app.core.knowledge_graph import KnowledgeGraph
from app.core.vector_store import VectorStore


@dataclass
class PredictedStep:
    step: int
    action: str
    technique_id: str
    technique_name: str
    probability: float
    reasoning: str
    related_entities: List[str] = field(default_factory=list)
    time_window: str = ""
    risk_level: str = "medium"

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "action": self.action,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "probability": self.probability,
            "reasoning": self.reasoning,
            "related_entities": self.related_entities,
            "time_window": self.time_window,
            "risk_level": self.risk_level,
        }


@dataclass
class PredictionResult:
    entity_id: str
    entity_name: str
    predictions: List[PredictedStep] = field(default_factory=list)
    confidence: float = 0.0
    based_on_patterns: int = 0

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "predictions": [p.to_dict() for p in self.predictions],
            "confidence": self.confidence,
            "based_on_patterns": self.based_on_patterns,
        }


@dataclass
class SimulatedChain:
    start_entity: str
    paths: List[Dict] = field(default_factory=list)
    critical_junctions: List[Dict] = field(default_factory=list)
    max_probability_path: List[PredictedStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "start_entity": self.start_entity,
            "paths": self.paths,
            "critical_junctions": self.critical_junctions,
            "max_probability_path": [p.to_dict() for p in self.max_probability_path],
        }


@dataclass
class EarlyWarning:
    predicted_step: str
    signal_description: str
    signal_source: str
    urgency: str = "monitor"
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "predicted_step": self.predicted_step,
            "signal_description": self.signal_description,
            "signal_source": self.signal_source,
            "urgency": self.urgency,
            "recommended_actions": self.recommended_actions,
        }


MITRE_TECHNIQUES = {
    "T1595": {"name": "主动扫描", "tactic": "reconnaissance", "risk": "low"},
    "T1592": {"name": "收集受害者主机信息", "tactic": "reconnaissance", "risk": "low"},
    "T1589": {"name": "收集受害者身份信息", "tactic": "reconnaissance", "risk": "medium"},
    "T1566": {"name": "钓鱼攻击", "tactic": "initial_access", "risk": "high"},
    "T1190": {"name": "利用公开应用漏洞", "tactic": "initial_access", "risk": "critical"},
    "T1078": {"name": "有效账号", "tactic": "initial_access", "risk": "high"},
    "T1059": {"name": "命令行脚本执行", "tactic": "execution", "risk": "high"},
    "T1204": {"name": "用户执行", "tactic": "execution", "risk": "medium"},
    "T1053": {"name": "计划任务", "tactic": "execution", "risk": "medium"},
    "T1055": {"name": "进程注入", "tactic": "defense_evasion", "risk": "high"},
    "T1070": {"name": "痕迹清除", "tactic": "defense_evasion", "risk": "high"},
    "T1562": {"name": "削弱防御", "tactic": "defense_evasion", "risk": "critical"},
    "T1027": {"name": "混淆文件或信息", "tactic": "defense_evasion", "risk": "medium"},
    "T1082": {"name": "系统信息发现", "tactic": "discovery", "risk": "low"},
    "T1083": {"name": "文件和目录发现", "tactic": "discovery", "risk": "low"},
    "T1046": {"name": "网络服务发现", "tactic": "discovery", "risk": "medium"},
    "T1005": {"name": "本地数据收集", "tactic": "collection", "risk": "medium"},
    "T1039": {"name": "共享驱动器数据收集", "tactic": "collection", "risk": "medium"},
    "T1041": {"name": "通过C2通道渗出数据", "tactic": "exfiltration", "risk": "high"},
    "T1048": {"name": "通过替代协议渗出", "tactic": "exfiltration", "risk": "high"},
    "T1071": {"name": "应用层协议通信", "tactic": "command_and_control", "risk": "high"},
    "T1573": {"name": "加密通道", "tactic": "command_and_control", "risk": "medium"},
    "T1095": {"name": "非应用层协议通信", "tactic": "command_and_control", "risk": "medium"},
    "T1486": {"name": "数据加密勒索", "tactic": "impact", "risk": "critical"},
    "T1489": {"name": "服务停止", "tactic": "impact", "risk": "critical"},
    "T1490": {"name": " inhibit system recovery", "tactic": "impact", "risk": "critical"},
    "T1111": {"name": "认证钓鱼", "tactic": "credential_access", "risk": "high"},
    "T1558": {"name": "Kerberoasting", "tactic": "credential_access", "risk": "high"},
    "T1003": {"name": "操作系统凭证转储", "tactic": "credential_access", "risk": "critical"},
    "T1548": {"name": "权限提升滥用", "tactic": "privilege_escalation", "risk": "high"},
    "T1068": {"name": "漏洞利用提权", "tactic": "privilege_escalation", "risk": "critical"},
    "T1547": {"name": "启动项劫持", "tactic": "persistence", "risk": "high"},
    "T1133": {"name": "外部远程服务", "tactic": "persistence", "risk": "medium"},
    "T1050": {"name": "新建服务", "tactic": "persistence", "risk": "medium"},
    "T1098": {"name": "账号操作", "tactic": "persistence", "risk": "medium"},
    "T1070.004": {"name": "文件删除", "tactic": "defense_evasion", "risk": "medium"},
    "T1071.001": {"name": "Web协议通信", "tactic": "command_and_control", "risk": "high"},
    "T1566.001": {"name": "钓鱼附件", "tactic": "initial_access", "risk": "high"},
    "T1566.002": {"name": "钓鱼链接", "tactic": "initial_access", "risk": "high"},
    "T1059.001": {"name": "PowerShell执行", "tactic": "execution", "risk": "high"},
    "T1059.003": {"name": "Windows命令行", "tactic": "execution", "risk": "medium"},
}

MITRE_TRANSITIONS = {
    "reconnaissance": {"initial_access": 0.7, "reconnaissance": 0.3},
    "initial_access": {"execution": 0.5, "persistence": 0.2, "credential_access": 0.15, "defense_evasion": 0.15},
    "execution": {"persistence": 0.25, "privilege_escalation": 0.25, "defense_evasion": 0.2, "discovery": 0.15, "credential_access": 0.15},
    "persistence": {"privilege_escalation": 0.3, "defense_evasion": 0.25, "discovery": 0.2, "credential_access": 0.15, "execution": 0.1},
    "privilege_escalation": {"credential_access": 0.3, "discovery": 0.25, "collection": 0.2, "defense_evasion": 0.15, "persistence": 0.1},
    "defense_evasion": {"credential_access": 0.2, "discovery": 0.2, "persistence": 0.2, "execution": 0.2, "privilege_escalation": 0.2},
    "credential_access": {"discovery": 0.3, "collection": 0.25, "lateral_movement": 0.2, "persistence": 0.15, "privilege_escalation": 0.1},
    "discovery": {"collection": 0.3, "lateral_movement": 0.25, "credential_access": 0.2, "command_and_control": 0.15, "execution": 0.1},
    "lateral_movement": {"collection": 0.3, "credential_access": 0.25, "discovery": 0.2, "command_and_control": 0.15, "persistence": 0.1},
    "collection": {"command_and_control": 0.35, "exfiltration": 0.3, "collection": 0.15, "lateral_movement": 0.1, "impact": 0.1},
    "command_and_control": {"exfiltration": 0.4, "impact": 0.25, "collection": 0.15, "lateral_movement": 0.1, "defense_evasion": 0.1},
    "exfiltration": {"impact": 0.3, "command_and_control": 0.2, "defense_evasion": 0.2, "exfiltration": 0.15, "collection": 0.15},
    "impact": {"defense_evasion": 0.3, "exfiltration": 0.2, "impact": 0.2, "command_and_control": 0.15, "persistence": 0.15},
}

ENTITY_TYPE_TO_TACTIC = {
    "malware": "execution",
    "threat_actor": "initial_access",
    "vulnerability": "initial_access",
    "attack_pattern": "execution",
    "tool": "execution",
    "ip": "command_and_control",
    "ip_address": "command_and_control",
    "domain": "command_and_control",
    "url": "initial_access",
    "hash": "execution",
    "email": "initial_access",
    "phone": "initial_access",
    "organization": "reconnaissance",
    "person": "credential_access",
    "location": "reconnaissance",
    "financial_account": "credential_access",
    "account": "credential_access",
    "website": "initial_access",
    "service": "discovery",
    "blacktalk": "reconnaissance",
    "crypto_wallet": "command_and_control",
    "payment_method": "credential_access",
}


class DynamicTransitionLearner:
    PRIOR_STRENGTH = 100

    def __init__(self, persist_dir: str = "./model_data/attack_chain"):
        self._persist_dir = persist_dir
        os.makedirs(self._persist_dir, exist_ok=True)
        self._max_techniques = 500
        self._dirichlet_alpha: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._observed_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._posterior: Dict[str, Dict[str, float]] = {}
        self._total_observations = 0
        self._initialized = False
        self._init_priors()

    def _init_priors(self):
        for src_tactic, transitions in MITRE_TRANSITIONS.items():
            for dst_tactic, prob in transitions.items():
                self._dirichlet_alpha[src_tactic][dst_tactic] = prob * self.PRIOR_STRENGTH
        self._recompute_posterior()
        self._initialized = True
        logger.info(f"DynamicTransitionLearner initialized with MITRE priors (strength={self.PRIOR_STRENGTH})")

    def _recompute_posterior(self):
        self._posterior = {}
        for src_tactic in set(list(self._dirichlet_alpha.keys()) + list(self._observed_counts.keys())):
            alpha = self._dirichlet_alpha.get(src_tactic, {})
            obs = self._observed_counts.get(src_tactic, {})
            all_targets = set(list(alpha.keys()) + list(obs.keys()))
            total_alpha = sum(alpha.get(t, 0.0) for t in all_targets)
            total_obs = sum(obs.get(t, 0) for t in all_targets)
            denominator = total_alpha + total_obs
            if denominator == 0:
                continue
            self._posterior[src_tactic] = {}
            for t in all_targets:
                a = alpha.get(t, 0.0)
                o = obs.get(t, 0)
                self._posterior[src_tactic][t] = (a + o) / denominator

    def observe_transition(self, src_tactic: str, dst_tactic: str, count: int = 1):
        self._observed_counts[src_tactic][dst_tactic] += count
        self._total_observations += count
        if len(self._dirichlet_alpha) > self._max_techniques:
            oldest_key = next(iter(self._dirichlet_alpha))
            del self._dirichlet_alpha[oldest_key]
            self._observed_counts.pop(oldest_key, None)
            self._posterior.pop(oldest_key, None)
        self._recompute_posterior()

    def observe_path(self, path: List[str]):
        for i in range(len(path) - 1):
            self.observe_transition(path[i], path[i + 1])

    def get_posterior_prob(self, src_tactic: str, dst_tactic: str) -> float:
        if src_tactic in self._posterior:
            return self._posterior[src_tactic].get(dst_tactic, 0.0)
        return MITRE_TRANSITIONS.get(src_tactic, {}).get(dst_tactic, 0.01)

    def get_all_posterior_probs(self, src_tactic: str) -> Dict[str, float]:
        if src_tactic in self._posterior:
            return dict(self._posterior[src_tactic])
        return dict(MITRE_TRANSITIONS.get(src_tactic, {}))

    def learn_from_graph(self, knowledge_graph: KnowledgeGraph):
        if not knowledge_graph.graph or knowledge_graph.graph.number_of_nodes() == 0:
            logger.warning("Knowledge graph empty, no observations to learn from")
            return

        path_count = 0
        for source in knowledge_graph.graph.nodes():
            source_data = knowledge_graph.graph.nodes[source]
            source_type = source_data.get("type", source_data.get("entity_type", "unknown"))
            source_tactic = ENTITY_TYPE_TO_TACTIC.get(source_type, "unknown")
            if source_tactic == "unknown":
                continue

            for _, target, data in knowledge_graph.graph.out_edges(source, data=True):
                target_data = knowledge_graph.graph.nodes[target]
                target_type = target_data.get("type", target_data.get("entity_type", "unknown"))
                target_tactic = ENTITY_TYPE_TO_TACTIC.get(target_type, "unknown")
                if target_tactic == "unknown":
                    continue
                self.observe_transition(source_tactic, target_tactic)
                path_count += 1

        self._recompute_posterior()
        logger.info(f"DynamicTransitionLearner learned {path_count} transitions from knowledge graph, total observations: {self._total_observations}")

    def incremental_update(self, src_tactic: str, dst_tactic: str):
        self.observe_transition(src_tactic, dst_tactic)

    def save(self):
        data = {
            "dirichlet_alpha": {k: dict(v) for k, v in self._dirichlet_alpha.items()},
            "observed_counts": {k: dict(v) for k, v in self._observed_counts.items()},
            "total_observations": self._total_observations,
        }
        path = os.path.join(self._persist_dir, "dynamic_learner.pkl")
        with open(path, "wb") as f:
            pickle.dump(data, f)
        logger.info(f"DynamicTransitionLearner saved: {self._total_observations} total observations")

    def load(self):
        path = os.path.join(self._persist_dir, "dynamic_learner.pkl")
        if not os.path.exists(path):
            return
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            self._dirichlet_alpha = defaultdict(lambda: defaultdict(float))
            for k, v in data.get("dirichlet_alpha", {}).items():
                for kk, vv in v.items():
                    self._dirichlet_alpha[k][kk] = vv
            self._observed_counts = defaultdict(lambda: defaultdict(int))
            for k, v in data.get("observed_counts", {}).items():
                for kk, vv in v.items():
                    self._observed_counts[k][kk] = vv
            self._total_observations = data.get("total_observations", 0)
            self._recompute_posterior()
            logger.info(f"DynamicTransitionLearner loaded: {self._total_observations} total observations")
        except Exception as exc:
            logger.warning(f"Failed to load DynamicTransitionLearner: {exc}")

    @property
    def total_observations(self) -> int:
        return self._total_observations


class LLMAttackReasoner:
    LLM_CALL_TIMEOUT = 8.0

    def __init__(self, llm_service=None):
        self._llm = llm_service

    @property
    def _llm_available(self) -> bool:
        if not self._llm:
            return False
        if hasattr(self._llm, 'is_available'):
            return self._llm.is_available
        return True

    async def reason_about_prediction(
        self,
        entity: Any,
        current_tactic: str,
        next_tactic: str,
        context: Optional[Dict] = None,
    ) -> str:
        if not self._llm_available:
            return self._fallback_reasoning(current_tactic, next_tactic)

        entity_desc = f"类型:{getattr(entity, 'type', 'unknown')}, 值:{getattr(entity, 'value', 'unknown')}"
        context_str = ""
        if context:
            context_str = f"\n上下文信息: {json.dumps(context, ensure_ascii=False)[:800]}"

        techniques = [
            f"{tid}({tinfo['name']})"
            for tid, tinfo in MITRE_TECHNIQUES.items()
            if tinfo["tactic"] == next_tactic
        ]
        techniques_str = ", ".join(techniques[:5])

        prompt = (
            f"你是攻击链分析专家。请对以下攻击阶段转移进行深度推理分析：\n\n"
            f"攻击实体: {entity_desc}\n"
            f"当前攻击阶段: {current_tactic}\n"
            f"预测下一阶段: {next_tactic}\n"
            f"该阶段可能的技术: {techniques_str}\n"
            f"{context_str}\n\n"
            f"请分析:\n"
            f"1. 为什么攻击者会从{current_tactic}转移到{next_tactic}？\n"
            f"2. 这个转移在黑灰产场景下的典型模式是什么？\n"
            f"3. 最可能使用的技术和原因\n"
            f"请用200字以内的中文回答，直接给出分析内容。"
        )

        try:
            response = await asyncio.wait_for(
                self._llm.chat(prompt, temperature=0.5, max_tokens=512),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            if isinstance(response, dict):
                return response.get("content", "")[:500]
            return str(response)[:500]
        except asyncio.TimeoutError:
            logger.warning(f"LLM推理超时({self.LLM_CALL_TIMEOUT}s)，回退到规则推理")
            return self._fallback_reasoning(current_tactic, next_tactic)
        except Exception as exc:
            logger.warning(f"LLM推理失败，回退到规则推理: {exc}")
            return self._fallback_reasoning(current_tactic, next_tactic)

    async def assess_time_window(
        self,
        entity: Any,
        tactic: str,
        context: Optional[Dict] = None,
    ) -> str:
        if not self._llm_available:
            return self._fallback_time_window(tactic)

        entity_desc = f"类型:{getattr(entity, 'type', 'unknown')}, 值:{getattr(entity, 'value', 'unknown')}"
        context_str = ""
        if context:
            context_str = f"\n上下文: {json.dumps(context, ensure_ascii=False)[:500]}"

        prompt = (
            f"你是攻击时间线分析专家。请评估以下攻击阶段的时间窗口：\n\n"
            f"攻击实体: {entity_desc}\n"
            f"攻击阶段: {tactic}\n"
            f"{context_str}\n\n"
            f"请给出该攻击阶段在黑灰产场景下的典型时间窗口估计，"
            f"格式如'数小时内'、'1-3天'、'1-7天'等。只需返回时间窗口，不要其他内容。"
        )

        try:
            response = await asyncio.wait_for(
                self._llm.chat(prompt, temperature=0.3, max_tokens=64),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            if isinstance(response, dict):
                result = response.get("content", "").strip()
            else:
                result = str(response).strip()
            if result and len(result) < 30:
                return result
            return self._fallback_time_window(tactic)
        except asyncio.TimeoutError:
            logger.warning(f"LLM时间窗口评估超时({self.LLM_CALL_TIMEOUT}s)")
            return self._fallback_time_window(tactic)
        except Exception as exc:
            logger.warning(f"LLM时间窗口评估失败: {exc}")
            return self._fallback_time_window(tactic)

    async def generate_countermeasures(self, prediction: "PredictionResult") -> List[Dict]:
        if not self._llm_available:
            return self._fallback_countermeasures(prediction)

        steps_desc = "\n".join([
            f"- 步骤{p.step}: {p.technique_id}({p.technique_name}), 概率={p.probability:.2f}, 风险={p.risk_level}"
            for p in prediction.predictions[:5]
        ])

        prompt = (
            f"你是安全防御专家。请针对以下预测的攻击链生成针对性防御建议：\n\n"
            f"攻击实体: {prediction.entity_name}(ID: {prediction.entity_id})\n"
            f"预测置信度: {prediction.confidence:.2f}\n"
            f"预测步骤:\n{steps_desc}\n\n"
            f"请以JSON数组格式返回防御建议，每条建议包含:\n"
            f'- "technique_id": 针对的技术ID\n'
            f'- "countermeasure": 防御措施描述\n'
            f'- "priority": 优先级(critical/high/medium/low)\n'
            f'- "action_type": 行动类型(detect/prevent/contain/recover)\n'
            f"最多返回5条建议。"
        )

        try:
            response = await asyncio.wait_for(
                self._llm.generate_json(prompt, temperature=0.3),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            if isinstance(response, list):
                return response[:5]
            if isinstance(response, dict) and "countermeasures" in response:
                return response["countermeasures"][:5]
            return self._fallback_countermeasures(prediction)
        except asyncio.TimeoutError:
            logger.warning(f"LLM防御建议生成超时({self.LLM_CALL_TIMEOUT}s)")
            return self._fallback_countermeasures(prediction)
        except Exception as exc:
            logger.warning(f"LLM防御建议生成失败: {exc}")
            return self._fallback_countermeasures(prediction)

    def _fallback_reasoning(self, current_tactic: str, next_tactic: str) -> str:
        return f"基于MITRE ATT&CK马尔可夫链: {current_tactic}→{next_tactic}"

    def _fallback_time_window(self, tactic: str) -> str:
        windows = {
            "reconnaissance": "1-30天",
            "initial_access": "1-7天",
            "execution": "数小时内",
            "persistence": "1-3天",
            "privilege_escalation": "数小时内",
            "defense_evasion": "数小时内",
            "credential_access": "1-3天",
            "discovery": "1-7天",
            "lateral_movement": "1-14天",
            "collection": "1-7天",
            "command_and_control": "持续",
            "exfiltration": "1-3天",
            "impact": "数小时内",
        }
        return windows.get(tactic, "未知")

    def _fallback_countermeasures(self, prediction: "PredictionResult") -> List[Dict]:
        measures = []
        for pred in prediction.predictions[:3]:
            measures.append({
                "technique_id": pred.technique_id,
                "countermeasure": f"针对{pred.technique_name}加强监控和防御",
                "priority": pred.risk_level,
                "action_type": "detect",
            })
        return measures


class AttackChainPredictor:
    MAX_BFS_DEPTH = 4
    MAX_NEIGHBORS = 20
    PATTERN_MIN_LENGTH = 2
    SMOOTHING_ALPHA = 0.1
    MONTE_CARLO_SAMPLES = 100

    def __init__(self, vector_store: VectorStore, knowledge_graph: KnowledgeGraph, llm_service=None):
        self.vector_store = vector_store
        self.knowledge_graph = knowledge_graph
        self._llm = llm_service
        self._max_techniques = 500
        self._transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._technique_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._total_transitions = 0
        self._persist_dir = "./model_data/attack_chain"
        os.makedirs(self._persist_dir, exist_ok=True)
        self._load_model()

        self._dynamic_learner = DynamicTransitionLearner(self._persist_dir)
        self._dynamic_learner.load()
        self._llm_reasoner = LLMAttackReasoner(llm_service)

        self._prediction_history: List[Dict] = []
        self._actual_steps: List[Dict] = []
        self._accuracy_records: List[float] = []
        self._calibration_factor: float = 1.0

    def _load_model(self):
        model_path = os.path.join(self._persist_dir, "markov_chain.pkl")
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    data = pickle.load(f)
                self._transition_counts = defaultdict(lambda: defaultdict(int), data.get("transition_counts", {}))
                self._technique_counts = defaultdict(lambda: defaultdict(int), data.get("technique_counts", {}))
                self._total_transitions = data.get("total_transitions", 0)
                logger.info(f"Markov chain loaded: {self._total_transitions} transitions")
            except Exception as exc:
                logger.warning(f"Failed to load Markov chain: {exc}")

    def _save_model(self):
        model_path = os.path.join(self._persist_dir, "markov_chain.pkl")
        data = {
            "transition_counts": dict(self._transition_counts),
            "technique_counts": dict(self._technique_counts),
            "total_transitions": self._total_transitions,
        }
        with open(model_path, "wb") as f:
            pickle.dump(data, f)
        logger.info(f"Markov chain saved: {self._total_transitions} transitions")

    def train_from_graph(self):
        transitions_learned = 0
        if not self.knowledge_graph.graph or self.knowledge_graph.graph.number_of_nodes() == 0:
            logger.warning("Knowledge graph empty, using MITRE ATT&CK prior transitions")
            self._load_mitre_priors()
            return

        self._load_mitre_priors()

        tactic_entity_counts: Dict[str, int] = defaultdict(int)
        for node_id in self.knowledge_graph.graph.nodes():
            node_data = self.knowledge_graph.graph.nodes[node_id]
            entity_type = node_data.get("type", node_data.get("entity_type", "unknown"))
            tactic = ENTITY_TYPE_TO_TACTIC.get(entity_type, "unknown")
            if tactic != "unknown":
                tactic_entity_counts[tactic] += 1

        total_entities = sum(tactic_entity_counts.values()) or 1
        for src_tactic in list(self._transition_counts.keys()):
            for dst_tactic in list(self._transition_counts[src_tactic].keys()):
                obs_count = tactic_entity_counts.get(dst_tactic, 0)
                obs_freq = obs_count / total_entities
                boost = int(obs_freq * 50)
                if boost > 0:
                    self._transition_counts[src_tactic][dst_tactic] += boost
                    self._total_transitions += boost

        for source in self.knowledge_graph.graph.nodes():
            source_entity = self.knowledge_graph.graph.nodes[source]
            source_type = source_entity.get("type", source_entity.get("entity_type", "unknown"))
            source_tactic = ENTITY_TYPE_TO_TACTIC.get(source_type, "unknown")

            for _, target, data in self.knowledge_graph.graph.out_edges(source, data=True):
                target_entity = self.knowledge_graph.graph.nodes[target]
                target_type = target_entity.get("type", target_entity.get("entity_type", "unknown"))
                target_tactic = ENTITY_TYPE_TO_TACTIC.get(target_type, "unknown")

                if source_tactic != "unknown" and target_tactic != "unknown":
                    self._transition_counts[source_tactic][target_tactic] += 1
                    self._total_transitions += 1
                    transitions_learned += 1

                    relation_type = data.get("type", data.get("relation_type", "unknown"))
                    matching_techniques = [
                        tid for tid, tinfo in MITRE_TECHNIQUES.items()
                        if tinfo["tactic"] == target_tactic
                    ]
                    if matching_techniques:
                        self._technique_counts[target_tactic][relation_type] = len(matching_techniques)

        logger.info(f"Learned {transitions_learned} transitions from knowledge graph (adjusted with {sum(tactic_entity_counts.values())} entity observations)")
        if len(self._transition_counts) > self._max_techniques:
            oldest_key = next(iter(self._transition_counts))
            del self._transition_counts[oldest_key]
            self._technique_counts.pop(oldest_key, None)
        self._save_model()

        self._dynamic_learner.learn_from_graph(self.knowledge_graph)
        self._dynamic_learner.save()

    def _load_mitre_priors(self):
        for src_tactic, transitions in MITRE_TRANSITIONS.items():
            for dst_tactic, prob in transitions.items():
                count = int(prob * 100)
                self._transition_counts[src_tactic][dst_tactic] += count
                self._total_transitions += count
        logger.info(f"Loaded MITRE ATT&CK prior transitions: {self._total_transitions} total")
        self._save_model()

    def _get_transition_prob(self, from_tactic: str, to_tactic: str) -> float:
        dynamic_prob = self._dynamic_learner.get_posterior_prob(from_tactic, to_tactic)

        from_counts = self._transition_counts.get(from_tactic, {})
        total = sum(v for k, v in from_counts.items() if k != from_tactic)
        count = from_counts.get(to_tactic, 0)
        prior = MITRE_TRANSITIONS.get(from_tactic, {}).get(to_tactic, 0.01)
        if total == 0:
            empirical = 0.0
        else:
            empirical = count / total if total > 0 else 0.0
        blended = 0.6 * prior + 0.4 * empirical

        combined = 0.5 * blended + 0.5 * dynamic_prob
        combined *= self._calibration_factor
        return min(max(combined, 0.0), 1.0)

    def _predict_next_tactics(self, current_tactic: str, top_k: int = 3) -> List[Tuple[str, float]]:
        candidates = []
        all_probs = self._dynamic_learner.get_all_posterior_probs(current_tactic)
        for tactic in set(list(MITRE_TRANSITIONS.get(current_tactic, {}).keys()) + list(all_probs.keys())):
            if tactic == current_tactic:
                continue
            prob = self._get_transition_prob(current_tactic, tactic)
            candidates.append((tactic, prob))
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]

    def _get_techniques_for_tactic(self, tactic: str) -> List[Tuple[str, dict]]:
        return [
            (tid, tinfo) for tid, tinfo in MITRE_TECHNIQUES.items()
            if tinfo["tactic"] == tactic
        ]

    def _map_entity_to_tactic(self, entity_id: str) -> str:
        if entity_id in self.knowledge_graph.graph.nodes:
            entity_type = self.knowledge_graph.graph.nodes[entity_id].get("type", self.knowledge_graph.graph.nodes[entity_id].get("entity_type", "unknown"))
            return ENTITY_TYPE_TO_TACTIC.get(entity_type, "reconnaissance")
        return "reconnaissance"

    async def predict_next_steps(self, entity_id: str, depth: int = 3) -> PredictionResult:
        entity = await self.knowledge_graph.get_entity(entity_id)
        if not entity:
            return PredictionResult(entity_id=entity_id, entity_name="unknown")

        entity_name = entity.value
        current_tactic = self._map_entity_to_tactic(entity_id)
        next_tactics = self._predict_next_tactics(current_tactic, top_k=depth)

        patterns = await self._find_attack_patterns(entity_id, depth)
        pattern_count = len(patterns)

        graph_context = await self._build_graph_context(entity_id)

        predictions: List[PredictedStep] = []
        for step_idx, (tactic, tactic_prob) in enumerate(next_tactics):
            techniques = self._get_techniques_for_tactic(tactic)
            if not techniques:
                continue

            risk_weights = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
            technique_scores = []
            for tid, tinfo in techniques:
                risk = tinfo.get("risk", "medium")
                base_weight = risk_weights.get(risk, 1.0)
                graph_boost = 0.0
                tc = self._technique_counts.get(tactic, {})
                for rel_type, count in tc.items():
                    if rel_type and rel_type.lower() in tinfo["name"].lower():
                        graph_boost += count * 0.5
                score = base_weight + graph_boost
                technique_scores.append((tid, tinfo, score))

            technique_scores.sort(key=lambda x: x[2], reverse=True)
            top_technique = technique_scores[0]

            tid, tinfo, score = top_technique
            combined_prob = tactic_prob

            for pattern in patterns:
                if len(pattern) >= 2 and pattern[0] == entity_id:
                    for nid in pattern[1:]:
                        n_entity = await self.knowledge_graph.get_entity(nid)
                        if n_entity:
                            n_tactic = ENTITY_TYPE_TO_TACTIC.get(n_entity.type.value if hasattr(n_entity.type, 'value') else str(n_entity.type), "")
                            if n_tactic == tactic:
                                combined_prob = min(combined_prob * 1.3, 1.0)

            risk = tinfo.get("risk", "medium")
            other_techniques = [f"{t[0]}({t[1]['name']})" for t in technique_scores[1:4]]

            reasoning = await self._llm_reasoner.reason_about_prediction(
                entity, current_tactic, tactic, graph_context
            )
            if not reasoning or reasoning == self._llm_reasoner._fallback_reasoning(current_tactic, tactic):
                reasoning = f"基于MITRE ATT&CK马尔可夫链: {current_tactic}→{tactic}(P={tactic_prob:.3f}), 最可能技术{tid}属于{tactic}阶段" + (f", 其他可能技术: {', '.join(other_techniques)}" if other_techniques else "")

            time_window = await self._llm_reasoner.assess_time_window(entity, tactic, graph_context)

            predictions.append(PredictedStep(
                step=len(predictions) + 1,
                action=f"可能执行{tinfo['name']}({tid})",
                technique_id=tid,
                technique_name=tinfo["name"],
                probability=round(combined_prob, 3),
                reasoning=reasoning,
                related_entities=[entity_id],
                time_window=time_window,
                risk_level=risk,
            ))

        predictions.sort(key=lambda p: p.probability, reverse=True)

        overall_confidence = 0.0
        if predictions:
            overall_confidence = sum(p.probability for p in predictions) / len(predictions)
            if pattern_count > 0:
                overall_confidence = min(overall_confidence * (1 + 0.1 * min(pattern_count, 5)), 1.0)

        result = PredictionResult(
            entity_id=entity_id,
            entity_name=entity_name,
            predictions=predictions,
            confidence=overall_confidence,
            based_on_patterns=pattern_count,
        )

        self._prediction_history.append({
            "entity_id": entity_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "predicted_tactics": [(p.technique_id, p.probability) for p in predictions],
            "confidence": overall_confidence,
        })

        return result

    async def _build_graph_context(self, entity_id: str) -> Dict:
        context: Dict[str, Any] = {}
        if entity_id not in self.knowledge_graph.graph:
            return context

        node_data = self.knowledge_graph.graph.nodes[entity_id]
        context["entity_type"] = node_data.get("type", "unknown")
        context["entity_value"] = node_data.get("value", "")

        neighbors_out = []
        for _, target, data in self.knowledge_graph.graph.out_edges(entity_id, data=True):
            target_data = self.knowledge_graph.graph.nodes[target]
            neighbors_out.append({
                "target_type": target_data.get("type", "unknown"),
                "target_value": target_data.get("value", ""),
                "relation": data.get("type", data.get("relation_type", "unknown")),
            })
        context["outgoing_relations"] = neighbors_out[:10]

        neighbors_in = []
        for source, _, data in self.knowledge_graph.graph.in_edges(entity_id, data=True):
            source_data = self.knowledge_graph.graph.nodes[source]
            neighbors_in.append({
                "source_type": source_data.get("type", "unknown"),
                "source_value": source_data.get("value", ""),
                "relation": data.get("type", data.get("relation_type", "unknown")),
            })
        context["incoming_relations"] = neighbors_in[:10]

        return context

    def _estimate_time_window(self, tactic: str) -> str:
        windows = {
            "reconnaissance": "1-30天",
            "initial_access": "1-7天",
            "execution": "数小时内",
            "persistence": "1-3天",
            "privilege_escalation": "数小时内",
            "defense_evasion": "数小时内",
            "credential_access": "1-3天",
            "discovery": "1-7天",
            "lateral_movement": "1-14天",
            "collection": "1-7天",
            "command_and_control": "持续",
            "exfiltration": "1-3天",
            "impact": "数小时内",
        }
        return windows.get(tactic, "未知")

    async def _find_attack_patterns(self, entity_id: str, depth: int) -> List[List[str]]:
        if entity_id not in self.knowledge_graph.graph:
            return []

        patterns: List[List[str]] = []
        visited: set = set()
        queue = deque([(entity_id, [entity_id])])
        visited.add(entity_id)

        while queue and len(patterns) < 10:
            current_id, path = queue.popleft()
            if len(path) > depth + 1:
                continue

            if self.knowledge_graph.graph.out_degree(current_id) > 0:
                for _, neighbor, data in self.knowledge_graph.graph.out_edges(current_id, data=True):
                    if neighbor not in visited and len(visited) < self.MAX_NEIGHBORS:
                        new_path = path + [neighbor]
                        if len(new_path) >= self.PATTERN_MIN_LENGTH + 1:
                            patterns.append(new_path)
                        visited.add(neighbor)
                        queue.append((neighbor, new_path))

        return patterns

    async def simulate_attack_chain(self, start_entity_id: str, steps: int = 5, max_paths: int = 20) -> SimulatedChain:
        entity = await self.knowledge_graph.get_entity(start_entity_id)
        if not entity:
            return SimulatedChain(start_entity=start_entity_id)

        current_tactic = self._map_entity_to_tactic(start_entity_id)

        all_paths: List[Dict] = []
        critical_junctions: List[Dict] = []

        self._simulate_markov_chain(
            current_tactic=current_tactic,
            current_path=[],
            current_prob=1.0,
            remaining_steps=steps,
            all_paths=all_paths,
            critical_junctions=critical_junctions,
            visited_tactics=set(),
            max_paths=max_paths,
        )

        mc_paths = self._monte_carlo_simulation(current_tactic, steps, self.MONTE_CARLO_SAMPLES)
        for mc_path in mc_paths:
            path_steps = []
            for i, tactic in enumerate(mc_path["tactics"]):
                techniques = self._get_techniques_for_tactic(tactic)
                if not techniques:
                    continue
                best_technique = min(techniques, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[1]["risk"], 4))
                tid, tinfo = best_technique
                path_steps.append({
                    "action": f"执行{tinfo['name']}({tid})",
                    "technique_id": tid,
                    "technique_name": tinfo["name"],
                    "probability": mc_path["transition_probs"][i] if i < len(mc_path["transition_probs"]) else 0.0,
                    "reasoning": f"蒙特卡洛模拟: {tactic}(P={mc_path['transition_probs'][i]:.3f})" if i < len(mc_path["transition_probs"]) else f"蒙特卡洛模拟: {tactic}",
                    "time_window": self._estimate_time_window(tactic),
                    "risk_level": tinfo.get("risk", "medium"),
                    "related_entities": [],
                })
            all_paths.append({
                "steps": path_steps,
                "cumulative_probability": mc_path["cumulative_prob"],
                "simulation_method": "monte_carlo",
            })

        critical_junctions = self._identify_critical_junctions(mc_paths)

        max_prob_path: List[PredictedStep] = []
        if all_paths:
            best_path = max(all_paths, key=lambda p: p.get("cumulative_probability", 0))
            for i, step_data in enumerate(best_path.get("steps", [])):
                technique_id = step_data.get("technique_id", "")
                technique_info = MITRE_TECHNIQUES.get(technique_id, {})
                max_prob_path.append(PredictedStep(
                    step=i + 1,
                    action=step_data.get("action", ""),
                    technique_id=technique_id,
                    technique_name=technique_info.get("name", ""),
                    probability=step_data.get("probability", 0.0),
                    reasoning=step_data.get("reasoning", ""),
                    related_entities=step_data.get("related_entities", []),
                    time_window=step_data.get("time_window", ""),
                    risk_level=step_data.get("risk_level", "medium"),
                ))

        return SimulatedChain(
            start_entity=start_entity_id,
            paths=all_paths,
            critical_junctions=critical_junctions,
            max_probability_path=max_prob_path,
        )

    def _monte_carlo_simulation(
        self, start_tactic: str, max_steps: int, num_samples: int
    ) -> List[Dict]:
        paths: List[Dict] = []
        for _ in range(num_samples):
            tactics = [start_tactic]
            transition_probs = []
            current = start_tactic
            cum_prob = 1.0
            visited = {start_tactic}

            for _ in range(max_steps):
                all_probs = self._dynamic_learner.get_all_posterior_probs(current)
                candidates = {k: v for k, v in all_probs.items() if k != current and v > 0}
                if not candidates:
                    break

                tactics_list = list(candidates.keys())
                probs_list = list(candidates.values())
                prob_sum = sum(probs_list)
                if prob_sum == 0:
                    break
                normalized = [p / prob_sum for p in probs_list]

                chosen = random.choices(tactics_list, weights=normalized, k=1)[0]
                chosen_prob = candidates[chosen]
                transition_probs.append(chosen_prob)
                cum_prob *= chosen_prob

                if cum_prob < 0.01:
                    break

                tactics.append(chosen)
                visited.add(chosen)
                current = chosen

            paths.append({
                "tactics": tactics,
                "transition_probs": transition_probs,
                "cumulative_prob": cum_prob,
            })

        paths.sort(key=lambda p: p["cumulative_prob"], reverse=True)
        return paths[:50]

    def _identify_critical_junctions(self, mc_paths: List[Dict]) -> List[Dict]:
        junction_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for path in mc_paths:
            tactics = path["tactics"]
            for i in range(len(tactics) - 1):
                junction_stats[tactics[i]][tactics[i + 1]] += 1

        critical = []
        for src_tactic, destinations in junction_stats.items():
            total = sum(destinations.values())
            if total < 2:
                continue
            branches = sorted(destinations.items(), key=lambda x: x[1], reverse=True)
            if len(branches) >= 2:
                top_prob = branches[0][1] / total
                second_prob = branches[1][1] / total
                if second_prob >= 0.15:
                    critical.append({
                        "tactic": src_tactic,
                        "branch_count": len(branches),
                        "branches": [
                            {"tactic": t, "probability": c / total, "frequency": c}
                            for t, c in branches
                        ],
                        "entropy": -sum((c / total) * np.log2(c / total + 1e-10) for c in destinations.values()),
                    })

        critical.sort(key=lambda x: x.get("entropy", 0), reverse=True)
        return critical[:10]

    def _simulate_markov_chain(
        self,
        current_tactic: str,
        current_path: List[Dict],
        current_prob: float,
        remaining_steps: int,
        all_paths: List[Dict],
        critical_junctions: List[Dict],
        visited_tactics: set,
    ) -> None:
        if remaining_steps <= 0 or current_prob < 0.05:
            if current_path:
                all_paths.append({
                    "steps": current_path.copy(),
                    "cumulative_probability": current_prob,
                })
            return

        next_tactics = self._predict_next_tactics(current_tactic, top_k=3)

        if len(next_tactics) > 1:
            critical_junctions.append({
                "tactic": current_tactic,
                "step": len(current_path) + 1,
                "branch_count": len(next_tactics),
                "branches": [{"tactic": t, "probability": p} for t, p in next_tactics],
            })

        for tactic, tactic_prob in next_tactics:
            techniques = self._get_techniques_for_tactic(tactic)
            if not techniques:
                continue

            best_technique = min(techniques, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[1]["risk"], 4))
            tid, tinfo = best_technique

            new_prob = current_prob * tactic_prob
            step_data = {
                "action": f"执行{tinfo['name']}({tid})",
                "technique_id": tid,
                "technique_name": tinfo["name"],
                "probability": tactic_prob,
                "reasoning": f"马尔可夫链: {current_tactic}→{tactic}(P={tactic_prob:.3f})",
                "time_window": self._estimate_time_window(tactic),
                "risk_level": tinfo.get("risk", "medium"),
                "related_entities": [],
            }

            new_path = current_path + [step_data]

            if tactic not in visited_tactics:
                new_visited = visited_tactics | {tactic}
                self._simulate_markov_chain(
                    current_tactic=tactic,
                    current_path=new_path,
                    current_prob=new_prob,
                    remaining_steps=remaining_steps - 1,
                    all_paths=all_paths,
                    critical_junctions=critical_junctions,
                    visited_tactics=new_visited,
                )
            else:
                all_paths.append({
                    "steps": new_path,
                    "cumulative_probability": new_prob,
                })

    async def find_early_warning_signals(self, prediction: PredictionResult) -> List[EarlyWarning]:
        warnings: List[EarlyWarning] = []

        for pred in prediction.predictions:
            search_terms = [pred.technique_name, pred.technique_id, pred.action]
            for term in search_terms:
                try:
                    results = await self.vector_store.search_intelligence(term, n_results=3)
                    for result in results:
                        doc = result.get("document", "")
                        metadata = result.get("metadata", {})
                        if not doc:
                            continue

                        overlap = sum(1 for kw in pred.action.split() if kw in doc)
                        if overlap >= 1 or pred.technique_id in doc:
                            urgency = self._determine_urgency(pred, result)
                            actions = self._generate_recommended_actions(pred, urgency)
                            warnings.append(EarlyWarning(
                                predicted_step=pred.action,
                                signal_description=f"发现与{pred.technique_id}({pred.technique_name})相关的情报活动: {doc[:150]}",
                                signal_source=metadata.get("source", "unknown"),
                                urgency=urgency,
                                recommended_actions=actions,
                            ))
                except Exception:
                    pass

        llm_countermeasures = await self._llm_reasoner.generate_countermeasures(prediction)
        for cm in llm_countermeasures[:3]:
            tid = cm.get("technique_id", "")
            matching_pred = None
            for pred in prediction.predictions:
                if pred.technique_id == tid:
                    matching_pred = pred
                    break
            if matching_pred:
                warnings.append(EarlyWarning(
                    predicted_step=matching_pred.action,
                    signal_description=f"LLM防御建议: {cm.get('countermeasure', '')}",
                    signal_source="llm_analysis",
                    urgency="urgent" if cm.get("priority") in ("critical", "high") else "monitor",
                    recommended_actions=[cm.get("countermeasure", "")],
                ))

        seen = set()
        unique_warnings = []
        for w in warnings:
            key = (w.predicted_step, w.signal_source)
            if key not in seen:
                seen.add(key)
                unique_warnings.append(w)

        unique_warnings.sort(
            key=lambda w: {"immediate": 0, "urgent": 1, "monitor": 2}.get(w.urgency, 2)
        )
        return unique_warnings

    def _determine_urgency(self, step: PredictedStep, intel_result: Dict) -> str:
        if step.risk_level in ("critical", "high") and step.probability >= 0.7:
            return "immediate"
        if step.risk_level in ("critical", "high") or step.probability >= 0.6:
            return "urgent"
        return "monitor"

    def _generate_recommended_actions(self, step: PredictedStep, urgency: str) -> List[str]:
        actions: List[str] = []
        if urgency == "immediate":
            actions.append("立即启动应急响应流程")
            actions.append(f"针对{step.technique_id}({step.technique_name})加强监控")
            actions.append("通知相关安全团队")
        elif urgency == "urgent":
            actions.append(f"加强对{step.technique_name}相关指标的监控")
            actions.append("更新防御规则")
        else:
            actions.append(f"持续关注{step.technique_name}相关动态")
            actions.append("定期复查情报更新")
        if step.related_entities:
            actions.append(f"重点关注关联实体: {', '.join(step.related_entities[:5])}")
        return actions

    def record_actual_attack_step(self, entity_id: str, actual_step: str) -> None:
        actual_tactic = "unknown"
        for tid, tinfo in MITRE_TECHNIQUES.items():
            if tid == actual_step or tinfo["name"] == actual_step:
                actual_tactic = tinfo["tactic"]
                break

        if actual_tactic == "unknown":
            for tid, tinfo in MITRE_TECHNIQUES.items():
                if actual_step.lower() in tinfo["name"].lower() or actual_step.lower() in tid.lower():
                    actual_tactic = tinfo["tactic"]
                    break

        record = {
            "entity_id": entity_id,
            "actual_step": actual_step,
            "actual_tactic": actual_tactic,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._actual_steps.append(record)

        matching_predictions = [
            ph for ph in self._prediction_history
            if ph["entity_id"] == entity_id
        ]
        if matching_predictions and actual_tactic != "unknown":
            latest_pred = matching_predictions[-1]
            for pred_tid, pred_prob in latest_pred.get("predicted_tactics", []):
                pred_tactic = MITRE_TECHNIQUES.get(pred_tid, {}).get("tactic", "unknown")
                if pred_tactic == actual_tactic:
                    self._accuracy_records.append(1.0)
                    break
            else:
                self._accuracy_records.append(0.0)

        if actual_tactic != "unknown":
            entity_tactic = self._map_entity_to_tactic(entity_id)
            if entity_tactic != "unknown":
                self._dynamic_learner.incremental_update(entity_tactic, actual_tactic)
                self._dynamic_learner.save()

        logger.info(f"Recorded actual attack step: entity={entity_id}, step={actual_step}, tactic={actual_tactic}")

    def compute_prediction_accuracy(self) -> Dict:
        if not self._accuracy_records:
            return {
                "total_predictions": 0,
                "total_actuals": len(self._actual_steps),
                "accuracy": 0.0,
                "recent_accuracy": 0.0,
                "calibration_factor": self._calibration_factor,
            }

        total = len(self._accuracy_records)
        overall_accuracy = sum(self._accuracy_records) / total if total > 0 else 0.0

        recent_window = min(20, total)
        recent_records = self._accuracy_records[-recent_window:]
        recent_accuracy = sum(recent_records) / len(recent_records) if recent_records else 0.0

        return {
            "total_predictions": len(self._prediction_history),
            "total_actuals": len(self._actual_steps),
            "accuracy_records_count": total,
            "accuracy": round(overall_accuracy, 4),
            "recent_accuracy": round(recent_accuracy, 4),
            "calibration_factor": round(self._calibration_factor, 4),
            "dynamic_learner_observations": self._dynamic_learner.total_observations,
        }

    def auto_calibrate(self) -> Dict:
        accuracy_info = self.compute_prediction_accuracy()
        recent_accuracy = accuracy_info.get("recent_accuracy", 0.0)

        if len(self._accuracy_records) < 5:
            logger.info("Insufficient accuracy records for auto-calibration")
            return {
                "calibrated": False,
                "reason": "insufficient_data",
                "current_factor": self._calibration_factor,
                "accuracy": accuracy_info,
            }

        old_factor = self._calibration_factor

        if recent_accuracy < 0.3:
            self._calibration_factor = min(self._calibration_factor * 1.2, 2.0)
        elif recent_accuracy < 0.5:
            self._calibration_factor = min(self._calibration_factor * 1.1, 2.0)
        elif recent_accuracy > 0.8:
            self._calibration_factor = max(self._calibration_factor * 0.95, 0.5)
        elif recent_accuracy > 0.7:
            self._calibration_factor = max(self._calibration_factor * 0.98, 0.5)

        if len(self._accuracy_records) >= 10:
            recent = self._accuracy_records[-10:]
            recent_acc = sum(recent) / len(recent)
            if recent_acc < 0.2:
                self._dynamic_learner.learn_from_graph(self.knowledge_graph)
                self._dynamic_learner.save()
                logger.info("Auto-calibration triggered re-learning from knowledge graph due to low accuracy")

        logger.info(f"Auto-calibrated: factor {old_factor:.4f} -> {self._calibration_factor:.4f}, recent_accuracy={recent_accuracy:.4f}")

        return {
            "calibrated": True,
            "old_factor": round(old_factor, 4),
            "new_factor": round(self._calibration_factor, 4),
            "recent_accuracy": round(recent_accuracy, 4),
            "accuracy": accuracy_info,
        }
