import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from loguru import logger

from app.core.vector_store import VectorStore


@dataclass
class ProvenanceRecord:
    id: str
    intelligence_id: str
    stage: str
    timestamp: str
    input_hash: str
    output_hash: str
    previous_record_id: Optional[str] = None
    previous_hash: Optional[str] = None
    chain_hash: Optional[str] = None
    algorithm_input: Optional[str] = None
    algorithm_output: Optional[str] = None
    confidence_before: Optional[float] = None
    confidence_after: Optional[float] = None
    operator: str = "automated"
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "intelligence_id": self.intelligence_id,
            "stage": self.stage,
            "timestamp": self.timestamp,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "previous_record_id": self.previous_record_id,
            "previous_hash": self.previous_hash,
            "chain_hash": self.chain_hash,
            "algorithm_input": self.algorithm_input,
            "algorithm_output": self.algorithm_output,
            "confidence_before": self.confidence_before,
            "confidence_after": self.confidence_after,
            "operator": self.operator,
            "metadata": self.metadata,
        }

    def content_for_hash(self) -> str:
        content_dict = {
            "id": self.id,
            "intelligence_id": self.intelligence_id,
            "stage": self.stage,
            "timestamp": self.timestamp,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "previous_record_id": self.previous_record_id,
            "algorithm_input": self.algorithm_input,
            "algorithm_output": self.algorithm_output,
            "confidence_before": self.confidence_before,
            "confidence_after": self.confidence_after,
            "operator": self.operator,
        }
        return json.dumps(content_dict, sort_keys=True, ensure_ascii=False, default=str)


@dataclass
class VerificationResult:
    intelligence_id: str
    is_valid: bool
    chain_length: int
    algorithm_contributions: int
    human_contributions: int
    automated_contributions: int
    tampered_steps: List[str] = field(default_factory=list)
    completeness: float = 0.0
    chain_hash_valid: bool = True

    def to_dict(self) -> dict:
        return {
            "intelligence_id": self.intelligence_id,
            "is_valid": self.is_valid,
            "chain_length": self.chain_length,
            "algorithm_contributions": self.algorithm_contributions,
            "human_contributions": self.human_contributions,
            "automated_contributions": self.automated_contributions,
            "tampered_steps": self.tampered_steps,
            "completeness": self.completeness,
            "chain_hash_valid": self.chain_hash_valid,
        }


@dataclass
class ConfidencePoint:
    stage: str
    confidence: float
    delta: float
    reason: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "confidence": self.confidence,
            "delta": self.delta,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


@dataclass
class HallucinationReport:
    intelligence_id: str
    hallucination_score: float = 0.0
    flagged_claims: List[Dict] = field(default_factory=list)
    unsupported_assertions: List[str] = field(default_factory=list)
    recommendation: str = ""

    @property
    def is_hallucination(self) -> bool:
        return self.hallucination_score > 0.5

    def to_dict(self) -> dict:
        return {
            "intelligence_id": self.intelligence_id,
            "hallucination_score": self.hallucination_score,
            "flagged_claims": self.flagged_claims,
            "unsupported_assertions": self.unsupported_assertions,
            "recommendation": self.recommendation,
            "is_hallucination": self.is_hallucination,
        }


@dataclass
class IntegrityProof:
    intelligence_id: str
    merkle_root: str
    leaf_hashes: List[str]
    proof_paths: Dict[str, List[Dict]]

    def to_dict(self) -> dict:
        return {
            "intelligence_id": self.intelligence_id,
            "merkle_root": self.merkle_root,
            "leaf_hashes": self.leaf_hashes,
            "proof_paths": self.proof_paths,
        }


class WORMLogger:
    def __init__(self, log_dir: str = "./model_data/provenance/worm_logs"):
        self._log_dir = log_dir
        os.makedirs(self._log_dir, exist_ok=True)
        self._current_log_path = os.path.join(self._log_dir, "provenance_worm.jsonl")

    def write_record(self, record: ProvenanceRecord) -> None:
        entry = record.to_dict()
        entry["_worm_written_at"] = datetime.now(timezone.utc).isoformat()
        entry["_worm_hash"] = self._compute_entry_hash(entry)

        if os.name == "nt" and os.path.exists(self._current_log_path):
            try:
                os.chmod(self._current_log_path, stat.S_IREAD | stat.S_IWRITE)
            except OSError:
                pass

        with open(self._current_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

        try:
            if os.name == "nt":
                os.chmod(self._current_log_path, stat.S_IREAD)
            else:
                os.chmod(self._current_log_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass

        logger.debug(f"WORM log entry written: record_id={record.id[:8]}")

    def query_worm_log(self, intelligence_id: str) -> List[Dict]:
        results = []
        if not os.path.exists(self._current_log_path):
            return results

        try:
            with open(self._current_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("intelligence_id") == intelligence_id:
                            results.append(entry)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.warning(f"WORM log query failed: {exc}")

        return results

    def verify_worm_integrity(self) -> Tuple[bool, List[str]]:
        errors = []
        if not os.path.exists(self._current_log_path):
            return True, []

        try:
            with open(self._current_log_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        stored_hash = entry.get("_worm_hash", "")
                        computed_hash = self._compute_entry_hash(entry)
                        if stored_hash != computed_hash:
                            errors.append(f"Line {line_num}: hash mismatch")
                    except json.JSONDecodeError:
                        errors.append(f"Line {line_num}: invalid JSON")
        except Exception as exc:
            errors.append(f"Read error: {exc}")

        return len(errors) == 0, errors

    @staticmethod
    def _compute_entry_hash(entry: Dict) -> str:
        hashable = {k: v for k, v in entry.items() if k != "_worm_hash"}
        serialized = json.dumps(hashable, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class MerkleTree:
    @staticmethod
    def build_tree(hashes: List[str]) -> str:
        if not hashes:
            return hashlib.sha256(b"").hexdigest()
        if len(hashes) == 1:
            return hashes[0]

        current_level = list(hashes)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)
            current_level = next_level

        return current_level[0]

    @staticmethod
    def generate_proof(hashes: List[str], index: int) -> List[Dict]:
        if not hashes or index >= len(hashes):
            return []

        proof = []
        current_level = list(hashes)
        current_index = index

        while len(current_level) > 1:
            next_level = []
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                if sibling_index < len(current_level):
                    proof.append({
                        "side": "right",
                        "hash": current_level[sibling_index],
                    })
                else:
                    proof.append({
                        "side": "right",
                        "hash": current_level[current_index],
                    })
            else:
                sibling_index = current_index - 1
                proof.append({
                    "side": "left",
                    "hash": current_level[sibling_index],
                })

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)

            current_index = current_index // 2
            current_level = next_level

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict], root_hash: str) -> bool:
        current = leaf_hash
        for step in proof:
            if step["side"] == "left":
                current = hashlib.sha256((step["hash"] + current).encode("utf-8")).hexdigest()
            else:
                current = hashlib.sha256((current + step["hash"]).encode("utf-8")).hexdigest()
        return current == root_hash


class ProvenanceChain:
    EXPECTED_STAGES = ["collected", "cleaned", "analyzed", "report_generated"]

    def __init__(self, vector_store: VectorStore, persist_dir: str = "./model_data/provenance"):
        self.vector_store = vector_store
        self._chains: Dict[str, List[ProvenanceRecord]] = {}
        self._records_by_id: Dict[str, ProvenanceRecord] = {}
        self._max_chains = 500
        self._max_records_per_chain = 100
        self._persist_dir = persist_dir
        self._worm_logger = WORMLogger(log_dir=os.path.join(persist_dir, "worm_logs"))
        os.makedirs(self._persist_dir, exist_ok=True)
        self._load_from_disk()

    @property
    def worm_logger(self) -> WORMLogger:
        return self._worm_logger

    @staticmethod
    def _compute_hash(data: dict) -> str:
        serialized = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_chain_hash(previous_hash: str, record_content: str) -> str:
        combined = previous_hash + record_content
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    async def record_provenance(
        self,
        intelligence_id: str,
        stage: str,
        input_data: dict,
        output_data: dict,
        algorithm_input: str = None,
        algorithm_output: str = None,
        confidence_before: float = None,
        confidence_after: float = None,
    ) -> ProvenanceRecord:
        input_hash = self._compute_hash(input_data)
        output_hash = self._compute_hash(output_data)

        previous_record_id = None
        previous_hash = "0" * 64

        if intelligence_id in self._chains and self._chains[intelligence_id]:
            last_record = self._chains[intelligence_id][-1]
            previous_record_id = last_record.id
            previous_hash = last_record.chain_hash or "0" * 64

        operator = "automated"
        if algorithm_input is not None or algorithm_output is not None:
            operator = "algorithm"
        elif stage == "collected":
            operator = "human"

        record = ProvenanceRecord(
            id=uuid4().hex,
            intelligence_id=intelligence_id,
            stage=stage,
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_hash=input_hash,
            output_hash=output_hash,
            previous_record_id=previous_record_id,
            previous_hash=previous_hash,
            chain_hash=None,
            algorithm_input=algorithm_input,
            algorithm_output=algorithm_output,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
            operator=operator,
            metadata={
                "input_data": input_data,
                "output_data": output_data,
            },
        )

        record.chain_hash = self._compute_chain_hash(previous_hash, record.content_for_hash())

        if intelligence_id not in self._chains:
            self._chains[intelligence_id] = []
            if len(self._chains) > self._max_chains:
                oldest_chain = next(iter(self._chains))
                for record in self._chains[oldest_chain]:
                    self._records_by_id.pop(record.id if hasattr(record, 'id') else str(record), None)
                del self._chains[oldest_chain]
        self._chains[intelligence_id].append(record)
        if len(self._chains[intelligence_id]) > self._max_records_per_chain:
            self._chains[intelligence_id] = self._chains[intelligence_id][-self._max_records_per_chain:]
        self._records_by_id[record.id] = record

        self._worm_logger.write_record(record)

        logger.info(
            f"Recorded provenance: {intelligence_id} stage={stage} "
            f"operator={operator} record_id={record.id[:8]} chain_hash={record.chain_hash[:16]}"
        )
        return record

    async def verify_provenance(self, intelligence_id: str) -> VerificationResult:
        chain = self._chains.get(intelligence_id, [])

        if not chain:
            return VerificationResult(
                intelligence_id=intelligence_id,
                is_valid=False,
                chain_length=0,
                algorithm_contributions=0,
                human_contributions=0,
                automated_contributions=0,
                tampered_steps=[],
                completeness=0.0,
                chain_hash_valid=False,
            )

        tampered_steps: List[str] = []
        algorithm_count = 0
        human_count = 0
        automated_count = 0
        chain_hash_valid = True

        for i, record in enumerate(chain):
            if record.operator == "algorithm":
                algorithm_count += 1
            elif record.operator == "human":
                human_count += 1
            else:
                automated_count += 1

            stored_input_hash = record.input_hash
            stored_output_hash = record.output_hash
            recomputed_input_hash = self._compute_hash(record.metadata.get("input_data", {}))
            recomputed_output_hash = self._compute_hash(record.metadata.get("output_data", {}))

            if stored_input_hash != recomputed_input_hash:
                tampered_steps.append(
                    f"stage={record.stage} record={record.id[:8]}: input_hash mismatch"
                )
            if stored_output_hash != recomputed_output_hash:
                tampered_steps.append(
                    f"stage={record.stage} record={record.id[:8]}: output_hash mismatch"
                )

            if i > 0 and record.previous_record_id != chain[i - 1].id:
                tampered_steps.append(
                    f"stage={record.stage} record={record.id[:8]}: chain link broken"
                )

            if i == 0:
                expected_previous_hash = "0" * 64
            else:
                expected_previous_hash = chain[i - 1].chain_hash or "0" * 64

            if record.previous_hash != expected_previous_hash:
                tampered_steps.append(
                    f"stage={record.stage} record={record.id[:8]}: previous_hash mismatch"
                )
                chain_hash_valid = False

            expected_chain_hash = self._compute_chain_hash(
                record.previous_hash or "0" * 64,
                record.content_for_hash(),
            )
            if record.chain_hash != expected_chain_hash:
                tampered_steps.append(
                    f"stage={record.stage} record={record.id[:8]}: chain_hash verification failed"
                )
                chain_hash_valid = False

        stages_present = {r.stage for r in chain}
        expected_present = stages_present & set(self.EXPECTED_STAGES)
        completeness = len(expected_present) / len(self.EXPECTED_STAGES) if self.EXPECTED_STAGES else 0.0

        is_valid = len(tampered_steps) == 0

        return VerificationResult(
            intelligence_id=intelligence_id,
            is_valid=is_valid,
            chain_length=len(chain),
            algorithm_contributions=algorithm_count,
            human_contributions=human_count,
            automated_contributions=automated_count,
            tampered_steps=tampered_steps,
            completeness=completeness,
            chain_hash_valid=chain_hash_valid,
        )

    def verify_chain_integrity(self, intelligence_id: str) -> Tuple[bool, List[str]]:
        chain = self._chains.get(intelligence_id, [])
        if not chain:
            return False, ["No chain found"]

        errors = []
        for i, record in enumerate(chain):
            if i == 0:
                expected_prev = "0" * 64
            else:
                expected_prev = chain[i - 1].chain_hash or "0" * 64

            if record.previous_hash != expected_prev:
                errors.append(f"Record {i} ({record.id[:8]}): previous_hash mismatch")

            expected_chain_hash = self._compute_chain_hash(
                record.previous_hash or "0" * 64,
                record.content_for_hash(),
            )
            if record.chain_hash != expected_chain_hash:
                errors.append(f"Record {i} ({record.id[:8]}): chain_hash verification failed")

        return len(errors) == 0, errors

    def generate_integrity_proof(self, intelligence_id: str) -> Optional[IntegrityProof]:
        chain = self._chains.get(intelligence_id, [])
        if not chain:
            return None

        leaf_hashes = []
        for record in chain:
            leaf_hash = record.chain_hash or self._compute_chain_hash(
                record.previous_hash or "0" * 64,
                record.content_for_hash(),
            )
            leaf_hashes.append(leaf_hash)

        merkle_root = MerkleTree.build_tree(leaf_hashes)

        proof_paths = {}
        for i, record in enumerate(chain):
            proof = MerkleTree.generate_proof(leaf_hashes, i)
            proof_paths[record.id] = proof

        return IntegrityProof(
            intelligence_id=intelligence_id,
            merkle_root=merkle_root,
            leaf_hashes=leaf_hashes,
            proof_paths=proof_paths,
        )

    def verify_batch_integrity(self, intelligence_ids: List[str]) -> Dict[str, Dict]:
        results = {}
        for intel_id in intelligence_ids:
            proof = self.generate_integrity_proof(intel_id)
            chain = self._chains.get(intel_id, [])

            if not proof or not chain:
                results[intel_id] = {
                    "valid": False,
                    "error": "No chain or proof found",
                    "record_count": 0,
                }
                continue

            all_verified = True
            for i, record in enumerate(chain):
                leaf_hash = proof.leaf_hashes[i]
                proof_path = proof.proof_paths.get(record.id, [])
                if not MerkleTree.verify_proof(leaf_hash, proof_path, proof.merkle_root):
                    all_verified = False
                    break

            chain_valid, chain_errors = self.verify_chain_integrity(intel_id)

            results[intel_id] = {
                "valid": all_verified and chain_valid,
                "merkle_root": proof.merkle_root,
                "record_count": len(chain),
                "chain_hash_valid": chain_valid,
                "chain_errors": chain_errors,
            }

        return results

    async def get_confidence_evolution(
        self, intelligence_id: str
    ) -> List[ConfidencePoint]:
        chain = self._chains.get(intelligence_id, [])

        if not chain:
            return []

        evolution: List[ConfidencePoint] = []
        prev_confidence = None

        for record in chain:
            confidence = record.confidence_after
            if confidence is None:
                confidence = record.confidence_before

            delta = 0.0
            if prev_confidence is not None and confidence is not None:
                delta = confidence - prev_confidence

            reason = self._infer_confidence_reason(record, delta)

            evolution.append(ConfidencePoint(
                stage=record.stage,
                confidence=confidence if confidence is not None else 0.0,
                delta=delta,
                reason=reason,
                timestamp=record.timestamp,
            ))

            if confidence is not None:
                prev_confidence = confidence

        return evolution

    def _infer_confidence_reason(self, record: ProvenanceRecord, delta: float) -> str:
        if record.stage == "collected":
            return "初始采集，设定基线置信度"
        if record.stage == "cleaned":
            if delta > 0:
                return "数据清洗后质量提升"
            elif delta < 0:
                return "数据清洗发现噪声，降低置信度"
            return "数据清洗完成，置信度不变"
        if record.stage == "analyzed":
            if delta > 0:
                return "分析发现更多支持证据"
            elif delta < 0:
                return "分析发现矛盾信息"
            return "分析完成，置信度不变"
        if record.stage == "report_generated":
            if delta > 0:
                return "报告生成时交叉验证通过"
            elif delta < 0:
                return "报告生成时发现不确定性"
            return "报告生成完成"
        if delta > 0:
            return f"{record.stage}阶段置信度提升"
        elif delta < 0:
            return f"{record.stage}阶段置信度下降"
        return f"{record.stage}阶段置信度不变"

    async def detect_hallucination(self, intelligence_id: str) -> HallucinationReport:
        chain = self._chains.get(intelligence_id, [])

        if not chain:
            return HallucinationReport(
                intelligence_id=intelligence_id,
                hallucination_score=0.0,
                recommendation="无溯源记录，无法检测幻觉",
            )

        flagged_claims: List[Dict] = []
        unsupported_assertions: List[str] = []
        total_algorithm_steps = 0
        hallucinated_steps = 0

        for record in chain:
            if record.operator != "algorithm":
                continue

            total_algorithm_steps += 1

            if not record.algorithm_output:
                continue

            input_data = record.metadata.get("input_data", {})
            input_text = json.dumps(input_data, ensure_ascii=False, default=str)[:2000]
            output_data = record.metadata.get("output_data", {})
            output_text = json.dumps(output_data, ensure_ascii=False, default=str)[:2000]

            claim_check = self._algorithmic_verify_claim(
                record.algorithm_output, input_text
            )

            if claim_check.get("is_hallucinated", False):
                hallucinated_steps += 1
                flagged_claims.append({
                    "claim": record.algorithm_output[:300],
                    "evidence_for": claim_check.get("evidence_for", ""),
                    "evidence_against": claim_check.get("evidence_against", ""),
                    "verdict": "likely_hallucinated",
                    "stage": record.stage,
                    "record_id": record.id[:8],
                })
                unsupported_assertions.append(record.algorithm_output[:200])

            if record.confidence_before is not None and record.confidence_after is not None:
                delta = record.confidence_after - record.confidence_before
                if delta > 0.3 and claim_check.get("overlap_ratio", 0) < 0.15:
                    hallucinated_steps += 1
                    flagged_claims.append({
                        "claim": f"置信度异常跳升 {delta:.2f}，但输出与输入重叠率低",
                        "evidence_for": f"输入输出重叠率: {claim_check.get('overlap_ratio', 0):.2f}",
                        "evidence_against": f"置信度变化: {record.confidence_before:.2f} → {record.confidence_after:.2f}",
                        "verdict": "suspicious_confidence_delta",
                        "stage": record.stage,
                        "record_id": record.id[:8],
                    })

        hallucination_score = 0.0
        if total_algorithm_steps > 0:
            hallucination_score = hallucinated_steps / total_algorithm_steps

        recommendation = self._generate_hallucination_recommendation(
            hallucination_score, len(flagged_claims)
        )

        return HallucinationReport(
            intelligence_id=intelligence_id,
            hallucination_score=hallucination_score,
            flagged_claims=flagged_claims,
            unsupported_assertions=unsupported_assertions,
            recommendation=recommendation,
        )

    def _algorithmic_verify_claim(self, claim: str, source_data: str) -> dict:
        claim_entities = self._extract_entities(claim)
        source_entities = self._extract_entities(source_data)

        claim_words = set(claim.split())
        source_words = set(source_data.split())
        word_overlap = claim_words & source_words
        word_overlap_ratio = len(word_overlap) / len(claim_words) if claim_words else 0.0

        claim_bigrams = self._extract_ngrams(claim, 2)
        source_bigrams = self._extract_ngrams(source_data, 2)
        bigram_overlap = claim_bigrams & source_bigrams
        bigram_overlap_ratio = len(bigram_overlap) / len(claim_bigrams) if claim_bigrams else 0.0

        entity_match_count = 0
        unmatched_entities = []
        for entity in claim_entities:
            if entity in source_entities:
                entity_match_count += 1
            else:
                unmatched_entities.append(entity)

        entity_match_ratio = entity_match_count / len(claim_entities) if claim_entities else 1.0

        combined_score = (
            word_overlap_ratio * 0.3
            + bigram_overlap_ratio * 0.3
            + entity_match_ratio * 0.4
        )

        is_hallucinated = combined_score < 0.2

        evidence_for = ""
        evidence_against = ""

        if not is_hallucinated:
            parts = []
            if word_overlap_ratio > 0:
                parts.append(f"词汇重叠率: {word_overlap_ratio:.2f}")
            if bigram_overlap_ratio > 0:
                parts.append(f"二元组重叠率: {bigram_overlap_ratio:.2f}")
            if entity_match_ratio > 0:
                parts.append(f"实体匹配率: {entity_match_ratio:.2f}")
            evidence_for = "; ".join(parts)
        else:
            parts = []
            if word_overlap_ratio < 0.15:
                parts.append(f"词汇重叠率过低: {word_overlap_ratio:.2f}")
            if bigram_overlap_ratio < 0.1:
                parts.append(f"二元组重叠率过低: {bigram_overlap_ratio:.2f}")
            if unmatched_entities:
                parts.append(f"未匹配实体: {', '.join(unmatched_entities[:5])}")
            evidence_against = "; ".join(parts)

        return {
            "is_hallucinated": is_hallucinated,
            "evidence_for": evidence_for,
            "evidence_against": evidence_against,
            "overlap_ratio": word_overlap_ratio,
            "bigram_overlap_ratio": bigram_overlap_ratio,
            "entity_match_ratio": entity_match_ratio,
        }

    def _extract_entities(self, text: str) -> List[str]:
        entities = []

        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities.extend(re.findall(ipv4_pattern, text))

        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        entities.extend(re.findall(hash_pattern, text))

        url_pattern = r'https?://[^\s<>"\']+(?:\.[^\s<>"\']+)+'
        entities.extend(re.findall(url_pattern, text))

        cve_pattern = r'CVE-\d{4}-\d{4,}'
        entities.extend(re.findall(cve_pattern, text))

        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cn|ru|tk|top|xyz|info|biz)\b'
        entities.extend(re.findall(domain_pattern, text))

        email_pattern = r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b'
        entities.extend(re.findall(email_pattern, text))

        return list(dict.fromkeys(entities))

    def _extract_ngrams(self, text: str, n: int) -> set:
        words = text.split()
        if len(words) < n:
            return set()
        return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}

    def _generate_hallucination_recommendation(
        self, score: float, flagged_count: int
    ) -> str:
        if score == 0.0:
            return "未检测到幻觉，所有LLM生成内容均有源数据支持"
        if score < 0.3:
            return f"低风险：少量内容可能存在幻觉（{flagged_count}处），建议人工复核"
        if score < 0.6:
            return f"中等风险：部分内容可能存在幻觉（{flagged_count}处），建议重新分析并补充证据"
        return f"高风险：大量内容可能存在幻觉（{flagged_count}处），强烈建议重新进行完整分析"

    def get_chain(self, intelligence_id: str) -> List[ProvenanceRecord]:
        return self._chains.get(intelligence_id, [])

    def get_record(self, record_id: str) -> Optional[ProvenanceRecord]:
        return self._records_by_id.get(record_id)

    def _load_from_disk(self) -> bool:
        path = os.path.join(self._persist_dir, "provenance_data.json")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for intel_id, records_data in data.get("chains", {}).items():
                chain = []
                for rd in records_data:
                    record = ProvenanceRecord(
                        id=rd["id"],
                        intelligence_id=rd["intelligence_id"],
                        stage=rd["stage"],
                        timestamp=rd["timestamp"],
                        input_hash=rd["input_hash"],
                        output_hash=rd["output_hash"],
                        previous_record_id=rd.get("previous_record_id"),
                        previous_hash=rd.get("previous_hash"),
                        chain_hash=rd.get("chain_hash"),
                        algorithm_input=rd.get("algorithm_input"),
                        algorithm_output=rd.get("algorithm_output"),
                        confidence_before=rd.get("confidence_before"),
                        confidence_after=rd.get("confidence_after"),
                        operator=rd.get("operator", "automated"),
                        metadata=rd.get("metadata", {}),
                    )
                    chain.append(record)
                    self._records_by_id[record.id] = record
                self._chains[intel_id] = chain
            logger.info(f"ProvenanceChain loaded {len(self._chains)} chains from disk")
            return True
        except Exception as exc:
            logger.warning(f"Failed to load provenance data: {exc}")
            return False

    def save_to_disk(self):
        path = os.path.join(self._persist_dir, "provenance_data.json")
        try:
            chains_data = {}
            for intel_id, chain in self._chains.items():
                chains_data[intel_id] = [r.to_dict() for r in chain]
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"chains": chains_data}, f, ensure_ascii=False, default=str)
            logger.info(f"ProvenanceChain saved {len(self._chains)} chains to disk")
        except Exception as exc:
            logger.warning(f"Failed to save provenance data: {exc}")

    async def ensure_provenance_for_intelligence(self, intelligence_items: List[Dict]):
        new_count = 0
        for item in intelligence_items:
            intel_id = item.get("id", "")
            if not intel_id:
                continue
            if intel_id in self._chains and self._chains[intel_id]:
                continue

            source = item.get("source", "unknown")
            content = item.get("content", "")
            intel_type = item.get("type", "raw")

            await self.record_provenance(
                intelligence_id=intel_id,
                stage="collected",
                input_data={"source": source, "type": intel_type},
                output_data={"content": content[:500]},
                confidence_before=None,
                confidence_after=0.7,
            )

            if intel_type in ("cleaned", "analyzed"):
                await self.record_provenance(
                    intelligence_id=intel_id,
                    stage="cleaned",
                    input_data={"content": content[:500]},
                    output_data={"cleaned": True},
                    confidence_before=0.7,
                    confidence_after=0.8,
                )

            if intel_type == "analyzed":
                await self.record_provenance(
                    intelligence_id=intel_id,
                    stage="analyzed",
                    input_data={"cleaned": True},
                    output_data={"analysis": "completed"},
                    algorithm_input=f"analyze_{source}",
                    algorithm_output=f"threat_intelligence_from_{source}",
                    confidence_before=0.8,
                    confidence_after=0.85,
                )

            new_count += 1

        if new_count > 0:
            self.save_to_disk()
            logger.info(f"ProvenanceChain: auto-generated records for {new_count} intelligence items")
