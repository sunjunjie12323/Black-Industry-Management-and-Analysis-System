"""
Intelligence Fusion Engine for Threat Intelligence Platform.

Implements multi-source intelligence fusion with:
- TF-IDF + cosine similarity for semantic deduplication
- Dempster-Shafer theory for evidence combination
- Source reputation-weighted conflict resolution
- Provenance tracking for fused intelligence
"""

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import numpy as np
from loguru import logger


class EvidenceAggregator:
    """Implements Dempster's rule of combination for evidence fusion."""

    def combine(self, beliefs: list[dict]) -> dict:
        """
        Combine multiple belief assignments using Dempster's rule.
        
        Args:
            beliefs: List of belief assignments, each a dict mapping
                    hypothesis -> mass value. Each dict must include
                    the frame of discernment masses.
        
        Returns:
            Combined belief assignment dict.
        
        Algorithm:
            m_combined(A) = (m1(A) * m2(A)) / (1 - conflict_factor)
            conflict_factor = sum(m1(A) * m2(not_A)) for conflicting beliefs
        """
        if not beliefs:
            return {}
        
        if len(beliefs) == 1:
            return beliefs[0].copy()
        
        # Start with first belief
        combined = beliefs[0].copy()
        
        for i in range(1, len(beliefs)):
            next_belief = beliefs[i]
            conflict = self.calculate_conflict(combined, next_belief)
            
            # Normalize factor
            if conflict >= 1.0:
                logger.warning(f"Total conflict between evidence sources at step {i}")
                # Return uniform distribution as fallback
                all_hypotheses = set(combined.keys()) | set(next_belief.keys())
                uniform_mass = 1.0 / len(all_hypotheses) if all_hypotheses else 0.0
                return {h: uniform_mass for h in all_hypotheses}
            
            normalization = 1.0 - conflict
            new_combined = defaultdict(float)
            
            # Combine each pair of hypotheses
            for h1, m1 in combined.items():
                for h2, m2 in next_belief.items():
                    # Intersection of hypotheses
                    if h1 == h2:
                        # Same hypothesis - masses multiply
                        new_combined[h1] += m1 * m2
                    elif h1 == "theta" or h2 == "theta":
                        # Theta represents ignorance/uncertainty
                        # m(A) * m(theta) = m(A) (assigns to the specific hypothesis)
                        specific_h = h2 if h1 == "theta" else h1
                        new_combined[specific_h] += m1 * m2
                    else:
                        # Empty intersection - contributes to conflict
                        pass
            
            # Normalize by dividing by (1 - conflict)
            if normalization > 0:
                combined = {h: m / normalization for h, m in new_combined.items()}
            else:
                combined = dict(new_combined)
        
        return combined

    def calculate_conflict(self, belief_a: dict, belief_b: dict) -> float:
        """
        Calculate conflict factor between two belief assignments.
        
        Args:
            belief_a: First belief assignment
            belief_b: Second belief assignment
        
        Returns:
            Conflict factor between 0.0 (no conflict) and 1.0 (total conflict)
        
        Algorithm:
            conflict = sum(m1(A) * m2(B)) where A ∩ B = ∅
        """
        conflict = 0.0
        
        for h1, m1 in belief_a.items():
            for h2, m2 in belief_b.items():
                # Check if hypotheses conflict (empty intersection)
                if h1 != h2 and h1 != "theta" and h2 != "theta":
                    # These are mutually exclusive hypotheses
                    conflict += m1 * m2
        
        return min(conflict, 1.0)


class IntelligenceFusionEngine:
    """
    Main intelligence fusion engine combining multiple threat intelligence sources.
    
    Implements:
    - Semantic deduplication using TF-IDF + cosine similarity
    - Conflict resolution using source reputation and majority voting
    - Evidence aggregation using Dempster-Shafer theory
    - Contradiction detection
    - Provenance tracking
    """

    def __init__(self):
        self._evidence_aggregator = EvidenceAggregator()
        self._stopwords = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
            "for", "of", "with", "by", "from", "is", "was", "are", "were",
            "be", "been", "being", "have", "has", "had", "do", "does", "did",
            "will", "would", "could", "should", "may", "might", "can", "this",
            "that", "these", "those", "it", "its", "as", "not", "no", "nor"
        }
        logger.info("IntelligenceFusionEngine initialized")

    async def fuse_intelligence(self, items: list[dict]) -> dict:
        """
        Main fusion pipeline: deduplicate -> resolve_conflicts -> aggregate_evidence -> produce_fused_result.
        
        Args:
            items: List of intelligence items to fuse
        
        Returns:
            Dict containing:
            - fused_items: List of fused intelligence items
            - duplicates_removed: Count of duplicates removed
            - conflicts_resolved: Count of conflicts resolved
            - confidence_boost: Average confidence improvement
        """
        if not items:
            return {
                "fused_items": [],
                "duplicates_removed": 0,
                "conflicts_resolved": 0,
                "confidence_boost": 0.0
            }
        
        logger.info(f"Starting fusion pipeline with {len(items)} items")
        
        # Step 1: Semantic deduplication
        unique_items, duplicate_groups = self.semantic_deduplication(items)
        duplicates_removed = len(items) - len(unique_items)
        logger.info(f"Deduplication: {len(unique_items)} unique, {duplicates_removed} duplicates removed")
        
        # Step 2: Resolve conflicts in duplicate groups
        resolved_items = []
        conflicts_resolved = 0
        
        for group in duplicate_groups:
            if len(group) > 1:
                resolved = self.resolve_conflicts(group)
                resolved_items.append(resolved)
                conflicts_resolved += 1
        
        # Add items that had no duplicates
        resolved_items.extend(unique_items)
        
        # Step 3: Aggregate evidence for related items
        fused_items = []
        total_confidence_boost = 0.0
        
        # Group by entity/threat type for aggregation
        entity_groups = self._group_by_entity(resolved_items)
        
        for entity_key, group_items in entity_groups.items():
            if len(group_items) > 1:
                aggregated = self.aggregate_evidence(group_items)
                fused_item = self._create_fused_item(group_items, aggregated)
                fused_items.append(fused_item)
                
                # Calculate confidence boost
                original_confidences = [item.get("confidence", 0.5) for item in group_items]
                max_original = max(original_confidences) if original_confidences else 0.5
                new_confidence = fused_item.get("confidence", 0.5)
                total_confidence_boost += (new_confidence - max_original)
            else:
                fused_items.append(group_items[0])
        
        avg_confidence_boost = total_confidence_boost / len(entity_groups) if entity_groups else 0.0
        
        logger.info(f"Fusion complete: {len(fused_items)} items, {conflicts_resolved} conflicts resolved")
        
        return {
            "fused_items": fused_items,
            "duplicates_removed": duplicates_removed,
            "conflicts_resolved": conflicts_resolved,
            "confidence_boost": avg_confidence_boost
        }

    def semantic_deduplication(
        self, items: list[dict], threshold: float = 0.85
    ) -> tuple[list[dict], list[list[dict]]]:
        """
        Find semantically duplicate intelligence items using TF-IDF + cosine similarity.
        
        Args:
            items: List of intelligence items
            threshold: Cosine similarity threshold for considering items duplicates
        
        Returns:
            Tuple of (unique_items, duplicate_groups)
            Each duplicate group is a list of similar items
        """
        if not items:
            return [], []
        
        if len(items) == 1:
            return items, [items]
        
        # Extract text content from items
        texts = []
        for item in items:
            text_parts = []
            # Combine relevant text fields
            for field in ["title", "description", "content", "summary", "details"]:
                if item.get(field):
                    text_parts.append(str(item[field]))
            text = " ".join(text_parts)
            texts.append(text)
        
        # Build TF-IDF matrix
        tfidf_matrix = self._build_tfidf_matrix(texts)
        
        if tfidf_matrix is None or tfidf_matrix.shape[0] == 0:
            return items, [[item] for item in items]
        
        # Calculate cosine similarity matrix
        similarity_matrix = self._cosine_similarity_matrix(tfidf_matrix)
        
        # Find duplicate groups using connected components
        duplicate_groups = []
        visited = set()
        
        for i in range(len(items)):
            if i in visited:
                continue
            
            group = [items[i]]
            visited.add(i)
            
            for j in range(i + 1, len(items)):
                if j in visited:
                    continue
                
                if similarity_matrix[i, j] >= threshold:
                    group.append(items[j])
                    visited.add(j)
            
            duplicate_groups.append(group)
        
        # Unique items are the first item from each group
        unique_items = [group[0] for group in duplicate_groups]
        
        return unique_items, duplicate_groups

    def _build_tfidf_matrix(self, texts: list[str]) -> Optional[np.ndarray]:
        """Build TF-IDF matrix from text documents."""
        if not texts:
            return None
        
        # Tokenize and clean texts
        tokenized_docs = []
        for text in texts:
            tokens = self._tokenize(text)
            tokenized_docs.append(tokens)
        
        # Build vocabulary
        vocab = set()
        for doc in tokenized_docs:
            vocab.update(doc)
        
        if not vocab:
            return None
        
        vocab_list = sorted(vocab)
        word_to_idx = {word: idx for idx, word in enumerate(vocab_list)}
        
        n_docs = len(tokenized_docs)
        n_terms = len(vocab_list)
        
        # Calculate document frequency for each term
        df = np.zeros(n_terms)
        for doc in tokenized_docs:
            unique_terms = set(doc)
            for term in unique_terms:
                if term in word_to_idx:
                    df[word_to_idx[term]] += 1
        
        # Calculate IDF (with smoothing)
        idf = np.log((n_docs + 1) / (df + 1)) + 1
        
        # Build TF-IDF matrix
        tfidf_matrix = np.zeros((n_docs, n_terms))
        
        for i, doc in enumerate(tokenized_docs):
            if not doc:
                continue
            
            # Term frequency
            tf = Counter(doc)
            max_tf = max(tf.values()) if tf else 1
            
            for term, count in tf.items():
                if term in word_to_idx:
                    idx = word_to_idx[term]
                    # Normalized TF * IDF
                    tfidf_matrix[i, idx] = (count / max_tf) * idf[idx]
        
        # L2 normalize each row
        norms = np.linalg.norm(tfidf_matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1  # Avoid division by zero
        tfidf_matrix = tfidf_matrix / norms
        
        return tfidf_matrix

    def _cosine_similarity_matrix(self, matrix: np.ndarray) -> np.ndarray:
        """Calculate cosine similarity matrix. Assumes rows are already L2 normalized."""
        # Since rows are L2 normalized, dot product equals cosine similarity
        similarity = np.dot(matrix, matrix.T)
        # Clip to valid range
        similarity = np.clip(similarity, -1.0, 1.0)
        return similarity

    def _tokenize(self, text: str) -> list[str]:
        """Tokenize text into terms."""
        # Convert to lowercase
        text = text.lower()
        # Remove special characters but keep alphanumeric and spaces
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        # Split into words
        words = text.split()
        # Remove stopwords and short words
        tokens = [w for w in words if w not in self._stopwords and len(w) > 2]
        return tokens

    def resolve_conflicts(self, duplicate_group: list[dict]) -> dict:
        """
        Resolve conflicts when multiple sources report conflicting information.
        
        Uses:
        - Source reputation weighting
        - Majority voting for categorical fields
        - Weighted average for numerical fields
        - Most recent timestamp for temporal fields
        
        Args:
            duplicate_group: List of conflicting intelligence items
        
        Returns:
            Resolved item with confidence scores
        """
        if not duplicate_group:
            return {}
        
        if len(duplicate_group) == 1:
            return duplicate_group[0].copy()
        
        # Calculate source weights based on reputation
        weights = []
        for item in duplicate_group:
            reputation = item.get("source_reputation", item.get("source", {}).get("reputation", 0.5))
            if isinstance(reputation, str):
                reputation = {"high": 0.9, "medium": 0.6, "low": 0.3}.get(reputation.lower(), 0.5)
            weights.append(float(reputation))
        
        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in weights]
        else:
            normalized_weights = [1.0 / len(weights)] * len(weights)
        
        resolved = {}
        
        # Collect all keys from all items
        all_keys = set()
        for item in duplicate_group:
            all_keys.update(item.keys())
        
        # Resolve each field
        for key in all_keys:
            if key in ("id", "source_id", "source"):
                # Keep first non-null value
                for item in duplicate_group:
                    if item.get(key):
                        resolved[key] = item[key]
                        break
                continue
            
            values = [item.get(key) for item in duplicate_group if item.get(key) is not None]
            item_weights = [
                normalized_weights[i]
                for i, item in enumerate(duplicate_group)
                if item.get(key) is not None
            ]
            
            if not values:
                continue
            
            # Determine field type and resolve accordingly
            if self._is_temporal_field(key, values[0]):
                # Use most recent timestamp
                resolved[key] = self._resolve_temporal(values)
            
            elif self._is_numerical_field(key, values):
                # Weighted average for numerical fields
                resolved[key] = self._resolve_numerical(values, item_weights)
            
            elif self._is_categorical_field(key, values):
                # Majority voting for categorical fields
                resolved[key] = self._resolve_categorical(values, item_weights)
            
            else:
                # For other fields, use weighted selection or first value
                resolved[key] = values[0]
        
        # Add metadata
        resolved["id"] = str(uuid4())
        resolved["_fusion_metadata"] = {
            "source_count": len(duplicate_group),
            "original_ids": [item.get("id") for item in duplicate_group if item.get("id")],
            "fusion_method": "conflict_resolution",
            "fusion_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Calculate confidence based on agreement and source quality
        agreement = self._calculate_agreement(duplicate_group)
        avg_reputation = sum(weights) / len(weights) if weights else 0.5
        resolved["confidence"] = min(1.0, agreement * avg_reputation * 1.2)
        
        return resolved

    def _is_temporal_field(self, key: str, value: Any) -> bool:
        """Check if field is temporal."""
        temporal_keywords = ["time", "date", "timestamp", "created", "updated", "first_seen", "last_seen"]
        key_lower = key.lower()
        if any(kw in key_lower for kw in temporal_keywords):
            return True
        if isinstance(value, str):
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                return True
            except (ValueError, AttributeError):
                pass
        return False

    def _is_numerical_field(self, key: str, values: list) -> bool:
        """Check if field contains numerical values."""
        numerical_keywords = ["score", "confidence", "reputation", "count", "severity", "risk", "weight"]
        key_lower = key.lower()
        if any(kw in key_lower for kw in numerical_keywords):
            return all(isinstance(v, (int, float)) for v in values if v is not None)
        return all(isinstance(v, (int, float)) for v in values if v is not None) and len(values) > 0

    def _is_categorical_field(self, key: str, values: list) -> bool:
        """Check if field contains categorical values."""
        categorical_keywords = ["type", "category", "level", "status", "threat_level", "severity", "classification"]
        key_lower = key.lower()
        return any(kw in key_lower for kw in categorical_keywords)

    def _resolve_temporal(self, values: list) -> Any:
        """Resolve temporal field by taking most recent."""
        parsed_dates = []
        for v in values:
            try:
                if isinstance(v, str):
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                elif isinstance(v, datetime):
                    dt = v
                else:
                    continue
                parsed_dates.append((dt, v))
            except (ValueError, AttributeError):
                continue
        
        if parsed_dates:
            # Return the most recent
            parsed_dates.sort(key=lambda x: x[0], reverse=True)
            return parsed_dates[0][1]
        
        return values[0] if values else None

    def _resolve_numerical(self, values: list, weights: list) -> float:
        """Resolve numerical field using weighted average."""
        if not values:
            return 0.0
        
        # Ensure we have matching weights
        if len(weights) < len(values):
            weights = weights + [1.0 / len(values)] * (len(values) - len(weights))
        
        weights = weights[:len(values)]
        total_weight = sum(weights)
        
        if total_weight == 0:
            return sum(values) / len(values)
        
        weighted_sum = sum(v * w for v, w in zip(values, weights))
        return weighted_sum / total_weight

    def _resolve_categorical(self, values: list, weights: list) -> Any:
        """Resolve categorical field using weighted majority voting."""
        if not values:
            return None
        
        # Count weighted votes
        vote_counts = defaultdict(float)
        for value, weight in zip(values, weights):
            vote_counts[value] += weight
        
        # Return the value with highest weighted votes
        if vote_counts:
            return max(vote_counts.keys(), key=lambda k: vote_counts[k])
        
        return values[0]

    def _calculate_agreement(self, items: list[dict]) -> float:
        """Calculate agreement level among items."""
        if len(items) <= 1:
            return 1.0
        
        # Check agreement on key fields
        key_fields = ["threat_level", "type", "category", "severity", "classification"]
        agreements = []
        
        for field in key_fields:
            values = [item.get(field) for item in items if item.get(field) is not None]
            if len(values) >= 2:
                counter = Counter(values)
                most_common_count = counter.most_common(1)[0][1]
                agreement = most_common_count / len(values)
                agreements.append(agreement)
        
        return sum(agreements) / len(agreements) if agreements else 0.5

    def aggregate_evidence(self, related_items: list[dict]) -> dict:
        """
        Combine evidence from multiple sources using Dempster-Shafer theory.
        
        Args:
            related_items: List of related intelligence items
        
        Returns:
            Aggregated evidence with combined_confidence, source_count, agreement_level
        """
        if not related_items:
            return {
                "combined_confidence": 0.0,
                "source_count": 0,
                "agreement_level": 0.0,
                "evidence_items": []
            }
        
        # Extract belief assignments from items
        beliefs = []
        for item in related_items:
            belief = self._extract_belief(item)
            beliefs.append(belief)
        
        # Combine using Dempster's rule
        combined_belief = self._evidence_aggregator.combine(beliefs)
        
        # Calculate combined confidence
        individual_confidences = [item.get("confidence", 0.5) for item in related_items]
        agreement_level = self._calculate_agreement(related_items)
        
        combined_confidence = self.calculate_fusion_confidence(
            individual_confidences,
            len(related_items),
            agreement_level
        )
        
        # Calculate total conflict
        total_conflict = 0.0
        if len(beliefs) >= 2:
            for i in range(len(beliefs)):
                for j in range(i + 1, len(beliefs)):
                    total_conflict += self._evidence_aggregator.calculate_conflict(beliefs[i], beliefs[j])
            # Average conflict
            n_pairs = len(beliefs) * (len(beliefs) - 1) / 2
            total_conflict = total_conflict / n_pairs if n_pairs > 0 else 0.0
        
        return {
            "combined_confidence": combined_confidence,
            "source_count": len(related_items),
            "agreement_level": agreement_level,
            "conflict_factor": total_conflict,
            "combined_belief": combined_belief,
            "evidence_items": [item.get("id") for item in related_items if item.get("id")]
        }

    def _extract_belief(self, item: dict) -> dict:
        """Extract belief assignment from an intelligence item."""
        belief = {}
        
        # Map threat level to hypothesis masses
        threat_level = item.get("threat_level", item.get("severity", "medium"))
        confidence = item.get("confidence", 0.5)
        
        if isinstance(threat_level, str):
            threat_level = threat_level.lower()
            level_mapping = {
                "critical": 0.95,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.2,
                "info": 0.1,
                "informational": 0.1
            }
            threat_mass = level_mapping.get(threat_level, 0.5)
        else:
            threat_mass = float(threat_level) if threat_level else 0.5
        
        # Create belief assignment
        # The hypothesis is the threat assessment
        belief["threat_detected"] = threat_mass * confidence
        belief["no_threat"] = (1 - threat_mass) * confidence
        
        # Remaining mass is uncertainty (assigned to theta)
        belief["theta"] = 1.0 - confidence
        
        return belief

    def detect_contradictions(self, items: list[dict]) -> list[dict]:
        """
        Find items that directly contradict each other.
        
        Checks:
        - threat_level conflicts
        - entity attribute conflicts
        - timeline conflicts
        
        Args:
            items: List of intelligence items to check
        
        Returns:
            List of contradiction pairs with explanations
        """
        contradictions = []
        
        if len(items) < 2:
            return contradictions
        
        # Check all pairs
        for i, item_a in enumerate(items):
            for j, item_b in enumerate(items[i + 1:], start=i + 1):
                pair_contradictions = self._check_pair_contradiction(item_a, item_b)
                contradictions.extend(pair_contradictions)
        
        return contradictions

    def _check_pair_contradiction(self, item_a: dict, item_b: dict) -> list[dict]:
        """Check if two items contradict each other."""
        contradictions = []
        
        # Check threat level contradiction
        threat_a = item_a.get("threat_level", item_a.get("severity"))
        threat_b = item_b.get("threat_level", item_b.get("severity"))
        
        if threat_a and threat_b:
            threat_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            
            level_a = threat_order.get(str(threat_a).lower(), -1)
            level_b = threat_order.get(str(threat_b).lower(), -1)
            
            # Contradiction if difference is 2+ levels
            if level_a >= 0 and level_b >= 0 and abs(level_a - level_b) >= 2:
                contradictions.append({
                    "type": "threat_level_conflict",
                    "item_a_id": item_a.get("id"),
                    "item_b_id": item_b.get("id"),
                    "field": "threat_level",
                    "value_a": threat_a,
                    "value_b": threat_b,
                    "explanation": f"Threat level conflict: {threat_a} vs {threat_b}"
                })
        
        # Check entity attribute contradictions
        entity_fields = ["entity_type", "classification", "category", "status"]
        for field in entity_fields:
            val_a = item_a.get(field)
            val_b = item_b.get(field)
            
            if val_a and val_b and val_a != val_b:
                # Check if they are truly contradictory (not just different)
                if self._are_contradictory(field, val_a, val_b):
                    contradictions.append({
                        "type": "entity_attribute_conflict",
                        "item_a_id": item_a.get("id"),
                        "item_b_id": item_b.get("id"),
                        "field": field,
                        "value_a": val_a,
                        "value_b": val_b,
                        "explanation": f"Entity attribute conflict on {field}: {val_a} vs {val_b}"
                    })
        
        # Check timeline contradictions
        first_seen_a = item_a.get("first_seen")
        last_seen_a = item_a.get("last_seen")
        first_seen_b = item_b.get("first_seen")
        last_seen_b = item_b.get("last_seen")
        
        if all([first_seen_a, last_seen_a, first_seen_b, last_seen_b]):
            try:
                # Parse timestamps
                fs_a = self._parse_timestamp(first_seen_a)
                ls_a = self._parse_timestamp(last_seen_a)
                fs_b = self._parse_timestamp(first_seen_b)
                ls_b = self._parse_timestamp(last_seen_b)
                
                # Contradiction if timelines don't overlap and are far apart
                if ls_a and fs_b and ls_a < fs_b:
                    # Check if there's a significant gap
                    gap = (fs_b - ls_a).total_seconds()
                    if gap > 86400 * 30:  # More than 30 days gap
                        contradictions.append({
                            "type": "timeline_conflict",
                            "item_a_id": item_a.get("id"),
                            "item_b_id": item_b.get("id"),
                            "field": "timeline",
                            "value_a": f"{first_seen_a} to {last_seen_a}",
                            "value_b": f"{first_seen_b} to {last_seen_b}",
                            "explanation": f"Non-overlapping timelines with {gap / 86400:.0f} day gap"
                        })
            except (ValueError, AttributeError, TypeError):
                pass
        
        return contradictions

    def _are_contradictory(self, field: str, val_a: Any, val_b: Any) -> bool:
        """Check if two values are truly contradictory."""
        # Define known contradictory pairs
        contradictions_map = {
            "status": {
                "active": ["inactive", "resolved", "mitigated"],
                "inactive": ["active"],
                "resolved": ["active", "open"],
                "open": ["resolved", "closed"],
                "closed": ["open", "active"]
            },
            "entity_type": {
                "malware": ["benign", "legitimate"],
                "benign": ["malware", "threat"],
                "threat": ["benign", "safe"]
            }
        }
        
        if field in contradictions_map:
            val_a_lower = str(val_a).lower()
            val_b_lower = str(val_b).lower()
            
            contradictory_values = contradictions_map[field].get(val_a_lower, [])
            if val_b_lower in contradictory_values:
                return True
        
        return False

    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            
            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d/%m/%Y"
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        
        return None

    def calculate_fusion_confidence(
        self, individual_confidences: list[float], source_count: int, agreement_level: float
    ) -> float:
        """
        Calculate confidence boost from fusion.
        
        Algorithm:
        - base = max(individual_confidences)
        - boost = 1 - (1 - base) ^ source_count (independent evidence combination)
        - adjustment = boost * agreement_level
        
        Args:
            individual_confidences: List of confidence values from individual sources
            source_count: Number of sources
            agreement_level: Level of agreement between sources (0.0 to 1.0)
        
        Returns:
            Final confidence value between 0.0 and 1.0
        """
        if not individual_confidences:
            return 0.0
        
        # Base confidence is the maximum individual confidence
        base = max(individual_confidences)
        
        # Independent evidence combination formula
        # P(at least one correct) = 1 - P(all wrong)
        # Assuming independence: P(all wrong) = product(1 - p_i)
        # Simplified: boost = 1 - (1 - base)^n
        if source_count > 0:
            boost = 1.0 - math.pow(1.0 - base, source_count)
        else:
            boost = base
        
        # Adjust by agreement level
        adjustment = boost * agreement_level
        
        # Ensure result is in valid range
        final_confidence = max(0.0, min(1.0, adjustment))
        
        return final_confidence

    def build_provenance_graph(self, fused_item: dict, source_items: list[dict]) -> dict:
        """
        Track the lineage of fused intelligence.
        
        Args:
            fused_item: The fused intelligence item
            source_items: List of source items that contributed to the fusion
        
        Returns:
            Provenance graph showing source contributions
        """
        source_nodes = []
        contribution_edges = []
        confidence_flow = []
        
        fused_id = fused_item.get("id", str(uuid4()))
        
        for source_item in source_items:
            source_id = source_item.get("id", str(uuid4()))
            source_name = source_item.get("source", source_item.get("source_id", "unknown"))
            source_confidence = source_item.get("confidence", 0.5)
            
            # Create source node
            source_node = {
                "id": source_id,
                "type": "source",
                "name": str(source_name),
                "confidence": source_confidence,
                "timestamp": source_item.get("timestamp", source_item.get("created_at")),
                "reputation": source_item.get("source_reputation", 0.5)
            }
            source_nodes.append(source_node)
            
            # Determine what this source contributed
            contributions = self._identify_contributions(fused_item, source_item)
            
            # Create contribution edge
            edge = {
                "source_id": source_id,
                "target_id": fused_id,
                "type": "contributed_to",
                "contributions": contributions,
                "weight": source_confidence
            }
            contribution_edges.append(edge)
            
            # Track confidence flow
            flow = {
                "from": source_id,
                "to": fused_id,
                "initial_confidence": source_confidence,
                "final_contribution": source_confidence * len(contributions) / max(1, len(fused_item.keys()))
            }
            confidence_flow.append(flow)
        
        # Create fused item node
        fused_node = {
            "id": fused_id,
            "type": "fused",
            "confidence": fused_item.get("confidence", 0.5),
            "source_count": len(source_items),
            "fusion_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return {
            "fused_item": fused_node,
            "source_nodes": source_nodes,
            "contribution_edges": contribution_edges,
            "confidence_flow": confidence_flow,
            "total_sources": len(source_items)
        }

    def _identify_contributions(self, fused_item: dict, source_item: dict) -> list[str]:
        """Identify what fields a source item contributed to the fused item."""
        contributions = []
        
        # Skip metadata fields
        skip_fields = {"id", "_fusion_metadata", "fusion_timestamp"}
        
        for key in source_item.keys():
            if key in skip_fields:
                continue
            
            source_val = source_item.get(key)
            fused_val = fused_item.get(key)
            
            if source_val is not None and source_val == fused_val:
                contributions.append(key)
        
        return contributions

    async def fuse_stream(
        self, new_item: dict, existing_items: list[dict]
    ) -> dict:
        """
        Real-time fusion: integrate a new item with existing knowledge.
        
        Args:
            new_item: New intelligence item to integrate
            existing_items: List of existing intelligence items
        
        Returns:
            Dict containing:
            - action_taken: "duplicate", "supplement", "contradiction", or "new"
            - updated_items: List of items that were updated
            - new_fused_item: The resulting fused item (if applicable)
        """
        if not existing_items:
            # No existing items, just add the new one
            new_item["id"] = new_item.get("id", str(uuid4()))
            return {
                "action_taken": "new",
                "updated_items": [],
                "new_fused_item": new_item
            }
        
        # Check for semantic similarity with existing items
        all_items = existing_items + [new_item]
        unique_items, duplicate_groups = self.semantic_deduplication(all_items, threshold=0.80)
        
        # Find which group the new item belongs to
        new_item_group = None
        for group in duplicate_groups:
            if new_item in group:
                new_item_group = group
                break
        
        if new_item_group is None or len(new_item_group) == 1:
            # New item is unique
            new_item["id"] = new_item.get("id", str(uuid4()))
            return {
                "action_taken": "new",
                "updated_items": [],
                "new_fused_item": new_item
            }
        
        # Check if new item contradicts existing items
        contradictions = self.detect_contradictions(new_item_group)
        
        if contradictions:
            # Handle contradiction
            resolved = self.resolve_conflicts(new_item_group)
            return {
                "action_taken": "contradiction",
                "updated_items": [item.get("id") for item in new_item_group if item != new_item],
                "new_fused_item": resolved,
                "contradictions": contradictions
            }
        
        # Check if new item supplements existing items
        if len(new_item_group) > 1:
            # New item is a duplicate or supplement
            existing_in_group = [item for item in new_item_group if item != new_item]
            
            # Check if new item adds new information
            new_fields = self._find_new_fields(new_item, existing_in_group)
            
            if new_fields:
                # Supplement existing items
                fused = self.resolve_conflicts(new_item_group)
                fused["_fusion_metadata"] = {
                    "fusion_type": "supplement",
                    "new_fields_added": list(new_fields),
                    "fusion_timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                return {
                    "action_taken": "supplement",
                    "updated_items": [item.get("id") for item in existing_in_group],
                    "new_fused_item": fused
                }
            else:
                # Pure duplicate
                return {
                    "action_taken": "duplicate",
                    "updated_items": [item.get("id") for item in existing_in_group],
                    "new_fused_item": existing_in_group[0]
                }
        
        # Default: treat as new
        new_item["id"] = new_item.get("id", str(uuid4()))
        return {
            "action_taken": "new",
            "updated_items": [],
            "new_fused_item": new_item
        }

    def _find_new_fields(self, new_item: dict, existing_items: list[dict]) -> set[str]:
        """Find fields in new_item that add information not in existing items."""
        new_fields = set()
        skip_fields = {"id", "_fusion_metadata", "timestamp", "created_at"}
        
        for key, value in new_item.items():
            if key in skip_fields or value is None:
                continue
            
            # Check if any existing item has this field with same value
            is_new = True
            for existing in existing_items:
                if existing.get(key) == value:
                    is_new = False
                    break
            
            if is_new:
                new_fields.add(key)
        
        return new_fields

    def _group_by_entity(self, items: list[dict]) -> dict[str, list[dict]]:
        """Group intelligence items by entity they describe."""
        groups = defaultdict(list)
        
        for item in items:
            # Try to find entity identifier
            entity_key = (
                item.get("entity_id") or
                item.get("entity") or
                item.get("indicator") or
                item.get("ip") or
                item.get("domain") or
                item.get("hash") or
                item.get("threat_id") or
                item.get("id", str(uuid4()))
            )
            
            # Also consider type for grouping
            item_type = item.get("type", item.get("category", "unknown"))
            group_key = f"{entity_key}:{item_type}"
            
            groups[group_key].append(item)
        
        return dict(groups)

    def _create_fused_item(self, source_items: list[dict], aggregated: dict) -> dict:
        """Create a fused intelligence item from source items and aggregated evidence."""
        # Start with the highest confidence item as base
        base_item = max(source_items, key=lambda x: x.get("confidence", 0.5))
        fused = base_item.copy()
        
        # Update with aggregated evidence
        fused["confidence"] = aggregated.get("combined_confidence", base_item.get("confidence", 0.5))
        fused["source_count"] = aggregated.get("source_count", len(source_items))
        fused["agreement_level"] = aggregated.get("agreement_level", 0.5)
        
        # Add fusion metadata
        fused["id"] = str(uuid4())
        fused["_fusion_metadata"] = {
            "source_ids": [item.get("id") for item in source_items if item.get("id")],
            "source_count": len(source_items),
            "fusion_method": "evidence_aggregation",
            "fusion_timestamp": datetime.now(timezone.utc).isoformat(),
            "conflict_factor": aggregated.get("conflict_factor", 0.0)
        }
        
        return fused


# Singleton instance
intelligence_fusion_engine = IntelligenceFusionEngine()
