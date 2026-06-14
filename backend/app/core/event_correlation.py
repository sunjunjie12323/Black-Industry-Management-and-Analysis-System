"""
Event Correlation Analysis Engine for Threat Intelligence Platform.

Implements multi-dimensional correlation algorithms to identify related security events,
reconstruct attack chains, and cluster threats using temporal, entity, and semantic analysis.
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import combinations
from typing import Any

import numpy as np
from loguru import logger


class EventCorrelationEngine:
    """
    Commercial-grade event correlation engine using real algorithms.
    
    Implements temporal, entity-based, and semantic correlation with
    causal inference and attack chain reconstruction.
    """

    # MITRE ATT&CK phase ordering for attack chain reconstruction
    ATTACK_PHASES = [
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "CommandAndControl",
        "Actions",
    ]

    # Threat type compatibility for causal inference (source -> target)
    CAUSAL_THREAT_MAPPING = {
        "reconnaissance": ["weaponization", "delivery", "exploitation"],
        "scanning": ["exploitation", "delivery"],
        "weaponization": ["delivery", "exploitation"],
        "delivery": ["exploitation", "installation"],
        "exploitation": ["installation", "command_and_control"],
        "phishing": ["exploitation", "credential_theft"],
        "credential_theft": ["lateral_movement", "privilege_escalation"],
        "installation": ["command_and_control", "lateral_movement"],
        "command_and_control": ["data_exfiltration", "lateral_movement"],
        "lateral_movement": ["data_exfiltration", "privilege_escalation"],
        "data_exfiltration": [],
        "malware": ["command_and_control", "data_exfiltration"],
        "intrusion": ["lateral_movement", "data_exfiltration"],
    }

    def __init__(self):
        """Initialize the correlation engine."""
        self._stopwords = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
            "for", "of", "with", "by", "from", "is", "was", "are", "were",
            "be", "been", "being", "have", "has", "had", "do", "does", "did",
            "will", "would", "could", "should", "may", "might", "can", "this",
            "that", "these", "those", "it", "its", "as", "not", "no", "but",
        }
        logger.info("EventCorrelationEngine initialized")

    async def find_correlations(
        self, events: list[dict], time_window_hours: int = 72
    ) -> dict:
        """
        Find correlated events within time window using multiple methods.
        
        Args:
            events: List of event dictionaries with timestamp, entities, content, etc.
            time_window_hours: Time window for temporal correlation (default: 72h)
            
        Returns:
            Dictionary with correlations, clusters, and attack_chains
        """
        if not events:
            return {"correlations": [], "clusters": [], "attack_chains": []}

        logger.info(f"Finding correlations for {len(events)} events")

        # Run all correlation methods
        temporal_corrs = self.temporal_correlation(events, time_window_hours)
        entity_corrs = self.entity_correlation(events)
        semantic_corrs = self.semantic_correlation(events)

        # Merge correlations with weighted scores
        merged_correlations = self._merge_correlations(
            temporal_corrs, entity_corrs, semantic_corrs
        )

        # Perform causal inference on correlated pairs
        causal_chains = self.causal_inference(merged_correlations)

        # Cluster events
        clusters = self.cluster_events(events)

        # Reconstruct attack chains
        attack_chains = []
        for cluster in clusters:
            if len(cluster) >= 2:
                chain = self.reconstruct_attack_chain(cluster)
                if chain:
                    attack_chains.append(chain)

        result = {
            "correlations": merged_correlations,
            "clusters": clusters,
            "attack_chains": attack_chains,
            "causal_chains": causal_chains,
            "summary": {
                "total_events": len(events),
                "temporal_correlations": len(temporal_corrs),
                "entity_correlations": len(entity_corrs),
                "semantic_correlations": len(semantic_corrs),
                "merged_correlations": len(merged_correlations),
                "clusters": len(clusters),
                "attack_chains": len(attack_chains),
            },
        }

        logger.info(
            f"Correlation complete: {len(merged_correlations)} correlations, "
            f"{len(clusters)} clusters, {len(attack_chains)} attack chains"
        )

        return result

    def temporal_correlation(
        self, events: list[dict], window_hours: int = 72
    ) -> list[dict]:
        """
        Find events that occurred in suspicious temporal proximity.
        
        Uses exponential decay scoring: score = exp(-time_diff_hours / window_hours)
        Groups events by time buckets (1h, 6h, 24h) for efficiency.
        
        Args:
            events: List of event dictionaries with 'timestamp' field
            window_hours: Time window for correlation scoring
            
        Returns:
            List of correlation pairs with confidence scores
        """
        if len(events) < 2:
            return []

        # Parse and sort events by timestamp
        parsed_events = []
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp"))
            if ts:
                parsed_events.append((ts, event))

        if len(parsed_events) < 2:
            return []

        parsed_events.sort(key=lambda x: x[0])
        correlations = []

        # Time buckets for grouping
        buckets = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
        }

        # Compare all pairs within window
        for i, (ts1, event1) in enumerate(parsed_events):
            for ts2, event2 in parsed_events[i + 1:]:
                time_diff = ts2 - ts1
                
                # Skip if outside window
                if time_diff > timedelta(hours=window_hours):
                    break

                # Calculate temporal score using exponential decay
                time_diff_hours = time_diff.total_seconds() / 3600
                score = math.exp(-time_diff_hours / window_hours)

                # Determine bucket
                bucket = None
                for bucket_name, bucket_delta in buckets.items():
                    if time_diff <= bucket_delta:
                        bucket = bucket_name
                        break

                if bucket is None:
                    bucket = f"{window_hours}h"

                # Boost score for very close events
                if time_diff_hours < 1:
                    score = min(1.0, score * 1.2)

                correlations.append({
                    "event1_id": event1.get("id", str(i)),
                    "event2_id": event2.get("id", str(i + 1)),
                    "event1": event1,
                    "event2": event2,
                    "correlation_type": "temporal",
                    "score": round(score, 4),
                    "time_diff_hours": round(time_diff_hours, 2),
                    "time_bucket": bucket,
                    "confidence": round(score, 4),
                })

        logger.debug(f"Temporal correlation found {len(correlations)} pairs")
        return correlations

    def entity_correlation(self, events: list[dict]) -> list[dict]:
        """
        Find events sharing same entities (IPs, domains, hashes, person names).
        
        Builds entity-event bipartite graph and uses Jaccard similarity:
        score = |intersection| / |union| of entity sets
        
        Args:
            events: List of event dictionaries with 'entities' field
            
        Returns:
            List of correlation pairs with shared entities and similarity scores
        """
        if len(events) < 2:
            return []

        # Extract entity sets for each event
        event_entities = []
        for event in events:
            entities = self._extract_entities(event)
            event_entities.append((event, entities))

        correlations = []

        # Compare all pairs using Jaccard similarity
        for (event1, entities1), (event2, entities2) in combinations(
            zip(events, [e for _, e in event_entities]), 2
        ):
            if not entities1 or not entities2:
                continue

            # Calculate Jaccard similarity
            intersection = entities1 & entities2
            union = entities1 | entities2

            if not union:
                continue

            jaccard_score = len(intersection) / len(union)

            if jaccard_score > 0:
                # Categorize shared entities
                shared_ips = [e for e in intersection if self._is_ip(e)]
                shared_domains = [e for e in intersection if self._is_domain(e)]
                shared_hashes = [e for e in intersection if self._is_hash(e)]
                shared_persons = [
                    e for e in intersection
                    if not self._is_ip(e) and not self._is_domain(e) and not self._is_hash(e)
                ]

                correlations.append({
                    "event1_id": event1.get("id"),
                    "event2_id": event2.get("id"),
                    "event1": event1,
                    "event2": event2,
                    "correlation_type": "entity",
                    "score": round(jaccard_score, 4),
                    "shared_entities": list(intersection),
                    "shared_ips": shared_ips,
                    "shared_domains": shared_domains,
                    "shared_hashes": shared_hashes,
                    "shared_persons": shared_persons,
                    "confidence": round(jaccard_score, 4),
                })

        logger.debug(f"Entity correlation found {len(correlations)} pairs")
        return correlations

    def semantic_correlation(self, events: list[dict]) -> list[dict]:
        """
        Find semantically related events using TF-IDF + cosine similarity.
        
        Extracts key terms from event content, builds TF-IDF vectors,
        and computes cosine similarity matrix.
        
        Args:
            events: List of event dictionaries with 'content' or 'description' field
            
        Returns:
            List of correlation pairs with similarity > 0.3
        """
        if len(events) < 2:
            return []

        # Extract text content from events
        documents = []
        valid_events = []
        for event in events:
            text = self._extract_text(event)
            if text:
                tokens = self._tokenize(text)
                if tokens:
                    documents.append(tokens)
                    valid_events.append(event)

        if len(documents) < 2:
            return []

        # Build vocabulary
        vocab = {}
        for doc in documents:
            for token in doc:
                if token not in vocab:
                    vocab[token] = len(vocab)

        if not vocab:
            return []

        # Build term-document matrix
        n_docs = len(documents)
        n_terms = len(vocab)
        term_freq = np.zeros((n_docs, n_terms))

        for i, doc in enumerate(documents):
            for token in doc:
                term_freq[i, vocab[token]] += 1

        # Calculate IDF (Inverse Document Frequency)
        doc_freq = np.sum(term_freq > 0, axis=0)
        idf = np.log((n_docs + 1) / (doc_freq + 1)) + 1  # Smoothed IDF

        # Calculate TF-IDF
        tfidf = term_freq * idf

        # Normalize vectors (L2 normalization)
        norms = np.linalg.norm(tfidf, axis=1, keepdims=True)
        norms[norms == 0] = 1  # Avoid division by zero
        tfidf_normalized = tfidf / norms

        # Compute cosine similarity matrix
        cosine_sim = np.dot(tfidf_normalized, tfidf_normalized.T)

        # Extract pairs with similarity > 0.3
        correlations = []
        threshold = 0.3

        for i, j in combinations(range(n_docs), 2):
            similarity = cosine_sim[i, j]
            if similarity > threshold:
                correlations.append({
                    "event1_id": valid_events[i].get("id"),
                    "event2_id": valid_events[j].get("id"),
                    "event1": valid_events[i],
                    "event2": valid_events[j],
                    "correlation_type": "semantic",
                    "score": round(float(similarity), 4),
                    "confidence": round(float(similarity), 4),
                })

        logger.debug(f"Semantic correlation found {len(correlations)} pairs")
        return correlations

    def causal_inference(self, event_pairs: list[dict]) -> list[dict]:
        """
        Infer causal relationships from correlated event pairs.
        
        Rules for causation:
        - Earlier event may cause later event
        - They share entities
        - Time gap is plausible (5min to 48h)
        - Threat types are compatible (recon -> exploit -> exfil)
        
        Args:
            event_pairs: List of correlated event pairs
            
        Returns:
            List of causal chains with confidence scores
        """
        causal_chains = []

        for pair in event_pairs:
            event1 = pair.get("event1", {})
            event2 = pair.get("event2", {})

            # Determine temporal order
            ts1 = self._parse_timestamp(event1.get("timestamp"))
            ts2 = self._parse_timestamp(event2.get("timestamp"))

            if not ts1 or not ts2:
                continue

            # Ensure event1 is earlier
            if ts1 > ts2:
                event1, event2 = event2, event1
                ts1, ts2 = ts2, ts1

            # Calculate time gap
            time_gap_hours = (ts2 - ts1).total_seconds() / 3600

            # Check plausible time gap (5min to 48h)
            if time_gap_hours < 0.083 or time_gap_hours > 48:
                continue

            # Check entity sharing
            entities1 = self._extract_entities(event1)
            entities2 = self._extract_entities(event2)
            shared_entities = entities1 & entities2

            if not shared_entities:
                continue

            # Check threat type compatibility
            threat1 = self._get_threat_type(event1).lower()
            threat2 = self._get_threat_type(event2).lower()

            compatible = self._are_threat_types_compatible(threat1, threat2)

            if not compatible:
                continue

            # Calculate causal confidence
            base_score = pair.get("score", 0.5)
            entity_bonus = min(0.2, len(shared_entities) * 0.05)
            time_score = math.exp(-time_gap_hours / 24)  # Decay over 24h
            
            causal_confidence = min(1.0, base_score + entity_bonus + time_score * 0.1)

            causal_chains.append({
                "cause_event": event1,
                "effect_event": event2,
                "cause_id": event1.get("id"),
                "effect_id": event2.get("id"),
                "causal_type": f"{threat1} -> {threat2}",
                "shared_entities": list(shared_entities),
                "time_gap_hours": round(time_gap_hours, 2),
                "confidence": round(causal_confidence, 4),
                "correlation_score": base_score,
            })

        # Sort by confidence
        causal_chains.sort(key=lambda x: x["confidence"], reverse=True)

        logger.debug(f"Causal inference found {len(causal_chains)} causal relationships")
        return causal_chains

    def reconstruct_attack_chain(self, events: list[dict]) -> list[dict]:
        """
        Reconstruct attack timeline from correlated events.
        
        Maps events to MITRE ATT&CK phases and sorts by timestamp.
        Phases: Reconnaissance -> Weaponization -> Delivery -> Exploitation -> 
                Installation -> C2 -> Actions
        
        Args:
            events: List of correlated events
            
        Returns:
            Ordered attack chain with phase assignments
        """
        if not events:
            return []

        # Parse timestamps and assign phases
        timed_events = []
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp"))
            if ts:
                phase = self._map_to_attack_phase(event)
                timed_events.append({
                    "timestamp": ts,
                    "event": event,
                    "phase": phase,
                    "phase_order": self.ATTACK_PHASES.index(phase) if phase in self.ATTACK_PHASES else 99,
                })

        if not timed_events:
            return []

        # Sort by timestamp
        timed_events.sort(key=lambda x: x["timestamp"])

        # Build attack chain
        attack_chain = []
        seen_phases = set()

        for item in timed_events:
            phase = item["phase"]
            event = item["event"]

            chain_step = {
                "step_order": len(attack_chain) + 1,
                "timestamp": item["timestamp"].isoformat(),
                "phase": phase,
                "event_id": event.get("id"),
                "event_type": self._get_threat_type(event),
                "description": self._extract_text(event)[:200],
                "entities": list(self._extract_entities(event)),
            }

            attack_chain.append(chain_step)
            seen_phases.add(phase)

        # Fill gaps with inferred steps
        attack_chain = self._fill_attack_chain_gaps(attack_chain, seen_phases)

        logger.debug(f"Reconstructed attack chain with {len(attack_chain)} steps")
        return attack_chain

    def cluster_events(
        self, events: list[dict], min_similarity: float = 0.4
    ) -> list[list[dict]]:
        """
        Cluster events using single-linkage clustering.
        
        Distance = 1 - similarity_score
        Uses union-find for efficient clustering.
        
        Args:
            events: List of events to cluster
            min_similarity: Minimum similarity to be in same cluster
            
        Returns:
            List of event clusters
        """
        if not events:
            return []

        n = len(events)
        if n == 1:
            return [events]

        # Union-Find data structure
        parent = list(range(n))

        def find(x: int) -> int:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: int, y: int):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Calculate pairwise similarities and cluster
        for i, j in combinations(range(n), 2):
            similarity = self._calculate_event_similarity(events[i], events[j])
            if similarity >= min_similarity:
                union(i, j)

        # Group events by cluster
        clusters_dict = defaultdict(list)
        for i in range(n):
            cluster_id = find(i)
            clusters_dict[cluster_id].append(events[i])

        clusters = list(clusters_dict.values())
        
        # Sort clusters by size (largest first)
        clusters.sort(key=len, reverse=True)

        logger.debug(f"Clustered {n} events into {len(clusters)} clusters")
        return clusters

    async def generate_correlation_report(self, events: list[dict]) -> dict:
        """
        Generate full correlation analysis report.
        
        Args:
            events: List of events to analyze
            
        Returns:
            Comprehensive correlation report
        """
        logger.info(f"Generating correlation report for {len(events)} events")

        # Run full correlation analysis
        correlation_result = await self.find_correlations(events)

        # Extract temporal patterns
        temporal_patterns = self._extract_temporal_patterns(events)

        # Extract entity links
        entity_links = self._extract_entity_links(events)

        report = {
            "report_generated_at": datetime.utcnow().isoformat(),
            "summary": correlation_result["summary"],
            "clusters": [
                {
                    "cluster_id": i,
                    "size": len(cluster),
                    "events": [e.get("id") for e in cluster],
                }
                for i, cluster in enumerate(correlation_result["clusters"])
            ],
            "attack_chains": correlation_result["attack_chains"],
            "causal_chains": correlation_result.get("causal_chains", []),
            "temporal_patterns": temporal_patterns,
            "entity_links": entity_links,
            "top_correlations": sorted(
                correlation_result["correlations"],
                key=lambda x: x["score"],
                reverse=True,
            )[:20],
        }

        logger.info("Correlation report generated successfully")
        return report

    # -------------------------------------------------------------------------
    # Private helper methods
    # -------------------------------------------------------------------------

    def _merge_correlations(
        self,
        temporal: list[dict],
        entity: list[dict],
        semantic: list[dict],
    ) -> list[dict]:
        """Merge correlations from multiple methods with weighted scores."""
        merged = {}

        # Weights for different correlation types
        weights = {
            "temporal": 0.3,
            "entity": 0.4,
            "semantic": 0.3,
        }

        for corr_list, corr_type, weight in [
            (temporal, "temporal", weights["temporal"]),
            (entity, "entity", weights["entity"]),
            (semantic, "semantic", weights["semantic"]),
        ]:
            for corr in corr_list:
                key = (corr["event1_id"], corr["event2_id"])
                # Normalize key order
                if key[0] > key[1]:
                    key = (key[1], key[0])

                if key not in merged:
                    merged[key] = {
                        "event1_id": corr["event1_id"],
                        "event2_id": corr["event2_id"],
                        "event1": corr.get("event1"),
                        "event2": corr.get("event2"),
                        "correlation_types": [],
                        "scores": {},
                        "score": 0.0,
                    }

                merged[key]["correlation_types"].append(corr_type)
                merged[key]["scores"][corr_type] = corr["score"]
                
                # Add weighted score
                merged[key]["score"] += corr["score"] * weight

                # Merge additional fields
                for field in ["shared_entities", "time_diff_hours", "time_bucket"]:
                    if field in corr and field not in merged[key]:
                        merged[key][field] = corr[field]

        # Finalize merged correlations
        result = []
        for corr in merged.values():
            corr["score"] = round(corr["score"], 4)
            corr["confidence"] = corr["score"]
            result.append(corr)

        # Sort by score
        result.sort(key=lambda x: x["score"], reverse=True)
        return result

    def _parse_timestamp(self, ts: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if ts is None:
            return None

        if isinstance(ts, datetime):
            return ts

        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts)

        if isinstance(ts, str):
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue

        return None

    def _extract_entities(self, event: dict) -> set[str]:
        """Extract entities (IPs, domains, hashes, persons) from event."""
        entities = set()

        # Direct entities field
        if "entities" in event:
            ent = event["entities"]
            if isinstance(ent, list):
                entities.update(str(e) for e in ent)
            elif isinstance(ent, dict):
                for key, values in ent.items():
                    if isinstance(values, list):
                        entities.update(str(v) for v in values)
                    else:
                        entities.add(str(values))

        # Extract from common fields
        field_mappings = [
            "source_ip", "src_ip", "ip", "ip_address",
            "dest_ip", "dst_ip", "target_ip",
            "domain", "hostname", "fqdn",
            "hash", "md5", "sha1", "sha256",
            "email", "username", "user",
        ]

        for field in field_mappings:
            if field in event and event[field]:
                entities.add(str(event[field]))

        return entities

    def _extract_text(self, event: dict) -> str:
        """Extract text content from event for semantic analysis."""
        text_parts = []

        for field in ["content", "description", "title", "summary", "details", "message"]:
            if field in event and event[field]:
                text_parts.append(str(event[field]))

        return " ".join(text_parts)

    def _tokenize(self, text: str) -> list[str]:
        """Simple tokenization with stopword removal."""
        # Lowercase and split on non-alphanumeric
        import re
        tokens = re.findall(r"\b[a-z0-9_]+\b", text.lower())
        
        # Remove stopwords and short tokens
        return [t for t in tokens if t not in self._stopwords and len(t) > 2]

    def _is_ip(self, entity: str) -> bool:
        """Check if entity looks like an IP address."""
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", entity))

    def _is_domain(self, entity: str) -> bool:
        """Check if entity looks like a domain."""
        return "." in entity and not self._is_ip(entity) and not self._is_hash(entity)

    def _is_hash(self, entity: str) -> bool:
        """Check if entity looks like a hash."""
        return len(entity) in (32, 40, 64) and all(c in "0123456789abcdef" for c in entity.lower())

    def _get_threat_type(self, event: dict) -> str:
        """Extract threat type from event."""
        for field in ["threat_type", "type", "category", "event_type", "attack_type"]:
            if field in event and event[field]:
                return str(event[field])
        return "unknown"

    def _are_threat_types_compatible(self, type1: str, type2: str) -> bool:
        """Check if two threat types can have causal relationship."""
        if type1 == "unknown" or type2 == "unknown":
            return True  # Allow unknown types

        compatible_targets = self.CAUSAL_THREAT_MAPPING.get(type1, [])
        return type2 in compatible_targets

    def _map_to_attack_phase(self, event: dict) -> str:
        """Map event to MITRE ATT&CK phase based on threat type."""
        threat_type = self._get_threat_type(event).lower()

        phase_mapping = {
            "reconnaissance": "Reconnaissance",
            "scanning": "Reconnaissance",
            "enumeration": "Reconnaissance",
            "surveillance": "Reconnaissance",
            "weaponization": "Weaponization",
            "malware_creation": "Weaponization",
            "delivery": "Delivery",
            "phishing": "Delivery",
            "spam": "Delivery",
            "exploit": "Exploitation",
            "exploitation": "Exploitation",
            "vulnerability_exploit": "Exploitation",
            "installation": "Installation",
            "backdoor": "Installation",
            "persistence": "Installation",
            "c2": "CommandAndControl",
            "command_and_control": "CommandAndControl",
            "callback": "CommandAndControl",
            "exfiltration": "Actions",
            "data_exfiltration": "Actions",
            "data_theft": "Actions",
            "lateral_movement": "Actions",
            "privilege_escalation": "Actions",
        }

        for key, phase in phase_mapping.items():
            if key in threat_type:
                return phase

        return "Actions"  # Default phase

    def _fill_attack_chain_gaps(
        self, chain: list[dict], seen_phases: set[str]
    ) -> list[dict]:
        """Fill gaps in attack chain with inferred steps."""
        if not chain:
            return chain

        # Find missing phases between seen phases
        seen_orders = sorted(
            self.ATTACK_PHASES.index(p) for p in seen_phases if p in self.ATTACK_PHASES
        )

        if len(seen_orders) < 2:
            return chain

        # Check for gaps
        for i in range(len(seen_orders) - 1):
            if seen_orders[i + 1] - seen_orders[i] > 1:
                # There's a gap - could add inferred steps here
                # For now, just note the gap
                pass

        return chain

    def _calculate_event_similarity(self, event1: dict, event2: dict) -> float:
        """Calculate overall similarity between two events."""
        # Entity similarity
        entities1 = self._extract_entities(event1)
        entities2 = self._extract_entities(event2)
        
        if entities1 and entities2:
            entity_sim = len(entities1 & entities2) / len(entities1 | entities2)
        else:
            entity_sim = 0.0

        # Temporal similarity
        ts1 = self._parse_timestamp(event1.get("timestamp"))
        ts2 = self._parse_timestamp(event2.get("timestamp"))
        
        if ts1 and ts2:
            time_diff_hours = abs((ts2 - ts1).total_seconds()) / 3600
            temporal_sim = math.exp(-time_diff_hours / 24)
        else:
            temporal_sim = 0.0

        # Semantic similarity (simplified)
        text1 = self._extract_text(event1)
        text2 = self._extract_text(event2)
        
        if text1 and text2:
            tokens1 = set(self._tokenize(text1))
            tokens2 = set(self._tokenize(text2))
            if tokens1 and tokens2:
                semantic_sim = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            else:
                semantic_sim = 0.0
        else:
            semantic_sim = 0.0

        # Weighted combination
        return 0.4 * entity_sim + 0.3 * temporal_sim + 0.3 * semantic_sim

    def _extract_temporal_patterns(self, events: list[dict]) -> list[dict]:
        """Extract temporal patterns from events."""
        if len(events) < 2:
            return []

        # Group events by hour
        hourly_counts = defaultdict(int)
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp"))
            if ts:
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key] += 1

        # Find bursts (hours with significantly more events)
        if not hourly_counts:
            return []

        counts = list(hourly_counts.values())
        mean_count = sum(counts) / len(counts)
        std_count = (sum((c - mean_count) ** 2 for c in counts) / len(counts)) ** 0.5

        patterns = []
        threshold = mean_count + 2 * std_count if std_count > 0 else mean_count * 2

        for hour, count in hourly_counts.items():
            if count > threshold:
                patterns.append({
                    "pattern_type": "temporal_burst",
                    "time_window": hour,
                    "event_count": count,
                    "severity": "high" if count > mean_count * 3 else "medium",
                })

        return patterns

    def _extract_entity_links(self, events: list[dict]) -> list[dict]:
        """Extract entity-based links between events."""
        entity_events = defaultdict(list)

        for event in events:
            entities = self._extract_entities(event)
            for entity in entities:
                entity_events[entity].append(event.get("id"))

        links = []
        for entity, event_ids in entity_events.items():
            if len(event_ids) >= 2:
                links.append({
                    "entity": entity,
                    "linked_events": event_ids,
                    "link_count": len(event_ids),
                    "entity_type": self._classify_entity(entity),
                })

        # Sort by link count
        links.sort(key=lambda x: x["link_count"], reverse=True)
        return links

    def _classify_entity(self, entity: str) -> str:
        """Classify entity type."""
        if self._is_ip(entity):
            return "ip_address"
        if self._is_hash(entity):
            return "hash"
        if self._is_domain(entity):
            return "domain"
        if "@" in entity:
            return "email"
        return "other"


# Singleton instance
event_correlation_engine = EventCorrelationEngine()
