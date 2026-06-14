"""
Threat Behavior Profiling Engine
Commercial-grade system for analyzing threat actor behavior patterns,
TTP fingerprinting, and behavioral clustering.
"""

import asyncio
import math
from collections import Counter, defaultdict
from itertools import combinations
from typing import Optional

import numpy as np
from loguru import logger


class TTPExtractor:
    """Extract TTPs from incident descriptions using keyword matching."""
    
    # MITRE ATT&CK technique keyword mappings
    TECHNIQUE_KEYWORDS = {
        "T1566.001": {
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial_Access",
            "keywords": ["spearphishing", "malicious attachment", "weaponized document", "phishing email"]
        },
        "T1566.002": {
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial_Access",
            "keywords": ["malicious link", "phishing link", "credential harvesting", "login page"]
        },
        "T1059.001": {
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "keywords": ["powershell", "ps1", "encoded command", "invoke-expression"]
        },
        "T1059.003": {
            "name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution",
            "keywords": ["cmd.exe", "command prompt", "batch script", "bat file"]
        },
        "T1053.005": {
            "name": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence",
            "keywords": ["scheduled task", "schtasks", "cron job", "persistence mechanism"]
        },
        "T1547.001": {
            "name": "Boot or Logon Autostart Execution: Registry Run Keys",
            "tactic": "Persistence",
            "keywords": ["registry run key", "autostart", "startup folder", "boot persistence"]
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Privilege_Escalation",
            "keywords": ["stolen credentials", "compromised account", "valid account", "credential theft"]
        },
        "T1003.001": {
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential_Access",
            "keywords": ["lsass", "mimikatz", "credential dumping", "password hash", "ntlm"]
        },
        "T1021.002": {
            "name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral_Movement",
            "keywords": ["smb", "admin share", "psexec", "lateral movement", "remote execution"]
        },
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "keywords": ["exfiltration", "data theft", "stolen data", "command and control"]
        },
        "T1071.001": {
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command_Control",
            "keywords": ["c2", "command and control", "beacon", "callback", "http callback"]
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "keywords": ["ransomware", "encryption", "encrypted files", "ransom note"]
        },
        "T1082": {
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "keywords": ["system info", "hostname", "os version", "reconnaissance", "discovery"]
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "keywords": ["file search", "directory listing", "find files", "enumeration"]
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "keywords": ["dns exfiltration", "ftp exfiltration", "alternative protocol"]
        },
        "T1105": {
            "name": "Ingress Tool Transfer",
            "tactic": "Command_Control",
            "keywords": ["download", "upload", "tool transfer", "payload delivery"]
        },
        "T1027": {
            "name": "Obfuscated Files or Information",
            "tactic": "Defense_Evasion",
            "keywords": ["obfuscation", "encoded", "encrypted payload", "evasion technique"]
        },
        "T1055": {
            "name": "Process Injection",
            "tactic": "Defense_Evasion",
            "keywords": ["process injection", "code injection", "dll injection", "process hollowing"]
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential_Access",
            "keywords": ["credential dump", "password dump", "hash dump", "sam database"]
        },
        "T1070": {
            "name": "Indicator Removal",
            "tactic": "Defense_Evasion",
            "keywords": ["log deletion", "evidence removal", "anti-forensics", "cover tracks"]
        }
    }
    
    def extract_from_text(self, text: str) -> list[dict]:
        """
        Extract TTPs from incident description text using keyword matching.
        
        Args:
            text: Incident description or report text
            
        Returns:
            List of extracted TTPs with technique_id, name, tactic, and confidence
        """
        if not text:
            return []
        
        text_lower = text.lower()
        extracted_ttps = []
        
        for technique_id, technique_data in self.TECHNIQUE_KEYWORDS.items():
            technique_name = technique_data["name"]
            tactic = technique_data["tactic"]
            keywords = technique_data["keywords"]
            
            # Count keyword matches
            match_count = sum(1 for keyword in keywords if keyword.lower() in text_lower)
            
            if match_count > 0:
                # Confidence based on number of keyword matches
                confidence = min(1.0, match_count / len(keywords))
                
                extracted_ttps.append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": tactic,
                    "confidence": confidence
                })
                
                logger.debug(f"Extracted TTP {technique_id}: {technique_name} (confidence: {confidence:.2f})")
        
        logger.info(f"Extracted {len(extracted_ttps)} TTPs from text")
        return extracted_ttps


class ThreatBehaviorProfiler:
    """Main engine for threat actor behavior profiling and analysis."""
    
    # MITRE ATT&CK tactics in order (14 dimensions)
    TACTICS = [
        "Reconnaissance",
        "Resource_Development",
        "Initial_Access",
        "Execution",
        "Persistence",
        "Privilege_Escalation",
        "Defense_Evasion",
        "Credential_Access",
        "Discovery",
        "Lateral_Movement",
        "Collection",
        "Exfiltration",
        "Command_Control",
        "Impact"
    ]
    
    def __init__(self):
        self.ttp_extractor = TTPExtractor()
        logger.info("ThreatBehaviorProfiler initialized")
    
    async def build_profile(self, incidents: list[dict]) -> dict:
        """
        Build a threat actor behavior profile from multiple incidents.
        
        Args:
            incidents: List of incident dictionaries with description or ttps fields
            
        Returns:
            Profile dictionary with ttp_fingerprint, behavior_clusters, actor_similarity
        """
        if not incidents:
            logger.warning("No incidents provided for profile building")
            return {
                "ttp_fingerprint": {},
                "behavior_clusters": [],
                "actor_similarity": 0.0,
                "incident_count": 0
            }
        
        logger.info(f"Building threat profile from {len(incidents)} incidents")
        
        # Extract TTP fingerprint
        ttp_fingerprint = self.extract_ttp_fingerprint(incidents)
        
        # Compute behavior vector
        behavior_vector = self.compute_behavior_vector(ttp_fingerprint)
        
        profile = {
            "ttp_fingerprint": ttp_fingerprint,
            "behavior_vector": behavior_vector,
            "incident_count": len(incidents),
            "behavior_clusters": [],
            "actor_similarity": 0.0
        }
        
        logger.info(f"Profile built with {len(ttp_fingerprint)} tactics")
        return profile
    
    def extract_ttp_fingerprint(self, incidents: list[dict]) -> dict:
        """
        Extract TTP fingerprint from incidents by mapping to MITRE ATT&CK.
        
        Args:
            incidents: List of incident dictionaries
            
        Returns:
            Fingerprint dict: {tactic: {technique: normalized_frequency}}
        """
        if not incidents:
            return {}
        
        # Count technique occurrences per tactic
        tactic_technique_counts = defaultdict(lambda: Counter())
        
        for incident in incidents:
            # Extract TTPs from incident description or use provided TTPs
            if "ttps" in incident and incident["ttps"]:
                ttps = incident["ttps"]
            elif "description" in incident:
                ttps = self.ttp_extractor.extract_from_text(incident["description"])
            else:
                continue
            
            # Count techniques per tactic
            for ttp in ttps:
                tactic = ttp.get("tactic")
                technique_id = ttp.get("technique_id")
                confidence = ttp.get("confidence", 1.0)
                
                if tactic and technique_id:
                    tactic_technique_counts[tactic][technique_id] += confidence
        
        # Normalize frequencies to probabilities
        fingerprint = {}
        for tactic, technique_counter in tactic_technique_counts.items():
            total_count = sum(technique_counter.values())
            if total_count > 0:
                fingerprint[tactic] = {
                    technique: count / total_count
                    for technique, count in technique_counter.items()
                }
        
        logger.info(f"Extracted TTP fingerprint with {len(fingerprint)} tactics")
        return fingerprint
    
    def compute_behavior_vector(self, ttp_fingerprint: dict) -> list[float]:
        """
        Convert TTP fingerprint to fixed-length behavior vector (14 dimensions).
        
        Args:
            ttp_fingerprint: TTP fingerprint dictionary
            
        Returns:
            List of 14 floats representing tactic frequencies
        """
        vector = []
        
        # Calculate total techniques across all tactics
        total_techniques = sum(
            sum(techniques.values())
            for techniques in ttp_fingerprint.values()
        )
        
        if total_techniques == 0:
            return [0.0] * 14
        
        # For each tactic, calculate normalized frequency
        for tactic in self.TACTICS:
            if tactic in ttp_fingerprint:
                tactic_total = sum(ttp_fingerprint[tactic].values())
                normalized_freq = tactic_total / total_techniques
                vector.append(normalized_freq)
            else:
                vector.append(0.0)
        
        # Ensure vector sums to 1.0 (probability distribution)
        vector_sum = sum(vector)
        if vector_sum > 0:
            vector = [v / vector_sum for v in vector]
        
        return vector
    
    def calculate_actor_similarity(self, profile_a: dict, profile_b: dict) -> float:
        """
        Calculate cosine similarity between two threat actor profiles.
        
        Args:
            profile_a: First actor profile with behavior_vector
            profile_b: Second actor profile with behavior_vector
            
        Returns:
            Similarity score from 0.0 to 1.0
        """
        vector_a = np.array(profile_a.get("behavior_vector", [0.0] * 14))
        vector_b = np.array(profile_b.get("behavior_vector", [0.0] * 14))
        
        # Calculate cosine similarity
        dot_product = np.dot(vector_a, vector_b)
        norm_a = np.linalg.norm(vector_a)
        norm_b = np.linalg.norm(vector_b)
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        similarity = dot_product / (norm_a * norm_b)
        
        # Clamp to [0, 1] range
        similarity = max(0.0, min(1.0, similarity))
        
        logger.debug(f"Actor similarity: {similarity:.4f}")
        return float(similarity)
    
    def cluster_by_behavior(
        self,
        profiles: list[dict],
        min_similarity: float = 0.6
    ) -> list[list[dict]]:
        """
        Cluster threat actor profiles by behavioral similarity using agglomerative clustering.
        
        Args:
            profiles: List of actor profiles
            min_similarity: Minimum similarity threshold for clustering
            
        Returns:
            List of clusters, each containing similar profiles
        """
        if not profiles:
            return []
        
        if len(profiles) == 1:
            return [profiles]
        
        # Initialize each profile as its own cluster
        clusters = [[profile] for profile in profiles]
        
        # Agglomerative clustering with average linkage
        while len(clusters) > 1:
            # Find most similar pair of clusters
            max_similarity = -1.0
            merge_i, merge_j = -1, -1
            
            for i in range(len(clusters)):
                for j in range(i + 1, len(clusters)):
                    # Calculate average linkage similarity
                    similarity = self._calculate_cluster_similarity(clusters[i], clusters[j])
                    
                    if similarity > max_similarity:
                        max_similarity = similarity
                        merge_i, merge_j = i, j
            
            # Stop if no clusters meet minimum similarity threshold
            if max_similarity < min_similarity:
                break
            
            # Merge clusters
            clusters[merge_i].extend(clusters[merge_j])
            clusters.pop(merge_j)
            
            logger.debug(f"Merged clusters, {len(clusters)} remaining (similarity: {max_similarity:.4f})")
        
        logger.info(f"Clustered {len(profiles)} profiles into {len(clusters)} groups")
        return clusters
    
    def _calculate_cluster_similarity(self, cluster_a: list[dict], cluster_b: list[dict]) -> float:
        """Calculate average linkage similarity between two clusters."""
        total_similarity = 0.0
        count = 0
        
        for profile_a in cluster_a:
            for profile_b in cluster_b:
                total_similarity += self.calculate_actor_similarity(profile_a, profile_b)
                count += 1
        
        return total_similarity / count if count > 0 else 0.0
    
    def identify_ttp_patterns(self, incidents: list[dict]) -> list[dict]:
        """
        Find frequently co-occurring TTP combinations using Apriori-like mining.
        
        Args:
            incidents: List of incidents
            
        Returns:
            List of patterns with support and confidence scores
        """
        if not incidents:
            return []
        
        # Extract technique sets from each incident
        technique_sets = []
        for incident in incidents:
            if "ttps" in incident and incident["ttps"]:
                techniques = {ttp["technique_id"] for ttp in incident["ttps"] if "technique_id" in ttp}
            elif "description" in incident:
                ttps = self.ttp_extractor.extract_from_text(incident["description"])
                techniques = {ttp["technique_id"] for ttp in ttps}
            else:
                techniques = set()
            
            if techniques:
                technique_sets.append(techniques)
        
        if not technique_sets:
            return []
        
        total_incidents = len(technique_sets)
        min_support = 0.3
        min_support_count = min_support * total_incidents
        
        # Find frequent 1-itemsets
        technique_counter = Counter()
        for techniques in technique_sets:
            technique_counter.update(techniques)
        
        frequent_itemsets = []
        frequent_1_itemsets = {
            frozenset([tech]): count
            for tech, count in technique_counter.items()
            if count >= min_support_count
        }
        
        if not frequent_1_itemsets:
            return []
        
        frequent_itemsets.extend(frequent_1_itemsets.items())
        
        # Generate candidate k-itemsets from frequent (k-1)-itemsets
        current_level = list(frequent_1_itemsets.keys())
        k = 2
        
        while current_level:
            candidates = set()
            
            # Generate candidates by combining pairs
            for i in range(len(current_level)):
                for j in range(i + 1, len(current_level)):
                    candidate = current_level[i].union(current_level[j])
                    if len(candidate) == k:
                        candidates.add(candidate)
            
            # Count support for each candidate
            candidate_supports = Counter()
            for candidate in candidates:
                for techniques in technique_sets:
                    if candidate.issubset(techniques):
                        candidate_supports[candidate] += 1
            
            # Filter by minimum support
            frequent_k_itemsets = {
                candidate: count
                for candidate, count in candidate_supports.items()
                if count >= min_support_count
            }
            
            if not frequent_k_itemsets:
                break
            
            frequent_itemsets.extend(frequent_k_itemsets.items())
            current_level = list(frequent_k_itemsets.keys())
            k += 1
        
        # Build pattern results with support and confidence
        patterns = []
        for itemset, support_count in frequent_itemsets:
            support = support_count / total_incidents
            
            # Calculate confidence for each technique in itemset
            confidences = {}
            for technique in itemset:
                technique_support = technique_counter[technique] / total_incidents
                if technique_support > 0:
                    confidences[technique] = support / technique_support
            
            patterns.append({
                "techniques": list(itemset),
                "support": support,
                "confidence": confidences,
                "incident_count": support_count
            })
        
        # Sort by support descending
        patterns.sort(key=lambda x: x["support"], reverse=True)
        
        logger.info(f"Identified {len(patterns)} frequent TTP patterns")
        return patterns
    
    def detect_behavior_anomaly(
        self,
        incident: dict,
        baseline_profile: dict
    ) -> dict:
        """
        Detect anomalies by comparing incident against baseline behavior profile.
        
        Args:
            incident: New incident to analyze
            baseline_profile: Baseline behavior profile
            
        Returns:
            Anomaly detection results with scores and explanations
        """
        # Extract TTPs from incident
        if "ttps" in incident and incident["ttps"]:
            incident_ttps = incident["ttps"]
        elif "description" in incident:
            incident_ttps = self.ttp_extractor.extract_from_text(incident["description"])
        else:
            incident_ttps = []
        
        # Build incident fingerprint
        incident_tactic_counts = Counter()
        for ttp in incident_ttps:
            tactic = ttp.get("tactic")
            if tactic:
                incident_tactic_counts[tactic] += 1
        
        # Get baseline behavior vector
        baseline_vector = np.array(baseline_profile.get("behavior_vector", [0.0] * 14))
        
        # Build incident vector
        incident_vector = []
        total_techniques = sum(incident_tactic_counts.values())
        
        for tactic in self.TACTICS:
            if total_techniques > 0:
                freq = incident_tactic_counts.get(tactic, 0) / total_techniques
                incident_vector.append(freq)
            else:
                incident_vector.append(0.0)
        
        incident_vector = np.array(incident_vector)
        
        # Calculate deviation for each tactic
        deviations = np.abs(incident_vector - baseline_vector)
        
        # Calculate mean and standard deviation of baseline (assume small std for baseline)
        baseline_std = np.std(baseline_vector)
        if baseline_std == 0:
            baseline_std = 0.01  # Avoid division by zero
        
        # Flag anomalies where deviation > 2 standard deviations
        anomaly_threshold = 2 * baseline_std
        anomalous_tactics = []
        
        for i, deviation in enumerate(deviations):
            if deviation > anomaly_threshold:
                tactic = self.TACTICS[i]
                anomalous_tactics.append({
                    "tactic": tactic,
                    "deviation": float(deviation),
                    "baseline_value": float(baseline_vector[i]),
                    "incident_value": float(incident_vector[i])
                })
        
        # Calculate overall anomaly score (average deviation normalized)
        anomaly_score = float(np.mean(deviations) / (baseline_std + 0.01))
        anomaly_score = min(1.0, anomaly_score)
        
        # Generate explanation
        if anomalous_tactics:
            explanation = (
                f"Detected {len(anomalous_tactics)} anomalous tactics with significant deviation "
                f"from baseline behavior. Anomaly score: {anomaly_score:.3f}. "
                f"Most anomalous: {anomalous_tactics[0]['tactic']} "
                f"(deviation: {anomalous_tactics[0]['deviation']:.3f})"
            )
        else:
            explanation = "No significant behavioral anomalies detected. Behavior aligns with baseline."
        
        result = {
            "anomaly_score": anomaly_score,
            "anomalous_tactics": anomalous_tactics,
            "explanation": explanation,
            "is_anomalous": len(anomalous_tactics) > 0
        }
        
        logger.info(f"Anomaly detection complete: score={anomaly_score:.3f}, anomalies={len(anomalous_tactics)}")
        return result
    
    async def match_known_actors(
        self,
        profile: dict,
        known_actors: list[dict],
        top_k: int = 5
    ) -> list[dict]:
        """
        Match behavior profile against known threat actor database.
        
        Args:
            profile: Behavior profile to match
            known_actors: List of known actors with name and ttp_fingerprint
            top_k: Number of top matches to return
            
        Returns:
            List of matches with actor name and similarity score
        """
        if not known_actors:
            return []
        
        matches = []
        
        for actor in known_actors:
            actor_name = actor.get("name", "Unknown")
            actor_fingerprint = actor.get("ttp_fingerprint", {})
            
            # Build actor profile with behavior vector
            actor_profile = {
                "behavior_vector": self.compute_behavior_vector(actor_fingerprint)
            }
            
            # Calculate similarity
            similarity = self.calculate_actor_similarity(profile, actor_profile)
            
            matches.append({
                "actor_name": actor_name,
                "similarity": similarity,
                "ttp_fingerprint": actor_fingerprint
            })
        
        # Sort by similarity descending and return top-K
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        top_matches = matches[:top_k]
        
        logger.info(f"Matched against {len(known_actors)} known actors, top similarity: {top_matches[0]['similarity']:.4f}" if top_matches else "No matches found")
        return top_matches


# Singleton instance
threat_behavior_profiler = ThreatBehaviorProfiler()
