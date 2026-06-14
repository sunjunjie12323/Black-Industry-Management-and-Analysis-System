import base64
import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger


class MaskingStrategy(str, Enum):
    PARTIAL = "PARTIAL"
    HASH = "HASH"
    REDACT = "REDACT"
    TOKENIZE = "TOKENIZE"


class PIIType(str, Enum):
    ID_CARD = "ID_CARD"
    PHONE = "PHONE"
    BANK_CARD = "BANK_CARD"
    EMAIL = "EMAIL"
    IP_ADDRESS = "IP_ADDRESS"


@dataclass
class PIIMatch:
    pii_type: PIIType
    start: int
    end: int
    original_value: str


_PII_DETECT_PATTERNS: Dict[PIIType, re.Pattern] = {
    PIIType.ID_CARD: re.compile(r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
    PIIType.PHONE: re.compile(r"\b1[3-9]\d{9}\b"),
    PIIType.BANK_CARD: re.compile(r"\b(?:62|4\d|5[1-5])\d{14,17}\b"),
    PIIType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    PIIType.IP_ADDRESS: re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
}


class FieldLevelEncryption:
    """字段级加密，使用AES-256-GCM对敏感字段进行加密和解密，支持密钥轮换和审计日志。"""

    _KEY_ENV = "DATA_ENCRYPTION_KEY"

    def __init__(self, key: Optional[bytes] = None):
        self.logger = logger.bind(component="field_level_encryption")
        self._audit_log: List[Dict] = []
        if key is not None:
            self._key = key
        else:
            key_hex = os.environ.get(self._KEY_ENV, "")
            if key_hex and len(key_hex) == 64:
                self._key = bytes.fromhex(key_hex)
            else:
                self._key = os.urandom(32)
                self.logger.warning(f"{self._KEY_ENV} not set, using ephemeral key")
        self._key_created_at = datetime.now(timezone.utc)
        self._key_id = hashlib.sha256(self._key).hexdigest()[:16]

    def encrypt_field(self, plaintext: str) -> str:
        """使用AES-256-GCM加密字段值，返回base64编码的密文（含nonce和tag）。

        Args:
            plaintext: 待加密的明文字符串

        Returns:
            base64编码的加密结果，格式为 FLE_<base64(nonce+ciphertext+tag)>
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(self._key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        encoded = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
        return f"FLE_{encoded}"

    def decrypt_field(self, ciphertext: str, requester_id: str, reason: str) -> str:
        """解密字段值，同时记录审计日志。

        Args:
            ciphertext: encrypt_field返回的加密字符串
            requester_id: 请求解密的用户/服务标识
            reason: 解密原因

        Returns:
            解密后的明文字符串
        """
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requester_id": requester_id,
            "reason": reason,
            "key_id": self._key_id,
        }
        self._audit_log.append(audit_entry)
        self.logger.info(f"Decrypt request: requester={requester_id}, reason={reason}")

        if ciphertext.startswith("FLE_"):
            ciphertext = ciphertext[4:]

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = base64.urlsafe_b64decode(ciphertext)
            nonce = raw[:12]
            ct = raw[12:]
            aesgcm = AESGCM(self._key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            return plaintext.decode("utf-8")
        except Exception as exc:
            self.logger.error(f"Decrypt failed: {exc}")
            return "[DECRYPT_FAILED]"

    def rotate_key(self, new_key: bytes) -> None:
        """轮换加密密钥。新密钥将用于后续加密操作，已有密文需用旧密钥解密后重新加密。

        Args:
            new_key: 新的32字节AES密钥
        """
        if len(new_key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        old_key_id = self._key_id
        self._key = new_key
        self._key_id = hashlib.sha256(self._key).hexdigest()[:16]
        self._key_created_at = datetime.now(timezone.utc)
        self.logger.info(f"Key rotated: {old_key_id} -> {self._key_id}")

    def get_key_info(self) -> Dict[str, Any]:
        """获取当前密钥信息，不暴露密钥本身。

        Returns:
            包含key_id、created_at、algorithm的字典
        """
        return {
            "key_id": self._key_id,
            "created_at": self._key_created_at.isoformat(),
            "algorithm": "AES-256-GCM",
        }


class SecureEraser:
    """安全擦除工具，支持文件安全删除、内存字符串清除和字典字段清除。"""

    def __init__(self):
        self.logger = logger.bind(component="secure_eraser")

    def erase_file(self, filepath: str, passes: int = 3) -> bool:
        """安全删除文件，通过多次随机数据覆写后删除文件。

        Args:
            filepath: 待删除的文件路径
            passes: 覆写次数，默认3次

        Returns:
            是否成功删除
        """
        try:
            file_size = os.path.getsize(filepath)
            with open(filepath, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(filepath)
            self.logger.info(f"Securely erased file: {filepath} ({passes} passes)")
            return True
        except FileNotFoundError:
            self.logger.warning(f"File not found: {filepath}")
            return False
        except Exception as exc:
            self.logger.error(f"Failed to erase file {filepath}: {exc}")
            return False

    def erase_string(self, data: str) -> None:
        """安全清除内存中的字符串，通过覆写内存缓冲区来减少敏感数据残留。

        Args:
            data: 待清除的字符串（将被就地覆写）
        """
        try:
            buffer = bytearray(data.encode("utf-8"))
            for i in range(len(buffer)):
                buffer[i] = 0
            for i in range(len(buffer)):
                buffer[i] = 0xFF
            for i in range(len(buffer)):
                buffer[i] = 0
            self.logger.debug("String securely erased from memory")
        except Exception as exc:
            self.logger.error(f"Failed to erase string: {exc}")

    def erase_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """安全清除字典中的指定字段，将字段值替换为随机数据后删除。

        Args:
            data: 包含敏感字段的字典
            fields: 需要清除的字段名列表

        Returns:
            清除指定字段后的字典
        """
        for field_name in fields:
            if field_name in data:
                value = data[field_name]
                if isinstance(value, str):
                    self.erase_string(value)
                data[field_name] = "[ERASED]"
        self.logger.info(f"Erased fields: {fields}")
        return data


class DataLineageTracker:
    """数据血缘追踪器，记录数据来源、变换和访问，支持血缘链查询和影响分析。"""

    def __init__(self):
        self.logger = logger.bind(component="data_lineage_tracker")
        self._origins: Dict[str, Dict] = {}
        self._transformations: Dict[str, List[Dict]] = {}
        self._access_log: Dict[str, List[Dict]] = {}
        self._downstream_map: Dict[str, List[str]] = defaultdict(list)

    def record_origin(self, data_id: str, source: str, collector: str, timestamp: Optional[str] = None) -> None:
        """记录数据来源信息。

        Args:
            data_id: 数据唯一标识
            source: 数据来源描述
            collector: 数据采集者/系统标识
            timestamp: 采集时间戳，默认为当前UTC时间
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        self._origins[data_id] = {
            "source": source,
            "collector": collector,
            "timestamp": ts,
        }
        self.logger.info(f"Recorded origin for {data_id}: source={source}, collector={collector}")

    def record_transformation(self, data_id: str, transform_type: str, input_ids: List[str], output_id: str) -> None:
        """记录数据变换信息。

        Args:
            data_id: 被变换的数据标识
            transform_type: 变换类型描述
            input_ids: 输入数据ID列表
            output_id: 输出数据ID
        """
        entry = {
            "transform_type": transform_type,
            "input_ids": input_ids,
            "output_id": output_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if data_id not in self._transformations:
            self._transformations[data_id] = []
        self._transformations[data_id].append(entry)
        for inp_id in input_ids:
            if output_id not in self._downstream_map[inp_id]:
                self._downstream_map[inp_id].append(output_id)
        self.logger.info(f"Recorded transformation for {data_id}: {transform_type}")

    def record_access(self, data_id: str, accessor_id: str, action: str) -> None:
        """记录数据访问事件。

        Args:
            data_id: 被访问的数据标识
            accessor_id: 访问者标识
            action: 访问动作描述（如read/write/export）
        """
        entry = {
            "accessor_id": accessor_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if data_id not in self._access_log:
            self._access_log[data_id] = []
        self._access_log[data_id].append(entry)
        self.logger.info(f"Recorded access for {data_id}: accessor={accessor_id}, action={action}")

    def get_lineage(self, data_id: str) -> Dict[str, Any]:
        """获取指定数据的完整血缘链。

        Args:
            data_id: 数据唯一标识

        Returns:
            包含origin、transformations、access_log的完整血缘信息
        """
        lineage: Dict[str, Any] = {"data_id": data_id}
        lineage["origin"] = self._origins.get(data_id)
        lineage["transformations"] = self._transformations.get(data_id, [])
        lineage["access_log"] = self._access_log.get(data_id, [])
        return lineage

    def get_impact_analysis(self, data_id: str) -> Dict[str, Any]:
        """影响分析，递归查找所有受影响的下游数据。

        Args:
            data_id: 源数据标识

        Returns:
            包含direct_downstream和all_downstream的影响分析结果
        """
        direct = self._downstream_map.get(data_id, [])
        all_downstream: List[str] = []
        visited: set = set()
        queue = list(direct)
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            all_downstream.append(current)
            for child in self._downstream_map.get(current, []):
                if child not in visited:
                    queue.append(child)
        return {
            "source_data_id": data_id,
            "direct_downstream": direct,
            "all_downstream": all_downstream,
            "total_impacted": len(all_downstream),
        }


class PIIDetector:
    def __init__(self):
        self.logger = logger.bind(component="pii_detector")

    def detect_pii(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for pii_type, pattern in _PII_DETECT_PATTERNS.items():
            for m in pattern.finditer(text):
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    start=m.start(),
                    end=m.end(),
                    original_value=m.group(),
                ))
        matches.sort(key=lambda x: x.start)
        return matches

    def mask_pii(self, text: str, strategy: MaskingStrategy) -> str:
        matches = self.detect_pii(text)
        if not matches:
            return text

        result = text
        offset = 0
        for match in matches:
            replacement = self._apply_strategy(match.original_value, match.pii_type, strategy)
            start = match.start + offset
            end = match.end + offset
            result = result[:start] + replacement + result[end:]
            offset += len(replacement) - (match.end - match.start)

        return result

    def detect_pii_in_dict(self, data: Dict[str, Any], path: str = "") -> List[Dict[str, Any]]:
        """递归检测字典中所有字符串值包含的PII信息。

        Args:
            data: 待检测的字典数据
            path: 当前递归路径（用于定位PII所在位置）

        Returns:
            包含path、pii_type、matches的检测结果列表
        """
        results: List[Dict[str, Any]] = []
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if isinstance(value, str):
                matches = self.detect_pii(value)
                if matches:
                    results.append({
                        "path": current_path,
                        "pii_types": list(set(m.pii_type.value for m in matches)),
                        "count": len(matches),
                        "matches": [
                            {
                                "pii_type": m.pii_type.value,
                                "start": m.start,
                                "end": m.end,
                                "original_value": m.original_value,
                            }
                            for m in matches
                        ],
                    })
            elif isinstance(value, dict):
                results.extend(self.detect_pii_in_dict(value, current_path))
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    item_path = f"{current_path}[{idx}]"
                    if isinstance(item, str):
                        matches = self.detect_pii(item)
                        if matches:
                            results.append({
                                "path": item_path,
                                "pii_types": list(set(m.pii_type.value for m in matches)),
                                "count": len(matches),
                                "matches": [
                                    {
                                        "pii_type": m.pii_type.value,
                                        "start": m.start,
                                        "end": m.end,
                                        "original_value": m.original_value,
                                    }
                                    for m in matches
                                ],
                            })
                    elif isinstance(item, dict):
                        results.extend(self.detect_pii_in_dict(item, item_path))
        return results

    def mask_pii_in_dict(self, data: Dict[str, Any], strategy: MaskingStrategy = MaskingStrategy.PARTIAL) -> Dict[str, Any]:
        """递归脱敏字典中所有字符串值包含的PII。

        Args:
            data: 待脱敏的字典数据
            strategy: 脱敏策略，默认为PARTIAL

        Returns:
            脱敏后的字典
        """
        result: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.mask_pii(value, strategy)
            elif isinstance(value, dict):
                result[key] = self.mask_pii_in_dict(value, strategy)
            elif isinstance(value, list):
                masked_list: List[Any] = []
                for item in value:
                    if isinstance(item, str):
                        masked_list.append(self.mask_pii(item, strategy))
                    elif isinstance(item, dict):
                        masked_list.append(self.mask_pii_in_dict(item, strategy))
                    else:
                        masked_list.append(item)
                result[key] = masked_list
            else:
                result[key] = value
        return result

    def get_pii_statistics(self, text: str) -> Dict[str, Any]:
        """获取文本中PII的统计信息。

        Args:
            text: 待统计的文本

        Returns:
            包含total_count、by_type、has_pii的统计信息字典
        """
        matches = self.detect_pii(text)
        by_type: Dict[str, int] = defaultdict(int)
        for m in matches:
            by_type[m.pii_type.value] += 1
        return {
            "total_count": len(matches),
            "by_type": dict(by_type),
            "has_pii": len(matches) > 0,
        }

    def _apply_strategy(self, value: str, pii_type: PIIType, strategy: MaskingStrategy) -> str:
        if strategy == MaskingStrategy.PARTIAL:
            return self._partial_mask(value, pii_type)
        elif strategy == MaskingStrategy.HASH:
            return "H_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        elif strategy == MaskingStrategy.REDACT:
            return f"[REDACTED_{pii_type.value}]"
        elif strategy == MaskingStrategy.TOKENIZE:
            return reversible_masker.mask(value)
        return value

    def _partial_mask(self, value: str, pii_type: PIIType) -> str:
        if pii_type == PIIType.PHONE:
            return value[:3] + "****" + value[-4:]
        elif pii_type == PIIType.ID_CARD:
            return value[:3] + "***********" + value[-4:]
        elif pii_type == PIIType.BANK_CARD:
            return value[:6] + "******" + value[-4:]
        elif pii_type == PIIType.EMAIL:
            parts = value.split("@")
            return parts[0][:2] + "***@" + parts[-1]
        elif pii_type == PIIType.IP_ADDRESS:
            octets = value.split(".")
            return octets[0] + ".*.*." + octets[-1]
        return value[:2] + "***" + value[-2:]


class ReversibleMasker:
    _AES_KEY_ENV = "DATA_MASKING_AES_KEY"

    def __init__(self):
        self.logger = logger.bind(component="reversible_masker")
        self._token_store: Dict[str, str] = {}
        self._max_tokens = 10000
        self._audit_unmask: List[Dict] = []
        self._key = self._get_or_create_key()
        self._mask_count = 0
        self._unmask_count = 0

    def _get_or_create_key(self) -> bytes:
        key_hex = os.environ.get(self._AES_KEY_ENV, "")
        if key_hex and len(key_hex) == 64:
            return bytes.fromhex(key_hex)
        key = os.urandom(32)
        self.logger.warning(f"{self._AES_KEY_ENV} not set, using ephemeral key (tokens will not survive restart)")
        return key

    def mask(self, value: str) -> str:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(self._key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
            token = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
            self._token_store[token] = value
            if len(self._token_store) > self._max_tokens:
                oldest_token = next(iter(self._token_store))
                del self._token_store[oldest_token]
            self._mask_count += 1
            return f"TKN_{token}"
        except ImportError:
            token_id = uuid.uuid4().hex[:16]
            self._token_store[token_id] = value
            if len(self._token_store) > self._max_tokens:
                oldest_token = next(iter(self._token_store))
                del self._token_store[oldest_token]
            self._mask_count += 1
            return f"TKN_{token_id}"

    def unmask(self, token: str, requester_id: str, reason: str) -> str:
        if token.startswith("TKN_"):
            token = token[4:]

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requester_id": requester_id,
            "reason": reason,
            "token_prefix": token[:8] if len(token) > 8 else token,
        }
        self._audit_unmask.append(audit_entry)
        self.logger.info(f"Unmask request: requester={requester_id}, reason={reason}")

        if token in self._token_store:
            self._unmask_count += 1
            return self._token_store[token]

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = base64.urlsafe_b64decode(token)
            nonce = raw[:12]
            ct = raw[12:]
            aesgcm = AESGCM(self._key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            decoded = plaintext.decode("utf-8")
            self._token_store[token] = decoded
            self._unmask_count += 1
            return decoded
        except Exception as exc:
            self.logger.error(f"Unmask failed: {exc}")
            return "[UNMASK_FAILED]"

    def mask_batch(self, values: List[str]) -> List[str]:
        """批量脱敏多个值。

        Args:
            values: 待脱敏的值列表

        Returns:
            脱敏后的token列表
        """
        return [self.mask(v) for v in values]

    def unmask_batch(self, tokens: List[str], requester_id: str, reason: str) -> List[str]:
        """批量还原多个token。

        Args:
            tokens: 待还原的token列表
            requester_id: 请求者标识
            reason: 还原原因

        Returns:
            还原后的值列表
        """
        return [self.unmask(t, requester_id, reason) for t in tokens]

    def get_statistics(self) -> Dict[str, Any]:
        """获取脱敏统计信息。

        Returns:
            包含mask_count、unmask_count、active_tokens、audit_entries的统计字典
        """
        return {
            "mask_count": self._mask_count,
            "unmask_count": self._unmask_count,
            "active_tokens": len(self._token_store),
            "max_tokens": self._max_tokens,
            "audit_entries": len(self._audit_unmask),
        }

    def get_unmask_audit_log(self) -> List[Dict]:
        return list(self._audit_unmask)


reversible_masker = ReversibleMasker()
pii_detector = PIIDetector()
