import asyncio
import base64
import hashlib
import json
import math
import os
import struct
import time
import uuid
from datetime import date
from typing import AsyncGenerator, Dict, List, Optional

import httpx
from cryptography.fernet import Fernet
from loguru import logger

from app.config import settings
from app.core.metrics import LLM_CALL_COUNT, LLM_CALL_DURATION, LLM_TOKENS_USED
from app.core.tracing import get_tracer

_EMBEDDING_DIM = 1536


def _hash_embedding(text: str, dim: int = _EMBEDDING_DIM) -> List[float]:
    raw = hashlib.sha512(text.encode("utf-8")).digest()
    values = []
    for i in range(dim):
        chunk = hashlib.sha256(f"{text}|{i}".encode("utf-8")).digest()
        val = struct.unpack("f", chunk[:4])[0]
        values.append(val)
    magnitude = math.sqrt(sum(v * v for v in values))
    if magnitude == 0:
        return [0.0] * dim
    return [v / magnitude for v in values]


DEEPSEEK_THREAT_INTEL_SYSTEM = (
    "你是「黑灰产情报分析专家系统」，专门服务于黑灰产威胁情报的采集、清洗、分析和预警。\n\n"
    "你的核心能力：\n"
    "1. 黑话/暗语识别与解码：熟悉网络黑灰产圈子的暗语体系（如「料」=个人信息、「跑分」=洗钱、"
    "「水房」=洗钱团队、「猫池」=多卡聚合设备、「杀猪盘」=长线诈骗等）\n"
    "2. 威胁分类：诈骗/赌博/黑客攻击/洗钱/数据盗窃/钓鱼/勒索/毒品\n"
    "3. 攻击链重建：资源获取→工具准备→攻击执行→资金流转\n"
    "4. 实体提取：IP/域名/URL/手机号/邮箱/加密货币地址/账号/工具/组织/支付方式\n"
    "5. 可靠性评估：判断情报的真实性和可信度，识别虚假/过时/矛盾信息\n\n"
    "重要原则：\n"
    "- 对不确定的信息标注置信度，不编造不存在的细节\n"
    "- 区分事实和推测，推测需说明依据\n"
    "- 对来源不明的信息保持审慎态度\n"
    "- 回答必须基于提供的情报内容，不添加未提及的信息\n"
    "- 回答使用纯文本格式，不要使用Markdown语法（如##、**、-等），直接用中文标点和换行组织内容"
)


class LLMService:
    MAX_INPUT_LENGTH = 50000
    MAX_TOKENS_PER_DAY = 500000

    PRESET_MODELS: Dict[str, Dict] = {
        "deepseek-chat": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com/v1",
            "model_name": "deepseek-chat",
            "temperature": 0.7,
            "max_tokens": 4096,
        },
        "deepseek-reasoner": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com/v1",
            "model_name": "deepseek-reasoner",
            "temperature": 0.7,
            "max_tokens": 4096,
        },
        "gpt-4o": {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model_name": "gpt-4o",
            "temperature": 0.7,
            "max_tokens": 4096,
        },
        "gpt-4o-mini": {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model_name": "gpt-4o-mini",
            "temperature": 0.7,
            "max_tokens": 4096,
        },
    }

    def __init__(self):
        self.api_key = settings.LLM_API_KEY
        self.base_url = settings.LLM_BASE_URL.rstrip("/")
        self.model_name = settings.LLM_MODEL_NAME
        self.default_temperature = settings.LLM_TEMPERATURE
        self.default_max_tokens = settings.LLM_MAX_TOKENS
        self._client: Optional[httpx.AsyncClient] = None
        self._max_retries = 5
        self._base_delay = 1.0
        self._is_deepseek = "deepseek" in self.base_url.lower()
        self._request_count = 0
        self._total_tokens = 0
        self._stats_lock = asyncio.Lock()
        self._generate_retries = 3
        self._generate_retry_base_delay = 1.0
        self._cb_failures = 0
        self._cb_threshold = 5
        self._cb_opened_at: Optional[float] = None
        self._cb_recovery_timeout = 30.0
        self._cb_lock = asyncio.Lock()
        self._daily_tokens_used = 0
        self._daily_tokens_date: Optional[date] = None

        self._init_fernet()

        self._models: Dict[str, Dict] = {}
        for mid, mcfg in self.PRESET_MODELS.items():
            self._models[mid] = {**mcfg, "is_preset": True, "api_key": ""}

        env_model_id = settings.LLM_MODEL_NAME
        matched_preset = None
        for mid, mcfg in self._models.items():
            if mcfg["model_name"] == env_model_id:
                matched_preset = mid
                break
        if matched_preset:
            self._current_model_id = matched_preset
            self._models[matched_preset]["api_key"] = self._encrypt_key(self.api_key)
        else:
            custom_id = f"custom-{env_model_id}"
            self._models[custom_id] = {
                "provider": "openai_compatible",
                "base_url": self.base_url,
                "model_name": env_model_id,
                "temperature": self.default_temperature,
                "max_tokens": self.default_max_tokens,
                "is_preset": False,
                "api_key": self._encrypt_key(self.api_key),
            }
            self._current_model_id = custom_id

    def _init_fernet(self):
        enc_key = os.environ.get("LLM_KEY_ENCRYPTION_KEY", "")
        if enc_key:
            key_bytes = base64.urlsafe_b64decode(enc_key)
        else:
            secret = settings.secret_key_resolved.encode("utf-8")
            key_bytes = hashlib.sha256(secret).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(key_bytes[:32]))

    def _encrypt_key(self, key: str) -> str:
        if not key:
            return ""
        return self._fernet.encrypt(key.encode("utf-8")).decode("utf-8")

    def _decrypt_key(self, encrypted: str) -> str:
        if not encrypted:
            return ""
        try:
            return self._fernet.decrypt(encrypted.encode("utf-8")).decode("utf-8")
        except Exception:
            return encrypted

    def _check_daily_token_limit(self):
        today = date.today()
        if self._daily_tokens_date != today:
            self._daily_tokens_date = today
            self._daily_tokens_used = 0
        if self._daily_tokens_used >= self.MAX_TOKENS_PER_DAY:
            raise RuntimeError(
                f"Daily token limit reached ({self.MAX_TOKENS_PER_DAY}), try again tomorrow"
            )

    async def _reset_client(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    def list_models(self) -> List[Dict]:
        result = []
        for mid, mcfg in self._models.items():
            entry = {
                "model_id": mid,
                "name": mcfg.get("model_name", mid),
                "provider": mcfg.get("provider", "openai_compatible"),
                "base_url": mcfg.get("base_url", ""),
                "model_name": mcfg.get("model_name", ""),
                "temperature": mcfg.get("temperature", 0.7),
                "max_tokens": mcfg.get("max_tokens", 4096),
                "is_preset": mcfg.get("is_preset", False),
                "is_active": mid == self._current_model_id,
            }
            encrypted_key = mcfg.get("api_key", "")
            if encrypted_key:
                key = self._decrypt_key(encrypted_key)
                entry["api_key_preview"] = "****" + key[-4:] if len(key) >= 4 else "****"
            else:
                entry["api_key_preview"] = ""
            result.append(entry)
        return result

    async def switch_model(self, model_id: str) -> bool:
        if model_id not in self._models:
            return False
        mcfg = self._models[model_id]
        encrypted_key = mcfg.get("api_key", "")
        new_api_key = self._decrypt_key(encrypted_key) or self.api_key
        new_base_url = mcfg.get("base_url", self.base_url).rstrip("/")
        new_model_name = mcfg.get("model_name", self.model_name)

        self.api_key = new_api_key
        self.base_url = new_base_url
        self.model_name = new_model_name
        self.default_temperature = mcfg.get("temperature", self.default_temperature)
        self.default_max_tokens = mcfg.get("max_tokens", self.default_max_tokens)
        self._is_deepseek = "deepseek" in self.base_url.lower()
        self._current_model_id = model_id
        if self._client and not self._client.is_closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self._client = None

        logger.info(f"Switched LLM model to: {model_id} ({new_model_name})")
        return True

    def add_custom_model(self, config: Dict) -> str:
        name = config.get("name", config.get("model_name", "custom"))
        model_id = f"custom-{uuid.uuid4().hex[:8]}"
        raw_key = config.get("api_key", "")
        self._models[model_id] = {
            "provider": config.get("provider", "openai_compatible"),
            "base_url": config.get("base_url", "").rstrip("/"),
            "model_name": config.get("model_name", name),
            "temperature": config.get("temperature", 0.7),
            "max_tokens": config.get("max_tokens", 4096),
            "is_preset": False,
            "api_key": self._encrypt_key(raw_key),
        }
        logger.info(f"Added custom model: {model_id} ({config.get('model_name', name)})")
        return model_id

    def remove_custom_model(self, model_id: str) -> bool:
        if model_id not in self._models:
            return False
        if self._models[model_id].get("is_preset", False):
            return False
        if model_id == self._current_model_id:
            return False
        del self._models[model_id]
        logger.info(f"Removed custom model: {model_id}")
        return True

    def get_current_model(self) -> Dict:
        if self._current_model_id not in self._models:
            return {
                "model_id": self._current_model_id,
                "name": self.model_name,
                "provider": "deepseek" if self._is_deepseek else "openai",
                "base_url": self.base_url,
                "model_name": self.model_name,
                "temperature": self.default_temperature,
                "max_tokens": self.default_max_tokens,
                "is_active": True,
            }
        mcfg = self._models[self._current_model_id]
        entry = {
            "model_id": self._current_model_id,
            "name": mcfg.get("model_name", self.model_name),
            "provider": mcfg.get("provider", "openai_compatible"),
            "base_url": mcfg.get("base_url", self.base_url),
            "model_name": mcfg.get("model_name", self.model_name),
            "temperature": mcfg.get("temperature", self.default_temperature),
            "max_tokens": mcfg.get("max_tokens", self.default_max_tokens),
            "is_preset": mcfg.get("is_preset", False),
            "is_active": True,
        }
        if mcfg.get("api_key"):
            key = self._decrypt_key(mcfg["api_key"])
            entry["api_key_preview"] = "****" + key[-4:] if len(key) >= 4 else "****"
        else:
            entry["api_key_preview"] = ""
        return entry

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            timeout_config = httpx.Timeout(180.0, connect=30.0)
            if self._is_deepseek:
                timeout_config = httpx.Timeout(240.0, connect=30.0)
            self._client = httpx.AsyncClient(
                timeout=timeout_config,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    @property
    def is_available(self) -> bool:
        if not self.api_key or not self.api_key.strip():
            return False
        if self.circuit_breaker_state == "open":
            return False
        return True

    @property
    def usage_stats(self) -> Dict:
        return {
            "request_count": self._request_count,
            "total_tokens": self._total_tokens,
            "model": self.model_name,
            "provider": "deepseek" if self._is_deepseek else "openai",
        }

    @property
    def circuit_breaker_state(self) -> str:
        if self._cb_failures < self._cb_threshold:
            return "closed"
        if self._cb_opened_at is None:
            return "closed"
        elapsed = time.monotonic() - self._cb_opened_at
        if elapsed >= self._cb_recovery_timeout:
            return "half_open"
        return "open"

    def _check_circuit_breaker(self):
        state = self.circuit_breaker_state
        if state == "open":
            raise RuntimeError("Circuit breaker is open - LLM service unavailable")

    def _record_success(self):
        self._cb_failures = 0
        self._cb_opened_at = None

    def _record_failure(self):
        self._cb_failures += 1
        if self._cb_failures >= self._cb_threshold and self._cb_opened_at is None:
            self._cb_opened_at = time.monotonic()
            logger.warning(f"Circuit breaker opened after {self._cb_failures} failures, recovery in {self._cb_recovery_timeout}s")

    async def _retry_request(self, request_fn):
        delay = self._base_delay
        last_exception = None
        for attempt in range(self._max_retries):
            try:
                return await request_fn()
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                if status_code == 429:
                    retry_after = exc.response.headers.get("retry-after")
                    if retry_after:
                        try:
                            wait_time = float(retry_after)
                        except ValueError:
                            wait_time = delay
                    else:
                        wait_time = min(delay * 2, 30.0)
                    logger.warning(
                        f"Rate limited (429), retrying in {wait_time:.1f}s "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                    await asyncio.sleep(wait_time)
                    delay = min(delay * 2, 60.0)
                    last_exception = exc
                elif status_code >= 500:
                    logger.warning(
                        f"Server error {status_code}, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60.0)
                    last_exception = exc
                else:
                    logger.error(f"HTTP error {status_code}: {exc.response.text}")
                    # 402(余额不足)/401(无效Key) 是不可恢复的，立即熔断不重试
                    if status_code in (401, 402, 403):
                        self._record_failure()
                        # 连续3次不可恢复错误则长期熔断（10分钟）
                        if self._cb_failures >= 3:
                            self._cb_opened_at = time.monotonic()
                            self._cb_recovery_timeout = 600.0
                            logger.warning(
                                f"Permanent auth/balance error ({status_code}), "
                                f"circuit breaker opened for 600s"
                            )
                    raise
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                logger.warning(
                    f"Connection error: {exc}, retrying in {delay:.1f}s "
                    f"(attempt {attempt + 1}/{self._max_retries})"
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)
                last_exception = exc
            except Exception as exc:
                logger.error(f"Unexpected error during LLM request: {exc}")
                raise
        raise last_exception or RuntimeError("Max retries exceeded")

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        self._check_circuit_breaker()
        self._check_daily_token_limit()

        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")
        input_len = len(prompt) + len(system_prompt)
        if input_len > self.MAX_INPUT_LENGTH:
            raise ValueError(
                f"Input length ({input_len}) exceeds maximum allowed ({self.MAX_INPUT_LENGTH})"
            )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async def _request():
            client = await self._get_client()
            payload = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if self._is_deepseek:
                payload["top_p"] = 0.9
                payload["frequency_penalty"] = 0.1
                payload["presence_penalty"] = 0.1

            response = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            async with self._stats_lock:
                self._request_count += 1
                usage = data.get("usage", {})
                if usage:
                    tokens_used = usage.get("total_tokens", 0)
                    self._total_tokens += tokens_used
                    self._daily_tokens_used += tokens_used
            return data["choices"][0]["message"]["content"], data.get("usage", {})

        delay = self._generate_retry_base_delay
        last_exception = None
        tracer = get_tracer("llm")
        with tracer.start_as_current_span("llm.generate") as span:
            span.set_attribute("llm.model", self.model_name)
            span.set_attribute("llm.prompt_length", input_len)
            try:
                for attempt in range(self._generate_retries):
                    try:
                        generate_start = time.monotonic()
                        result, usage = await self._retry_request(_request)
                        generate_duration = time.monotonic() - generate_start
                        self._record_success()
                        LLM_CALL_COUNT.labels(model=self.model_name, status='success').inc()
                        LLM_CALL_DURATION.labels(model=self.model_name).observe(generate_duration)
                        if usage:
                            span.set_attribute("llm.usage.prompt_tokens", usage.get("prompt_tokens", 0))
                            span.set_attribute("llm.usage.completion_tokens", usage.get("completion_tokens", 0))
                            span.set_attribute("llm.usage.total_tokens", usage.get("total_tokens", 0))
                            prompt_tokens = usage.get("prompt_tokens", 0)
                            completion_tokens = usage.get("completion_tokens", 0)
                            if prompt_tokens:
                                LLM_TOKENS_USED.labels(model=self.model_name, type='prompt').inc(prompt_tokens)
                            if completion_tokens:
                                LLM_TOKENS_USED.labels(model=self.model_name, type='completion').inc(completion_tokens)
                        return result
                    except Exception as exc:
                        last_exception = exc
                        self._record_failure()
                        LLM_CALL_COUNT.labels(model=self.model_name, status='error').inc()
                        if self.circuit_breaker_state == "open":
                            logger.error("Circuit breaker opened, stopping generate retries")
                            break
                        if attempt < self._generate_retries - 1:
                            logger.warning(
                                f"Generate attempt {attempt + 1}/{self._generate_retries} failed: {exc}, "
                                f"retrying in {delay:.1f}s"
                            )
                            await asyncio.sleep(delay)
                            delay = min(delay * 2, 30.0)

                logger.error(
                    f"Generate failed after {self._generate_retries} attempts. "
                    f"Model: {self.model_name}, Prompt length: {input_len}, "
                    f"Last error: {last_exception}"
                )
                span.set_attribute("error", True)
                span.set_attribute("error.message", str(last_exception))
                raise last_exception or RuntimeError("Generate failed")
            except Exception:
                raise

    async def chat(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> str:
        return await self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def generate_json(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_retries: int = 2,
    ) -> dict:
        json_system = system_prompt
        if not json_system:
            json_system = "You are a helpful assistant that responds in valid JSON format."
        elif "json" not in json_system.lower():
            json_system += "\n\nYou must respond with valid JSON only. No markdown, no explanation, just pure JSON."

        last_raw = ""
        for attempt in range(max_retries + 1):
            current_prompt = prompt
            if attempt > 0 and last_raw:
                current_prompt = (
                    f"{prompt}\n\n"
                    f"你之前的回复不是有效的JSON格式，请修正。"
                    f"你之前的回复开头为：{last_raw[:300]}\n"
                    f"请只返回纯JSON，不要包含任何其他文字或markdown标记。"
                )
                logger.info(f"generate_json retry attempt {attempt + 1}")

            raw = await self.generate(
                prompt=current_prompt,
                system_prompt=json_system,
                temperature=temperature,
                max_tokens=self.default_max_tokens,
            )
            last_raw = raw

            cleaned = raw.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[len("```json"):]
            elif cleaned.startswith("```"):
                cleaned = cleaned[len("```"):]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-len("```")]
            cleaned = cleaned.strip()

            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                start = cleaned.find("{")
                end = cleaned.rfind("}") + 1
                if start != -1 and end > start:
                    try:
                        return json.loads(cleaned[start:end])
                    except json.JSONDecodeError:
                        pass
                start = cleaned.find("[")
                end = cleaned.rfind("]") + 1
                if start != -1 and end > start:
                    try:
                        return json.loads(cleaned[start:end])
                    except json.JSONDecodeError:
                        pass

        logger.error(f"Could not parse JSON from LLM response after {max_retries + 1} attempts: {last_raw[:500]}")
        raise ValueError(f"LLM did not return valid JSON after {max_retries + 1} attempts: {last_raw[:200]}")

    async def generate_stream(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.7,
    ) -> AsyncGenerator[str, None]:
        self._check_circuit_breaker()
        self._check_daily_token_limit()
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        client = await self._get_client()
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.default_max_tokens,
            "stream": True,
        }
        if self._is_deepseek:
            payload["top_p"] = 0.9

        delay = self._base_delay
        for attempt in range(self._max_retries):
            try:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    timeout=httpx.Timeout(180.0, connect=30.0),
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[len("data: "):]
                        if data_str.strip() == "[DONE]":
                            return
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
                self._record_success()
                async with self._stats_lock:
                    self._request_count += 1
                return
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                if status_code == 429 or status_code >= 500:
                    self._record_failure()
                    logger.warning(
                        f"Stream error {status_code}, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self._max_retries})"
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 60.0)
                else:
                    logger.error(f"Stream HTTP error {status_code}: {exc.response.text}")
                    raise
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                self._record_failure()
                logger.warning(
                    f"Stream connection error: {exc}, retrying in {delay:.1f}s "
                    f"(attempt {attempt + 1}/{self._max_retries})"
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

        self._record_failure()
        raise RuntimeError("Max retries exceeded for streaming request")

    async def analyze_intelligence_batch(
        self,
        items: List[Dict],
        analysis_type: str = "classify",
    ) -> Dict:
        if not items:
            return {"status": "error", "message": "No items to analyze"}

        contents = []
        for item in items[:30]:
            content = item.get("content", "")
            if content:
                contents.append(content[:500])

        if not contents:
            return {"status": "error", "message": "No content to analyze"}

        combined = "\n---\n".join(
            f"[情报{i+1}] {c}" for i, c in enumerate(contents)
        )

        if analysis_type == "classify":
            return await self._classify_batch(combined, len(contents))
        elif analysis_type == "validate":
            return await self._validate_batch(combined, len(contents))
        elif analysis_type == "summarize":
            return await self._summarize_batch(combined, len(contents))
        elif analysis_type == "full":
            return await self._full_analysis_batch(combined, len(contents))
        else:
            return await self._classify_batch(combined, len(contents))

    async def _classify_batch(self, combined: str, count: int) -> Dict:
        system_prompt = DEEPSEEK_THREAT_INTEL_SYSTEM
        prompt = (
            f"请对以下{count}条情报进行分类和归类。对每条情报：\n"
            f"1. 判断威胁类别（fraud/gambling/hacking/money_laundering/data_theft/phishing/ransomware/drug/other）\n"
            f"2. 评估威胁等级（critical/high/medium/low/info）\n"
            f"3. 提取关键实体（IP/域名/手机号/工具/组织等）\n"
            f"4. 评估信息可靠性（0-1置信度，考虑来源可信度、信息一致性、时效性）\n\n"
            f"返回JSON对象：\n"
            f'{{"results": [{{"index": 1, "threat_category": "...", "threat_level": "...", '
            f'"key_entities": [{{"type": "...", "value": "..."}}], '
            f'"reliability": 0.0-1.0, "reliability_reason": "..."}}], '
            f'"category_summary": {{"fraud": 0, "hacking": 0}}, '
            f'"overall_assessment": "总体评估摘要"}}\n\n'
            f"情报内容：\n{combined}"
        )
        try:
            result = await self.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
            )
            return {"status": "success", "data": result}
        except Exception as exc:
            logger.error(f"Batch classification failed: {exc}")
            return {"status": "error", "message": "模型调用失败"}

    async def _validate_batch(self, combined: str, count: int) -> Dict:
        system_prompt = DEEPSEEK_THREAT_INTEL_SYSTEM
        prompt = (
            f"请验证以下{count}条情报的真实性和可靠性。对每条情报：\n"
            f"1. 判断信息是否可能为真（考虑逻辑一致性、技术可行性、来源可信度）\n"
            f"2. 识别其中的虚假/过时/矛盾信息\n"
            f"3. 标注需要进一步验证的关键声明\n"
            f"4. 给出可靠性评分和理由\n\n"
            f"返回JSON对象：\n"
            f'{{"results": [{{"index": 1, "is_likely_true": true/false, '
            f'"reliability_score": 0.0-1.0, "issues": ["..."], '
            f'"needs_verification": ["..."], "reason": "..."}}], '
            f'"validation_summary": "总体验证摘要"}}\n\n'
            f"情报内容：\n{combined}"
        )
        try:
            result = await self.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
            )
            return {"status": "success", "data": result}
        except Exception as exc:
            logger.error(f"Batch validation failed: {exc}")
            return {"status": "error", "message": "模型调用失败"}

    async def _summarize_batch(self, combined: str, count: int) -> Dict:
        system_prompt = DEEPSEEK_THREAT_INTEL_SYSTEM
        prompt = (
            f"请对以下{count}条情报进行归纳总结：\n"
            f"1. 提取主要威胁主题和趋势\n"
            f"2. 识别重复/关联的情报\n"
            f"3. 归纳攻击模式和手法\n"
            f"4. 生成综合分析报告\n\n"
            f"返回JSON对象：\n"
            f'{{"main_themes": ["..."], "related_groups": [{{"theme": "...", "indices": [1,2]}}], '
            f'"attack_patterns": [{{"name": "...", "description": "..."}}], '
            f'"summary": "综合分析摘要", "key_findings": ["..."], '
            f'"recommendations": ["..."]}}\n\n'
            f"情报内容：\n{combined}"
        )
        try:
            result = await self.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            return {"status": "success", "data": result}
        except Exception as exc:
            logger.error(f"Batch summarization failed: {exc}")
            return {"status": "error", "message": "模型调用失败"}

    async def _full_analysis_batch(self, combined: str, count: int) -> Dict:
        system_prompt = DEEPSEEK_THREAT_INTEL_SYSTEM
        prompt = (
            f"请对以下{count}条情报进行全面深度分析，包括：\n"
            f"1. 逐条分类（威胁类别+等级+可靠性）\n"
            f"2. 信息真实性验证（识别虚假/矛盾/过时信息）\n"
            f"3. 攻击链重建（资源获取→工具准备→攻击执行→资金流转）\n"
            f"4. 关联分析（情报间的关联和模式）\n"
            f"5. 综合总结和预警建议\n\n"
            f"返回JSON对象：\n"
            f'{{"classification": [{{"index": 1, "category": "...", "level": "...", '
            f'"reliability": 0.0-1.0}}], '
            f'"validation": {{"reliable_count": 0, "suspicious_count": 0, "issues": ["..."]}}, '
            f'"attack_chains": [{{"stages": ["..."], "confidence": 0.0-1.0}}], '
            f'"correlations": [{{"type": "...", "involved_indices": [1,2], "description": "..."}}], '
            f'"summary": "综合分析摘要", "alerts": ["..."], '
            f'"recommendations": ["..."]}}\n\n'
            f"情报内容：\n{combined}"
        )
        try:
            result = await self.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            return {"status": "success", "data": result}
        except Exception as exc:
            logger.error(f"Full batch analysis failed: {exc}")
            return {"status": "error", "message": "模型调用失败"}

    async def embed(self, text: str) -> List[float]:
        try:
            client = await self._get_client()
            resp = await client.post(
                f"{self.base_url}/embeddings",
                json={"model": "text-embedding-v3", "input": text},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                vec = data["data"][0]["embedding"]
                return vec
            logger.warning(f"Embedding API returned {resp.status_code}, falling back to hash embedding")
        except Exception as exc:
            logger.warning(f"Embedding API failed: {exc}, falling back to hash embedding")
        return _hash_embedding(text)

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        if len(texts) <= 64:
            try:
                client = await self._get_client()
                resp = await client.post(
                    f"{self.base_url}/embeddings",
                    json={"model": "text-embedding-v3", "input": texts},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=60.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [d["embedding"] for d in sorted(data["data"], key=lambda x: x["index"])]
                logger.warning(f"Batch embedding API returned {resp.status_code}, falling back")
            except Exception as exc:
                logger.warning(f"Batch embedding API failed: {exc}, falling back")
        return [_hash_embedding(t) for t in texts]
