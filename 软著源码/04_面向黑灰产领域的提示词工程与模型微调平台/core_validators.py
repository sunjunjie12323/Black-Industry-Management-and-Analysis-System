import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ValidationLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]

    def to_dict(self) -> Dict:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }


class PromptTemplateValidator:
    VALID_CATEGORIES = {"analysis", "generation", "translation", "extraction", "summarization", "classification", "threat_intel", "attack_chain", "blacktalk", "custom"}
    MAX_NAME_LENGTH = 256
    MAX_CONTENT_LENGTH = 10000
    MAX_TAGS = 20
    MAX_TAG_LENGTH = 50
    MAX_VARIABLES = 20

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        name = data.get("name", "")
        if not name or not name.strip():
            errors.append({"field": "name", "message": "模板名称不能为空", "level": ValidationLevel.ERROR.value})
        elif len(name) > cls.MAX_NAME_LENGTH:
            errors.append({"field": "name", "message": f"模板名称不能超过{cls.MAX_NAME_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        category = data.get("category", "")
        if not category:
            errors.append({"field": "category", "message": "分类不能为空", "level": ValidationLevel.ERROR.value})
        elif category not in cls.VALID_CATEGORIES:
            errors.append({"field": "category", "message": f"无效分类: {category}，可选: {cls.VALID_CATEGORIES}", "level": ValidationLevel.ERROR.value})

        content = data.get("content", "")
        if not content or not content.strip():
            errors.append({"field": "content", "message": "模板内容不能为空", "level": ValidationLevel.ERROR.value})
        elif len(content) > cls.MAX_CONTENT_LENGTH:
            errors.append({"field": "content", "message": f"模板内容不能超过{cls.MAX_CONTENT_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        content_vars = set(re.findall(r'\{\{(\w+)\}\}', content))
        if not content_vars:
            warnings.append({"field": "content", "message": "模板内容未包含任何变量占位符{{variable}}", "level": ValidationLevel.WARNING.value})

        variables = data.get("variables", [])
        if isinstance(variables, str):
            try:
                variables = json.loads(variables)
            except (json.JSONDecodeError, TypeError):
                variables = []

        if len(variables) > cls.MAX_VARIABLES:
            errors.append({"field": "variables", "message": f"变量数量不能超过{cls.MAX_VARIABLES}个", "level": ValidationLevel.ERROR.value})

        defined_var_names = set()
        for var in variables:
            var_name = var.get("name", "") if isinstance(var, dict) else ""
            if not var_name:
                errors.append({"field": "variables", "message": "变量名不能为空", "level": ValidationLevel.ERROR.value})
            elif not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name):
                errors.append({"field": "variables", "message": f"变量名'{var_name}'不是合法标识符", "level": ValidationLevel.ERROR.value})
            else:
                defined_var_names.add(var_name)

        missing_in_def = content_vars - defined_var_names
        if missing_in_def:
            warnings.append({"field": "variables", "message": f"模板中使用的变量{missing_in_def}未在variables中定义", "level": ValidationLevel.WARNING.value})

        missing_in_content = defined_var_names - content_vars
        if missing_in_content:
            warnings.append({"field": "content", "message": f"定义的变量{missing_in_content}未在模板内容中使用", "level": ValidationLevel.WARNING.value})

        tags = data.get("tags", [])
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, TypeError):
                tags = []
        if len(tags) > cls.MAX_TAGS:
            errors.append({"field": "tags", "message": f"标签数量不能超过{cls.MAX_TAGS}个", "level": ValidationLevel.ERROR.value})
        for tag in tags:
            if len(str(tag)) > cls.MAX_TAG_LENGTH:
                errors.append({"field": "tags", "message": f"标签'{tag}'超过{cls.MAX_TAG_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class PreprocessTaskValidator:
    VALID_TASK_TYPES = {"import", "clean", "label", "augment", "format_convert"}
    VALID_STATUSES = {"pending", "running", "completed", "failed", "cancelled"}
    MAX_NAME_LENGTH = 256

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        name = data.get("name", "")
        if not name or not name.strip():
            errors.append({"field": "name", "message": "任务名称不能为空", "level": ValidationLevel.ERROR.value})
        elif len(name) > cls.MAX_NAME_LENGTH:
            errors.append({"field": "name", "message": f"任务名称不能超过{cls.MAX_NAME_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        task_type = data.get("task_type", "")
        if not task_type:
            errors.append({"field": "task_type", "message": "任务类型不能为空", "level": ValidationLevel.ERROR.value})
        elif task_type not in cls.VALID_TASK_TYPES:
            errors.append({"field": "task_type", "message": f"无效任务类型: {task_type}", "level": ValidationLevel.ERROR.value})

        status = data.get("status", "pending")
        if status not in cls.VALID_STATUSES:
            errors.append({"field": "status", "message": f"无效状态: {status}", "level": ValidationLevel.ERROR.value})

        progress = data.get("progress", 0.0)
        if not (0.0 <= progress <= 1.0):
            errors.append({"field": "progress", "message": "进度值必须在0-1之间", "level": ValidationLevel.ERROR.value})

        pipeline_steps = data.get("pipeline_steps", [])
        if isinstance(pipeline_steps, str):
            try:
                pipeline_steps = json.loads(pipeline_steps)
            except (json.JSONDecodeError, TypeError):
                pipeline_steps = []

        for i, step in enumerate(pipeline_steps):
            if isinstance(step, dict):
                step_type = step.get("step_type", "")
                if step_type not in cls.VALID_TASK_TYPES:
                    errors.append({"field": f"pipeline_steps[{i}].step_type", "message": f"无效步骤类型: {step_type}", "level": ValidationLevel.ERROR.value})
                order = step.get("order", 0)
                if order < 0:
                    errors.append({"field": f"pipeline_steps[{i}].order", "message": "步骤顺序不能为负数", "level": ValidationLevel.ERROR.value})

        if pipeline_steps:
            orders = [s.get("order", 0) if isinstance(s, dict) else 0 for s in pipeline_steps]
            if orders != sorted(orders):
                warnings.append({"field": "pipeline_steps", "message": "步骤未按order升序排列", "level": ValidationLevel.WARNING.value})

        if status == "running" and not data.get("started_at"):
            warnings.append({"field": "started_at", "message": "运行中的任务应设置started_at", "level": ValidationLevel.WARNING.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class FinetuneTaskValidator:
    VALID_METHODS = {"lora", "full"}
    VALID_STATUSES = {"pending", "preparing", "training", "evaluating", "completed", "failed"}
    MAX_NAME_LENGTH = 256

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        name = data.get("name", "")
        if not name or not name.strip():
            errors.append({"field": "name", "message": "任务名称不能为空", "level": ValidationLevel.ERROR.value})
        elif len(name) > cls.MAX_NAME_LENGTH:
            errors.append({"field": "name", "message": f"任务名称不能超过{cls.MAX_NAME_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        method = data.get("method", "")
        if not method:
            errors.append({"field": "method", "message": "微调方法不能为空", "level": ValidationLevel.ERROR.value})
        elif method not in cls.VALID_METHODS:
            errors.append({"field": "method", "message": f"无效方法: {method}，可选: {cls.VALID_METHODS}", "level": ValidationLevel.ERROR.value})

        base_model = data.get("base_model", "")
        if not base_model or not base_model.strip():
            errors.append({"field": "base_model", "message": "基础模型不能为空", "level": ValidationLevel.ERROR.value})

        config = data.get("config_json", "{}")
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}

        if method == "lora":
            lora_r = config.get("lora_r", 16)
            if not (4 <= lora_r <= 256):
                errors.append({"field": "config.lora_r", "message": f"LoRA r必须在4-256之间，当前值: {lora_r}", "level": ValidationLevel.ERROR.value})
            lora_alpha = config.get("lora_alpha", 32)
            if not (1 <= lora_alpha <= 512):
                errors.append({"field": "config.lora_alpha", "message": f"LoRA alpha必须在1-512之间，当前值: {lora_alpha}", "level": ValidationLevel.ERROR.value})

        elif method == "full":
            lr = config.get("learning_rate", 2e-5)
            if not (1e-7 <= lr <= 1e-3):
                errors.append({"field": "config.learning_rate", "message": f"学习率必须在1e-7~1e-3之间，当前值: {lr}", "level": ValidationLevel.ERROR.value})

        progress = data.get("progress", 0)
        if not isinstance(progress, (int, float)) or not (0 <= progress <= 100):
            errors.append({"field": "progress", "message": "进度值必须在0-100之间", "level": ValidationLevel.ERROR.value})

        status = data.get("status", "pending")
        if status not in cls.VALID_STATUSES:
            errors.append({"field": "status", "message": f"无效状态: {status}，可选: {cls.VALID_STATUSES}", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class QAConversationValidator:
    VALID_ROLES = {"user", "assistant", "system"}
    MAX_MESSAGE_LENGTH = 10000
    MAX_MESSAGES = 200
    VALID_INDUSTRIES = {"manufacturing", "education", "healthcare", "finance"}

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        title = data.get("title", "")
        if not title or not title.strip():
            errors.append({"field": "title", "message": "对话标题不能为空", "level": ValidationLevel.ERROR.value})

        messages = data.get("messages", [])
        if isinstance(messages, str):
            try:
                messages = json.loads(messages)
            except (json.JSONDecodeError, TypeError):
                messages = []

        if len(messages) > cls.MAX_MESSAGES:
            warnings.append({"field": "messages", "message": f"消息数超过{cls.MAX_MESSAGES}条，建议进行摘要压缩", "level": ValidationLevel.WARNING.value})

        for i, msg in enumerate(messages):
            if isinstance(msg, dict):
                role = msg.get("role", "")
                if role not in cls.VALID_ROLES:
                    errors.append({"field": f"messages[{i}].role", "message": f"无效角色: {role}", "level": ValidationLevel.ERROR.value})
                content = msg.get("content", "")
                if len(content) > cls.MAX_MESSAGE_LENGTH:
                    errors.append({"field": f"messages[{i}].content", "message": f"消息内容超过{cls.MAX_MESSAGE_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        industry = data.get("industry")
        if industry and industry not in cls.VALID_INDUSTRIES:
            errors.append({"field": "industry", "message": f"无效行业: {industry}，可选: {cls.VALID_INDUSTRIES}", "level": ValidationLevel.ERROR.value})

        model_id = data.get("model_id")
        if model_id is not None and len(str(model_id)) > 100:
            errors.append({"field": "model_id", "message": "模型ID不能超过100字符", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class GeneratedContentValidator:
    VALID_CONTENT_TYPES = {"report_summary", "intel_brief", "security_advice", "trend_analysis", "threat_assessment", "attack_chain_analysis", "threat_situation_brief", "high_risk_alert", "ioc_report", "crime_pattern_analysis"}
    VALID_REVIEW_STATUSES = {"pending", "auto_checked", "expert_reviewed", "supervisor_approved", "approved", "rejected", "revised"}
    MAX_CONTENT_LENGTH = 100000
    SENSITIVE_PATTERNS = [
        (r"密码[是为：:]\s*\S+", "疑似密码泄露"),
        (r"api[_-]?key[=:]\s*\S+", "疑似API密钥泄露"),
        (r"secret[=:]\s*\S+", "疑似密钥泄露"),
    ]

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        title = data.get("title", "")
        if not title or not title.strip():
            errors.append({"field": "title", "message": "内容标题不能为空", "level": ValidationLevel.ERROR.value})

        content_type = data.get("content_type", "")
        if not content_type:
            errors.append({"field": "content_type", "message": "内容类型不能为空", "level": ValidationLevel.ERROR.value})
        elif content_type not in cls.VALID_CONTENT_TYPES:
            errors.append({"field": "content_type", "message": f"无效内容类型: {content_type}", "level": ValidationLevel.ERROR.value})

        content = data.get("content", "")
        if not content or not content.strip():
            errors.append({"field": "content", "message": "内容不能为空", "level": ValidationLevel.ERROR.value})
        elif len(content) > cls.MAX_CONTENT_LENGTH:
            errors.append({"field": "content", "message": f"内容不能超过{cls.MAX_CONTENT_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        review_status = data.get("review_status", "pending")
        if review_status not in cls.VALID_REVIEW_STATUSES:
            errors.append({"field": "review_status", "message": f"无效审核状态: {review_status}", "level": ValidationLevel.ERROR.value})

        if review_status == "rejected" and not data.get("review_comment"):
            warnings.append({"field": "review_comment", "message": "拒绝时应填写审核意见", "level": ValidationLevel.WARNING.value})

        if review_status in ("approved", "expert_reviewed", "supervisor_approved") and not data.get("reviewer"):
            warnings.append({"field": "reviewer", "message": "审核通过时应记录审核人", "level": ValidationLevel.WARNING.value})

        model_id = data.get("model_id")
        if model_id is not None and len(str(model_id)) > 100:
            errors.append({"field": "model_id", "message": "模型ID不能超过100字符", "level": ValidationLevel.ERROR.value})

        prompt_template_id = data.get("prompt_template_id")
        if prompt_template_id is not None and len(str(prompt_template_id)) > 100:
            errors.append({"field": "prompt_template_id", "message": "提示词模板ID不能超过100字符", "level": ValidationLevel.ERROR.value})

        for pattern, desc in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                warnings.append({"field": "content", "message": f"检测到敏感信息: {desc}", "level": ValidationLevel.WARNING.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class IndustryConfigValidator:
    VALID_INDUSTRIES = {"threat_intel", "general"}

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        industry = data.get("industry", "")
        if not industry:
            errors.append({"field": "industry", "message": "行业类型不能为空", "level": ValidationLevel.ERROR.value})
        elif industry not in cls.VALID_INDUSTRIES:
            errors.append({"field": "industry", "message": f"无效行业: {industry}，可选: {cls.VALID_INDUSTRIES}", "level": ValidationLevel.ERROR.value})

        name = data.get("name", "")
        if not name or not name.strip():
            errors.append({"field": "name", "message": "配置名称不能为空", "level": ValidationLevel.ERROR.value})

        description = data.get("description", "")
        if not description or not description.strip():
            errors.append({"field": "description", "message": "配置描述不能为空", "level": ValidationLevel.ERROR.value})
        elif len(description) > 2000:
            errors.append({"field": "description", "message": "配置描述不能超过2000字符", "level": ValidationLevel.ERROR.value})

        model_config = data.get("model_config_json", "{}")
        if isinstance(model_config, str):
            try:
                model_config = json.loads(model_config)
            except (json.JSONDecodeError, TypeError):
                model_config = {}
        if isinstance(model_config, dict) and "model_id" not in model_config:
            warnings.append({"field": "model_config_json", "message": "建议配置model_id字段", "level": ValidationLevel.WARNING.value})

        prompt_templates = data.get("prompt_templates", [])
        if isinstance(prompt_templates, str):
            try:
                prompt_templates = json.loads(prompt_templates)
            except (json.JSONDecodeError, TypeError):
                prompt_templates = []
        if not prompt_templates:
            warnings.append({"field": "prompt_templates", "message": "未关联任何提示词模板", "level": ValidationLevel.WARNING.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class IndustrySceneConfigValidator:
    VALID_INDUSTRIES = {"smart_manufacturing", "smart_education", "healthcare", "financial_services"}
    MAX_NAME_LENGTH = 256
    MAX_DESCRIPTION_LENGTH = 2000

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        industry = data.get("industry", "")
        if not industry:
            errors.append({"field": "industry", "message": "行业场景不能为空", "level": ValidationLevel.ERROR.value})
        elif industry not in cls.VALID_INDUSTRIES:
            errors.append({"field": "industry", "message": f"无效行业场景: {industry}，可选: {cls.VALID_INDUSTRIES}", "level": ValidationLevel.ERROR.value})

        name = data.get("name", "")
        if not name or not name.strip():
            errors.append({"field": "name", "message": "配置名称不能为空", "level": ValidationLevel.ERROR.value})
        elif len(name) > cls.MAX_NAME_LENGTH:
            errors.append({"field": "name", "message": f"配置名称不能超过{cls.MAX_NAME_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        description = data.get("description", "")
        if len(description) > cls.MAX_DESCRIPTION_LENGTH:
            errors.append({"field": "description", "message": f"描述不能超过{cls.MAX_DESCRIPTION_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        config_json = data.get("config_json", "")
        if config_json:
            if isinstance(config_json, str):
                try:
                    json.loads(config_json)
                except (json.JSONDecodeError, TypeError):
                    errors.append({"field": "config_json", "message": "config_json不是有效的JSON", "level": ValidationLevel.ERROR.value})
            elif not isinstance(config_json, dict):
                errors.append({"field": "config_json", "message": "config_json必须是JSON对象或字符串", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class AnalysisResultValidator:
    VALID_THREAT_LEVELS = {"critical", "high", "medium", "low", "info"}

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        analysis_type = data.get("analysis_type", "")
        if not analysis_type or not str(analysis_type).strip():
            errors.append({"field": "analysis_type", "message": "分析类型不能为空", "level": ValidationLevel.ERROR.value})

        threat_level = data.get("threat_level")
        if threat_level is not None:
            if threat_level not in cls.VALID_THREAT_LEVELS:
                errors.append({"field": "threat_level", "message": f"无效威胁等级: {threat_level}，可选: {cls.VALID_THREAT_LEVELS}", "level": ValidationLevel.ERROR.value})

        confidence = data.get("confidence")
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
                errors.append({"field": "confidence", "message": "置信度必须在0.0-1.0之间", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class TranslationMemoryValidator:
    MAX_LANG_LENGTH = 10

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        source_text = data.get("source_text", "")
        if not source_text or not str(source_text).strip():
            errors.append({"field": "source_text", "message": "源文本不能为空", "level": ValidationLevel.ERROR.value})

        target_text = data.get("target_text", "")
        if not target_text or not str(target_text).strip():
            errors.append({"field": "target_text", "message": "目标文本不能为空", "level": ValidationLevel.ERROR.value})

        source_lang = data.get("source_lang", "")
        if not source_lang or not str(source_lang).strip():
            errors.append({"field": "source_lang", "message": "源语言不能为空", "level": ValidationLevel.ERROR.value})
        elif len(str(source_lang)) > cls.MAX_LANG_LENGTH:
            errors.append({"field": "source_lang", "message": f"源语言代码不能超过{cls.MAX_LANG_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        target_lang = data.get("target_lang", "")
        if not target_lang or not str(target_lang).strip():
            errors.append({"field": "target_lang", "message": "目标语言不能为空", "level": ValidationLevel.ERROR.value})
        elif len(str(target_lang)) > cls.MAX_LANG_LENGTH:
            errors.append({"field": "target_lang", "message": f"目标语言代码不能超过{cls.MAX_LANG_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class TerminologyValidator:
    MAX_TERM_LENGTH = 200

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        term = data.get("term", "")
        if not term or not str(term).strip():
            errors.append({"field": "term", "message": "术语不能为空", "level": ValidationLevel.ERROR.value})
        elif len(str(term)) > cls.MAX_TERM_LENGTH:
            errors.append({"field": "term", "message": f"术语不能超过{cls.MAX_TERM_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        translation = data.get("translation", "")
        if not translation or not str(translation).strip():
            errors.append({"field": "translation", "message": "翻译不能为空", "level": ValidationLevel.ERROR.value})
        elif len(str(translation)) > cls.MAX_TERM_LENGTH:
            errors.append({"field": "translation", "message": f"翻译不能超过{cls.MAX_TERM_LENGTH}字符", "level": ValidationLevel.ERROR.value})

        source_lang = data.get("source_lang", "")
        if not source_lang or not str(source_lang).strip():
            errors.append({"field": "source_lang", "message": "源语言不能为空", "level": ValidationLevel.ERROR.value})

        target_lang = data.get("target_lang", "")
        if not target_lang or not str(target_lang).strip():
            errors.append({"field": "target_lang", "message": "目标语言不能为空", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


class AnalyticsResultValidator:

    @classmethod
    def validate(cls, data: Dict[str, Any]) -> ValidationResult:
        errors = []
        warnings = []

        query_type = data.get("query_type", "")
        if not query_type or not str(query_type).strip():
            errors.append({"field": "query_type", "message": "查询类型不能为空", "level": ValidationLevel.ERROR.value})

        result_data = data.get("result_data")
        if result_data is not None:
            if isinstance(result_data, str):
                try:
                    json.loads(result_data)
                except (json.JSONDecodeError, TypeError):
                    errors.append({"field": "result_data", "message": "result_data不是有效的JSON", "level": ValidationLevel.ERROR.value})
            elif not isinstance(result_data, (dict, list)):
                errors.append({"field": "result_data", "message": "result_data必须是JSON对象、数组或字符串", "level": ValidationLevel.ERROR.value})

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


VALIDATORS = {
    "prompt_template": PromptTemplateValidator,
    "preprocess_task": PreprocessTaskValidator,
    "finetune_task": FinetuneTaskValidator,
    "qa_conversation": QAConversationValidator,
    "generated_content": GeneratedContentValidator,
    "industry_config": IndustryConfigValidator,
    "industry_scene_config": IndustrySceneConfigValidator,
    "analysis_result": AnalysisResultValidator,
    "translation_memory": TranslationMemoryValidator,
    "terminology": TerminologyValidator,
    "analytics_result": AnalyticsResultValidator,
}


def validate_domain_object(object_type: str, data: Dict[str, Any]) -> ValidationResult:
    validator = VALIDATORS.get(object_type)
    if not validator:
        return ValidationResult(
            is_valid=False,
            errors=[{"field": "object_type", "message": f"未知的领域对象类型: {object_type}", "level": ValidationLevel.ERROR.value}],
            warnings=[],
        )
    return validator.validate(data)
