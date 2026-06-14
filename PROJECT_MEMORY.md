# 黑灰产情报分析Agent — 项目记忆

## 项目概述
- 路径: `c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent`
- 后端: FastAPI + SQLAlchemy + SQLite/PostgreSQL
- 前端: React + TypeScript + Vite + GSAP
- LLM: DeepSeek API
- 启动: 后端 `uvicorn app.main:app --reload --port 8000`，前端 `npm run dev --port 5173`

## 核心架构

### 后端目录结构
```
backend/app/
├── api/          # 52个API路由模块
├── core/         # 核心引擎（20+个服务）
├── agents/       # AI代理（orchestrator/analyst/collector/cleaner/graph_builder）
├── db/           # 数据库（tables/crud/seed）
├── collectors/   # 数据采集器（telegram/forum/wechat/darkweb/realtime/commercial）
├── engine/       # 分析引擎+调度器
├── models/       # 数据模型
├── config.py     # 统一配置（所有参数走环境变量）
├── main.py       # 应用入口
└── service_registry.py  # 服务注册
```

### 核心引擎清单
| 引擎 | 文件 | 算法 | 状态 |
|------|------|------|------|
| LLM服务 | llm.py | DeepSeek API调用 | ✅ 真实LLM |
| 向量存储 | vector_store.py | TF-IDF+SVD本地嵌入(256维) | ✅ 真实算法 |
| 知识图谱 | knowledge_graph.py | NetworkX + Louvain社区检测 | ✅ 真实图算法 |
| 黑话引擎 | blacktalk_engine.py | 领域词典+向量语义匹配 | ✅ 真实NLP |
| 证据链 | evidence_chain.py | 交叉验证+可信度追踪+幻觉检测 | ✅ LLM+规则 |
| PIR引擎 | pir_engine.py | 检索增强推理 | ✅ RAG |
| 零日检测 | zero_day_detector.py | Skip-gram+KL散度+语义漂移 | ✅ 真实ML |
| 攻击链预测 | attack_chain_predictor.py | MITRE ATT&CK+马尔可夫链+蒙特卡洛 | ✅ 真实算法 |
| 实体归属 | entity_attribution.py | TransE知识图谱嵌入+行为指纹 | ✅ 真实ML |
| 时间衰减 | temporal_decay.py | MLE半衰期估计 | ✅ 统计算法 |
| 情报有机体 | intelligence_organism.py | 自适应半衰期+语义变异+基因继承 | ✅ 真实模型 |
| 溯源链 | provenance_chain.py | SHA-256哈希链+WORM日志+Merkle校验 | ✅ 密码学 |
| 分析引擎 | analytics_engine.py | NLQuery+Z-Score异常+线性回归趋势 | ✅ 真实算法 |
| QA引擎 | qa_engine.py | RAG+交叉编码器重排序+多轮对话 | ✅ RAG |
| 报告生成 | report_generator.py | LLM驱动+证据验证+IoC提取 | ✅ LLM |
| NER引擎 | ner_engine.py | 规则NER+LLM NER+融合 | ✅ 混合 |
| 翻译引擎 | translation_engine.py | LLM翻译+术语表 | ✅ LLM |
| 内容引擎 | content_engine.py | LLM生成+审核工作流+模板渲染 | ✅ LLM |
| 提示词引擎 | prompt_engine_service.py | A/B测试+提示词优化 | ✅ 真实算法 |
| 数据治理 | data_governance.py | 数据分类+最小化+保留策略 | ✅ 合规 |
| 缓存服务 | cache_service.py | Redis/Memory双模式 | ✅ 生产级 |
| 消息队列 | message_queue.py | Redis/内存队列 | ✅ 生产级 |
| 任务队列 | task_queue.py | 并发工作者+重试 | ✅ 生产级 |
| 经济引擎 | economic_engine.py | 威胁经济损失建模 | ✅ 可配置 |
| 告警引擎 | alert_engine.py | 规则匹配+通知 | ✅ 可配置 |
| 威胁情报服务 | threat_intel_service.py | 分类+实体提取+犯罪模式+技术链 | ✅ LLM+规则 |

### 新增引擎（本轮构建中）
| 引擎 | 文件 | 算法 | 状态 |
|------|------|------|------|
| 情报质量评估 | intelligence_quality.py | 贝叶斯可信度+指数衰减时效+Jaccard一致性 | ✅ 已创建 |
| 事件关联分析 | event_correlation.py | TF-IDF余弦+时间衰减+Jaccard+因果推理 | ✅ 已创建 |
| 威胁行为画像 | threat_behavior.py | TTP指纹+余弦相似度+层次聚类+Apriori | ✅ 已创建 |
| 动态风险评分 | risk_scoring.py | CVSS v3.1+指数衰减+级联风险+行业矩阵 | ✅ 已创建 |
| 情报融合 | intelligence_fusion.py | TF-IDF去重+Dempster-Shafer证据融合+溯源图 | ✅ 已创建 |

## 已完成的重要修复

### 第一轮（60→22个问题）
- 假数据生成器（auto_collector.py）改为真实数据源采集
- seed文件添加SEED_DATABASE守卫
- temperature硬编码→settings.LLM_TEMPERATURE_*
- 5个API模块添加LLM优先路径

### 第二轮（22→0个问题）
- max_tokens硬编码→settings.LLM_MAX_TOKENS_*
- 经济/生物/衰减/告警/攻击链引擎参数→环境变量可配置
- finetune重复端点合并
- 行业列表统一到INDUSTRY_THREAT_MAPPING（6个行业）

### 第三轮（24→0个问题）
- 登录页默认凭据移除
- 硬编码confidence值→settings.CONFIDENCE_*
- INDUSTRY_THREAT_MAPPING扩充为6个行业

### 第四轮（5个新引擎集成）
- 构建5个商用级核心引擎（质量/关联/画像/风险/融合）
- 服务注册完成（service_registry.py `_init_new_analysis_engines()`）
- 5个API路由文件全部修复：
  - `get_service()` → `request.app.state.xxx`
  - `get_db_session` → `get_db`
  - `app.models.user.User` → `app.core.auth.User`
  - `RawIntelligence` ORM → `RawIntelligenceTable`（JSON字段解析）
  - `ThreatBehaviorProfile` → `AnalysisResultTable`
  - intelligence_fusion.py 添加路由前缀 `/intelligence-fusion`
  - intelligence_fusion.py 残留 `Intelligence` 引用已修复
- 构建验证通过：后端import OK + 前端build OK

### 第五轮（代码优化）
- 修复 intelligence_fusion.py SQLite兼容性问题：`entities.overlap()` → 基于source和classification_level的查询

### 第六轮（前端页面集成）
- 完成5个新引擎前端页面创建：
  - `IntelligenceQuality.tsx` - 情报质量评估（贝叶斯可信度、指数衰减时效）
  - `EventCorrelation.tsx` - 事件关联分析（时间/实体/语义多维度）
  - `ThreatBehavior.tsx` - 威胁行为画像（TTP提取、行为聚类、异常检测）
  - `RiskScoring.tsx` - 动态风险评分（CVSS v3.1、级联风险分析）
  - `IntelligenceFusion.tsx` - 情报融合（TF-IDF去重、Dempster-Shafer证据融合）
- API接口封装完成：`api.ts` 添加5个引擎的完整API调用
- 路由集成：`App.tsx` 添加5个页面路由 + 侧边栏"分析引擎"菜单组
- 构建验证通过：TypeScript编译 + Vite打包成功
- 添加 scikit-learn 依赖到 requirements.txt
- 提取公共函数 `raw_intelligence_to_dict()` 到 `app/api/utils.py`，消除4个新引擎文件的重复代码
- 构建验证通过：后端import OK + 前端build OK

## 已知问题与待办

### 高优先级
1. **前端未展示新引擎功能** — 需要新增或修改前端页面展示5个新引擎（质量评估/事件关联/行为画像/风险评分/情报融合）

### 中优先级
2. **anomaly_detector.py（旧版）与新引擎功能重叠** — intelligence_quality.py已包含更完善的异常检测
3. **sklearn依赖** — threat_behavior.py和anomaly_detector.py使用了sklearn，但requirements.txt中未列出
4. **intelligence_fusion.py `detect_contradictions` 使用 `entities.overlap()`** — SQLite不支持该操作符，需改为JSON文本匹配或移除该条件

### 低优先级
5. **6个API文件的_row_to_dict()重复** — 可提取为公共函数
6. **关键词fallback仍保留** — 5个API模块(deception/narrative/persona/game_theory/exploit_lifecycle)的关键词降级作为无LLM环境兜底

## 严格规则
- **禁止硬编码假数据**
- **禁止为了跑通而降级代码**
- **所有配置走环境变量/settings**
- **所有分析结果必须来自真实算法**
- **构建必须通过才能算完成**

## 构建验证命令
```bash
# 后端
cd backend && python -c "from app.api import api_router; print('OK')"
# 前端
cd frontend && npx vite build
# 测试
cd backend && python -m pytest tests/ -x
```
