# 黑灰产情报分析Agent — 系统架构图

## 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        用户浏览器 (React 18)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │Dashboard │ │Intel List│ │GraphView │ │BlackTalk │ │AI助手    │ │
│  │  G2Plot  │ │ +Pipeline│ │   G6     │ │+AI翻译   │ │DeepSeek  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ Reports  │ │  PIRs    │ │Innovation│ │  Alerts  │ │  Agent   │ │
│  │+AI简报   │ │ Manager  │ │  Engines │ │  Center  │ │ Console  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ HTTP REST + WebSocket + SSE
┌───────────────────────────▼─────────────────────────────────────────┐
│                     FastAPI 后端 (Python 3.10)                       │
│                                                                     │
│  ┌─── 中间件层 ──────────────────────────────────────────────────┐  │
│  │ CORS │ RateLimit(令牌桶) │ CSRF │ AuditLog │ ExceptionHandler │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── API路由层 (24模块, 50+端点) ──────────────────────────────┐  │
│  │ auth │ intelligence │ dashboard │ graph │ blacktalk           │  │
│  │ pirs │ reports │ agent │ tasks │ deepseek │ alerts            │  │
│  │ zero_day │ attack_prediction │ provenance │ attribution       │  │
│  │ temporal_decay │ organism │ innovation │ export │ precision  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── Agent调度层 ──────────────────────────────────────────────┐  │
│  │ OrchestratorAgent → Collector → Cleaner → Analyst → Graph    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── 7大创新引擎 ──────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │  │
│  │  │ ZeroDayDetector  │  │ AttackChainPred │  │EntityAttrib  │ │  │
│  │  │ SkipGram+KL散度  │  │ MITRE+马尔可夫  │  │ TransE嵌入   │ │  │
│  │  │ 33个零日术语     │  │ 32979条转移     │  │ 16200实体    │ │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │  │
│  │  │ ProvenanceChain  │  │IntelligenceOrg  │  │TemporalDecay │ │  │
│  │  │ SHA-256溯源链    │  │ 生物进化隐喻    │  │ MLE半衰期    │ │  │
│  │  │ AI幻觉检测       │  │ 60个存活体      │  │ 17威胁类型   │ │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │ DeepSeek大模型 (deepseek-chat)                          │ │  │
│  │  │ 黑灰产专属System Prompt (5大能力+4种分析模式)            │ │  │
│  │  │ Few-shot黑产示例 + CoT链式思维 + 三组对比实验框架        │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── 基础服务层 ──────────────────────────────────────────────┐  │
│  │ VectorStore(ChromaDB) │ KnowledgeGraph(NetworkX) │ LLMService │  │
│  │ BlackTalkEngine(55+术语) │ EvidenceChain │ AlertEngine(8规则) │  │
│  │ TaskQueue(异步) │ RateLimiter(令牌桶) │ CacheService │ STIX2.1 │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── 数据采集层 (7源+多级回退) ───────────────────────────────┐  │
│  │ CISA KEV │ URLhaus │ MalwareBazaar │ ThreatFox               │  │
│  │ AlienVault OTX │ CIRCL LU │ StevenBlack                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│                    SQLite 数据库 (aiosqlite 异步)                     │
│  raw_intelligence │ cleaned_intelligence │ analyzed_intelligence    │
│  entity │ relation │ pir │ pir_task │ report │ analysis_result      │
│  users │ token_blacklist │ audit_log                                │
└─────────────────────────────────────────────────────────────────────┘
```

## 数据处理流水线

```
7源采集 ──→ raw_intelligence ──→ 黑话解码+实体提取 ──→ cleaned_intelligence
                                                          │
                                        威胁分析+攻击模式 ──→ analyzed_intelligence
                                                          │
                                        知识图谱更新 ──→ NetworkX Graph (264节点+209边)
                                                          │
                                        溯源链生成 ──→ ProvenanceChain (SHA-256)
                                                          │
                                        报告生成 ──→ STIX 2.1 导出
```

## 安全架构

```
请求 → CORS → CSRF验证 → RateLimit(令牌桶) → JWT认证 → RBAC权限 → 业务逻辑
                                                        │
                                              admin ──→ 全部权限
                                              analyst ──→ 分析+采集
                                              viewer ──→ 只读查看
```

## DeepSeek集成架构

```
用户输入 → System Prompt(黑灰产专家) + Few-shot示例/CoT指令
         → DeepSeek Chat API (temperature按模式调参)
         → JSON结构化输出
         → 分析结果持久化(analysis_result表)
         → 前端可视化展示
```
