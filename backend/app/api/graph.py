from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import NotFoundException, ValidationException, AppException
from app.core.knowledge_graph import KnowledgeGraph
from app.models.entity import Entity, EntityType, Relation, RelationType

router = APIRouter(prefix="/graph", tags=["graph"])


class EntityCreate(BaseModel):
    type: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    context: Optional[str] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class RelationCreate(BaseModel):
    source_entity_id: str = Field(..., min_length=1)
    target_entity_id: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: Optional[str] = None


class PathRequest(BaseModel):
    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    max_depth: int = Field(default=5, ge=1, le=10)


class CommunityRequest(BaseModel):
    algorithm: str = Field(default="louvain")
    min_size: int = Field(default=2, ge=2)


def get_knowledge_graph(request: Request) -> KnowledgeGraph | None:
    return getattr(request.app.state, "knowledge_graph", None)


def _require_kg(request: Request) -> KnowledgeGraph:
    kg = get_knowledge_graph(request)
    if kg is None:
        raise AppException(detail="知识图谱服务未初始化", error_code="KG_NOT_AVAILABLE", status_code=503)
    return kg


@router.get("/stats")
async def graph_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    kg = get_knowledge_graph(request)
    if kg is None:
        return {"node_count": 0, "edge_count": 0, "entity_types": {}, "message": "知识图谱服务未初始化"}
    try:
        stats = await kg.get_statistics()
        return stats
    except Exception as exc:
        logger.error(f"Failed to get graph stats: {exc}", exc_info=True)
        return {"node_count": 0, "edge_count": 0, "entity_types": {}, "message": "获取图谱统计失败"}


@router.get("/entities")
async def list_entities(
    entity_type: Optional[str] = None,
    search: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    kg = get_knowledge_graph(request)
    if kg is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "知识图谱服务未初始化"}
    try:
        if search:
            entities = await kg.search_entities(
                query=search,
                entity_type=entity_type,
                limit=limit + offset,
            )
            total = len(entities)
            paginated = entities[offset: offset + limit]
        else:
            all_entities = list(kg._entities.values())
            if entity_type:
                all_entities = [e for e in all_entities if e.type.value == entity_type]
            def _sort_key(e):
                ls = e.last_seen
                if ls is None:
                    return ""
                if isinstance(ls, datetime) and ls.tzinfo is not None:
                    return ls.replace(tzinfo=None).isoformat()
                return ls.isoformat() if hasattr(ls, 'isoformat') else str(ls)
            all_entities.sort(key=_sort_key, reverse=True)
            total = len(all_entities)
            paginated = all_entities[offset: offset + limit]
        def _enrich_entity(e):
            d = e.model_dump()
            d["name"] = e.value
            d["aliases"] = e.metadata.get("aliases", []) if isinstance(e.metadata, dict) else []
            d["updated_at"] = e.last_seen.isoformat() if hasattr(e.last_seen, 'isoformat') else str(e.last_seen)
            return d
        return {
            "items": [_enrich_entity(e) for e in paginated],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.error(f"Failed to list graph entities: {exc}", exc_info=True)
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "获取实体列表失败"}


@router.get("/entities/{entity_id}")
async def get_entity(
    entity_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    kg = _require_kg(request)
    try:
        entity = await kg.get_entity(entity_id)
        if entity is None:
            raise NotFoundException(detail="实体未在知识图谱中找到")
        relations = await kg.get_entity_relations(entity_id)
        related_ids: set[str] = set()
        for r in relations:
            related_ids.add(r.source_entity_id)
            related_ids.add(r.target_entity_id)
        related_ids.discard(entity_id)
        related_entities = await kg.get_entities(related_ids)
        enriched_relations = []
        for r in relations:
            r_dict = r.model_dump()
            source_entity = related_entities.get(r.source_entity_id)
            target_entity = related_entities.get(r.target_entity_id)
            r_dict["source_entity_value"] = source_entity.value if source_entity else r.source_entity_id
            r_dict["source_entity_type"] = source_entity.type.value if source_entity else "unknown"
            r_dict["target_entity_value"] = target_entity.value if target_entity else r.target_entity_id
            r_dict["target_entity_type"] = target_entity.type.value if target_entity else "unknown"
            enriched_relations.append(r_dict)
        return {
            "entity": entity.model_dump(),
            "relations": enriched_relations,
            "relation_count": len(relations),
        }
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to get entity {entity_id}: {exc}", exc_info=True)
        raise AppException(detail="获取实体详情失败", error_code="GRAPH_ENTITY_ERROR")


@router.get("/relations")
async def list_relations(
    relation_type: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    kg = get_knowledge_graph(request)
    if kg is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "知识图谱服务未初始化"}
    try:
        all_relations = list(kg._relations.values())
        logger.info(f"KnowledgeGraph _relations count: {len(all_relations)}, graph edges: {kg.graph.number_of_edges()}")
        if not all_relations:
            edge_relations = []
            for u, v, data in kg.graph.edges(data=True):
                rid = data.get("id", "")
                if rid and rid in kg._relations:
                    continue
                rtype_str = data.get("type", "associated_with")
                try:
                    rtype = RelationType(rtype_str)
                except ValueError:
                    rtype = RelationType.ASSOCIATED_WITH
                rel = Relation(
                    id=rid or f"edge_{u}_{v}",
                    source_entity_id=u,
                    target_entity_id=v,
                    type=rtype,
                    confidence=data.get("confidence", 0.5),
                    evidence=data.get("evidence", ""),
                )
                edge_relations.append(rel)
            for rel in edge_relations:
                kg._relations[rel.id] = rel
            all_relations = list(kg._relations.values())
        if relation_type:
            all_relations = [r for r in all_relations if r.type.value == relation_type]
        def _sort_key(r):
            ls = r.last_seen
            if isinstance(ls, datetime):
                return ls
            if isinstance(ls, str):
                try:
                    return datetime.fromisoformat(ls.replace(' ', 'T') if ' ' in ls else ls)
                except Exception:
                    logger.exception("Unexpected error in relation sort key datetime parsing")
                    return datetime.min
            return datetime.min
        all_relations.sort(key=_sort_key, reverse=True)
        total = len(all_relations)
        paginated = all_relations[offset: offset + limit]
        result_items = []
        for r in paginated:
            try:
                result_items.append(r.model_dump())
            except Exception as e:
                logger.warning(f"Failed to serialize relation {r.id}: {e}")
        return {
            "items": result_items,
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.error(f"Failed to list relations: {exc}", exc_info=True)
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "获取关系列表失败"}


@router.post("/entities", status_code=201)
async def add_entity(
    data: EntityCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    kg = _require_kg(request)
    try:
        try:
            entity_type = EntityType(data.type)
        except ValueError:
            raise ValidationException(
                detail=f"无效实体类型: {data.type}. 有效类型: {[t.value for t in EntityType]}",
            )
        entity = Entity(
            type=entity_type,
            value=data.value,
            context=data.context,
            confidence=data.confidence,
        )
        entity_id = await kg.add_entity(entity)
        await kg.save()
        return {"id": entity_id, **entity.model_dump()}
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to add entity to graph: {exc}", exc_info=True)
        raise AppException(detail="添加实体到知识图谱失败", error_code="GRAPH_ADD_ENTITY_ERROR")


@router.delete("/entities/{entity_id}")
async def delete_entity(
    entity_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    kg = _require_kg(request)
    try:
        removed = await kg.remove_entity(entity_id)
        if not removed:
            raise NotFoundException(detail=f"实体 {entity_id} 未找到")
        await kg.save()
        return {"id": entity_id, "deleted": True}
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to delete entity {entity_id}: {exc}", exc_info=True)
        raise AppException(detail="删除实体失败", error_code="GRAPH_DELETE_ENTITY_ERROR")


@router.post("/relations", status_code=201)
async def add_relation(
    data: RelationCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    kg = _require_kg(request)
    try:
        try:
            rel_type = RelationType(data.type)
        except ValueError:
            raise ValidationException(
                detail=f"无效关系类型: {data.type}. 有效类型: {[t.value for t in RelationType]}",
            )
        source = await kg.get_entity(data.source_entity_id)
        if source is None:
            raise ValidationException(detail=f"源实体 {data.source_entity_id} 未找到")
        target = await kg.get_entity(data.target_entity_id)
        if target is None:
            raise ValidationException(detail=f"目标实体 {data.target_entity_id} 未找到")
        relation = Relation(
            source_entity_id=data.source_entity_id,
            target_entity_id=data.target_entity_id,
            type=rel_type,
            confidence=data.confidence,
            evidence=data.evidence,
        )
        relation_id = await kg.add_relation(relation)
        await kg.save()
        return {"id": relation_id, **relation.model_dump()}
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to add relation to graph: {exc}", exc_info=True)
        raise AppException(detail="添加关系到知识图谱失败", error_code="GRAPH_ADD_RELATION_ERROR")


@router.post("/path")
async def find_path(
    data: PathRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    kg = _require_kg(request)
    try:
        source = await kg.get_entity(data.source_id)
        if source is None:
            raise NotFoundException(detail=f"源实体 {data.source_id} 未找到")
        target = await kg.get_entity(data.target_id)
        if target is None:
            raise NotFoundException(detail=f"目标实体 {data.target_id} 未找到")
        paths = await kg.find_path(
            data.source_id, data.target_id, max_depth=data.max_depth
        )
        if not paths:
            return {
                "source_id": data.source_id,
                "target_id": data.target_id,
                "paths": [],
                "path_count": 0,
                "message": "未找到连接路径，两个实体可能不在同一连通分量中",
            }
        enriched_paths = []
        for path in paths:
            nodes_entities = await kg.get_entities(path)
            enriched_nodes = []
            for node_id in path:
                entity = nodes_entities.get(node_id)
                if entity:
                    enriched_nodes.append({
                        "id": entity.id,
                        "type": entity.type.value,
                        "value": entity.value,
                    })
                else:
                    enriched_nodes.append({"id": node_id})
            enriched_paths.append(enriched_nodes)
        return {
            "source_id": data.source_id,
            "target_id": data.target_id,
            "paths": enriched_paths,
            "path_count": len(enriched_paths),
        }
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to find path: {exc}", exc_info=True)
        raise AppException(detail="路径查找失败", error_code="GRAPH_PATH_ERROR")


@router.post("/communities")
async def find_communities(
    data: CommunityRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    kg = get_knowledge_graph(request)
    if kg is None:
        return {"algorithm": data.algorithm, "communities": [], "community_count": 0, "message": "知识图谱服务未初始化"}
    try:
        if len(kg._entities) == 0:
            return {
                "algorithm": data.algorithm,
                "communities": [],
                "community_count": 0,
            }
        communities = await kg.find_communities(algorithm=data.algorithm)
        all_member_ids: set[str] = set()
        for community in communities:
            all_member_ids.update(community)
        members_by_id = await kg.get_entities(all_member_ids)
        result = []
        for community in communities:
            if len(community) < data.min_size:
                continue
            members = []
            for member_id in community:
                entity = members_by_id.get(member_id)
                if entity:
                    members.append({
                        "id": entity.id,
                        "type": entity.type.value,
                        "value": entity.value,
                    })
            result.append({
                "member_count": len(members),
                "members": members,
            })
        return {
            "algorithm": data.algorithm,
            "communities": result,
            "community_count": len(result),
        }
    except Exception as exc:
        logger.error(f"Failed to find communities: {exc}", exc_info=True)
        raise AppException(detail="社区发现失败", error_code="GRAPH_COMMUNITY_ERROR")


@router.get("/subgraph/{entity_id}")
async def get_subgraph(
    entity_id: str,
    depth: int = Query(1, ge=1, le=3),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    kg = _require_kg(request)
    try:
        entity = await kg.get_entity(entity_id)
        if entity is None:
            raise NotFoundException(detail=f"实体 {entity_id} 未找到")
        subgraph = await kg.get_subgraph([entity_id], depth=depth)
        return subgraph
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to get subgraph for {entity_id}: {exc}", exc_info=True)
        raise AppException(detail="获取子图失败", error_code="GRAPH_SUBGRAPH_ERROR")


@router.get("/export")
async def export_graph(
    format: str = Query("json"),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    kg = _require_kg(request)
    try:
        data = await kg.export_graph(format=format)
        return data
    except ValueError as exc:
        raise ValidationException(detail="操作失败")
    except AppException:
        raise
    except Exception as exc:
        logger.error(f"Failed to export graph: {exc}", exc_info=True)
        raise AppException(detail="导出图谱失败", error_code="GRAPH_EXPORT_ERROR")


@router.get("/data")
async def get_graph_data(
    entity_type: Optional[str] = None,
    search: Optional[str] = None,
    depth: int = Query(1, ge=1, le=3),
    limit: int = Query(100, ge=1, le=1000),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    kg = get_knowledge_graph(request)
    if kg is None:
        return {"nodes": [], "edges": []}
    try:
        nodes = []
        edges = []

        all_entities = list(kg._entities.values())
        if entity_type:
            all_entities = [e for e in all_entities if e.type.value == entity_type]
        if search:
            search_lower = search.lower()
            all_entities = [e for e in all_entities if search_lower in e.value.lower()]

        all_entities = all_entities[:limit]

        for entity in all_entities:
            nodes.append({
                "id": entity.id,
                "label": entity.value,
                "entity_type": entity.type.value,
                "properties": {},
                "confidence": entity.confidence,
            })

        entity_ids = {e.id for e in all_entities}
        for relation in kg._relations.values():
            if relation.source_entity_id in entity_ids and relation.target_entity_id in entity_ids:
                edges.append({
                    "id": relation.id,
                    "source": relation.source_entity_id,
                    "target": relation.target_entity_id,
                    "relation_type": relation.type.value,
                    "properties": {},
                    "confidence": relation.confidence,
                })

        return {"nodes": nodes, "edges": edges}
    except Exception as exc:
        logger.error(f"Failed to get graph data: {exc}", exc_info=True)
        return {"nodes": [], "edges": []}
