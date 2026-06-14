from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.db.crud import EntityCRUD
from app.db.database import get_db
from app.models.entity import Entity, EntityType, Relation

router = APIRouter(prefix="/entities", tags=["entities"])


@router.post("", response_model=Entity, status_code=201)
async def create_entity(
    data: Entity,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = EntityCRUD(db)
    result = await crud.create_entity(data)
    await db.commit()
    return result


@router.get("", response_model=dict)
async def list_entities(
    entity_type: EntityType | None = None,
    min_confidence: float | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = EntityCRUD(db)
    items, total = await crud.list_entities(
        entity_type=entity_type, min_confidence=min_confidence, offset=offset, limit=limit
    )
    await db.commit()
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/search", response_model=dict)
async def search_entities(
    q: Optional[str] = Query(None, min_length=1),
    query_param: Optional[str] = Query(None, min_length=1, alias="query"),
    entity_type: EntityType | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    search_query = q or query_param
    if not search_query:
        raise HTTPException(status_code=422, detail="Either 'q' or 'query' parameter is required")

    vector_store = getattr(request.app.state, "vector_store", None)
    if vector_store is not None:
        try:
            vs_results = await vector_store.search(
                query=search_query,
                n_results=limit,
                collection="intelligence",
            )
            if vs_results:
                items = []
                for r in vs_results:
                    metadata = r.get("metadata", {})
                    doc = r.get("document", "")
                    entity_value = (
                        metadata.get("entity_value")
                        or metadata.get("value")
                        or metadata.get("name")
                        or metadata.get("title")
                        or metadata.get("indicator")
                        or (doc[:50].strip() if doc else "")
                    )
                    entity_type = (
                        metadata.get("entity_type")
                        or metadata.get("type")
                        or metadata.get("ioc_type")
                        or metadata.get("threat_type")
                        or metadata.get("breach_type")
                        or metadata.get("exploit_type")
                        or metadata.get("file_type")
                        or metadata.get("species")
                        or metadata.get("category")
                        or metadata.get("source_type")
                        or metadata.get("source")
                        or "unknown"
                    )
                    distance = r.get("distance")
                    score = 1.0 - distance if distance is not None else None
                    items.append({
                        "id": r.get("id", ""),
                        "type": entity_type,
                        "value": entity_value,
                        "document": doc,
                        "metadata": metadata,
                        "distance": distance,
                        "score": score,
                    })
                return {"items": items, "total": len(items), "offset": offset, "limit": limit}
        except Exception as exc:
            logger.warning(f"VectorStore search failed, falling back to DB: {exc}")

    crud = EntityCRUD(db)
    items, total = await crud.search_entities(
        query=search_query, entity_type=entity_type, offset=offset, limit=limit
    )
    await db.commit()
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/{entity_id}", response_model=Entity)
async def get_entity(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = EntityCRUD(db)
    result = await crud.get_entity(entity_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return result


@router.patch("/{entity_id}", response_model=Entity)
async def update_entity(
    entity_id: str,
    updates: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = EntityCRUD(db)
    result = await crud.update_entity(entity_id, **updates)
    if result is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    await db.commit()
    return result


@router.delete("/{entity_id}", status_code=204)
async def delete_entity(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = EntityCRUD(db)
    deleted = await crud.delete_entity(entity_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Entity not found")
    await db.commit()


@router.post("/relations", response_model=Relation, status_code=201)
async def create_relation(
    data: Relation,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = EntityCRUD(db)
    result = await crud.create_relation(data)
    await db.commit()
    return result


@router.get("/{entity_id}/relations", response_model=List[Relation])
async def get_entity_relations(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = EntityCRUD(db)
    return await crud.get_relations_for_entity(entity_id)


@router.delete("/relations/{relation_id}", status_code=204)
async def delete_relation(
    relation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = EntityCRUD(db)
    deleted = await crud.delete_relation(relation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Relation not found")
    await db.commit()
