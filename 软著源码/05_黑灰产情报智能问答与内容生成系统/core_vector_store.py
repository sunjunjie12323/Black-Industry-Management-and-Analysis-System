import asyncio
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings
from loguru import logger

from app.config import settings
from app.core.local_embedding import LocalEmbeddingEngine


class VectorStore:
    COLLECTION_NAMES = ("intelligence", "entities", "blacktalk")
    PERSIST_FILENAME = "vector_store.json"

    def __init__(self, persist_dir: str, embedding_engine: LocalEmbeddingEngine = None):
        self.persist_dir = persist_dir
        self._json_backup_path = Path(persist_dir) / self.PERSIST_FILENAME
        self._embedding = embedding_engine or LocalEmbeddingEngine()
        self._client = chromadb.PersistentClient(
            path=persist_dir,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collections: Dict[str, chromadb.Collection] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        for name in self.COLLECTION_NAMES:
            self._collections[name] = self._client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
            self._locks[name] = asyncio.Lock()
        logger.info(
            f"VectorStore initialized at {persist_dir} "
            f"with collections: {list(self._collections.keys())} "
            f"(embedding: local TF-IDF+SVD, dim={self._embedding.dim})"
        )
        self._load_from_json()

    def _get_collection(self, collection: str) -> chromadb.Collection:
        if collection not in self._collections:
            raise ValueError(
                f"Unknown collection '{collection}'. "
                f"Available: {list(self._collections.keys())}"
            )
        return self._collections[collection]

    def _get_lock(self, collection: str) -> asyncio.Lock:
        if collection not in self._locks:
            self._locks[collection] = asyncio.Lock()
        return self._locks[collection]

    async def _embed(self, text: str) -> List[float]:
        return self._embedding.embed(text)

    async def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        return self._embedding.embed_batch(texts)

    async def get_embedding(self, text: str) -> List[float]:
        return await self._embed(text)

    @staticmethod
    def _sanitize_metadata(metadata: dict) -> dict:
        sanitized = {}
        for k, v in metadata.items():
            if isinstance(v, (str, int, float, bool)):
                sanitized[k] = v
            elif isinstance(v, (list, tuple, set)):
                sanitized[k] = ",".join(str(x) for x in v)
            elif v is None:
                sanitized[k] = ""
            else:
                sanitized[k] = str(v)
        return sanitized

    async def add_intelligence(self, intel_id: str, content: str, metadata: dict):
        try:
            embedding = await self._embed(content)
            sanitized = self._sanitize_metadata(metadata)
            async with self._get_lock("intelligence"):
                self._collections["intelligence"].add(
                    ids=[intel_id],
                    embeddings=[embedding],
                    documents=[content],
                    metadatas=[sanitized],
                )
            logger.debug(f"Added intelligence vector: {intel_id}")
        except Exception as exc:
            logger.error(f"Failed to add intelligence vector {intel_id}: {exc}")
            raise

    async def search(
        self,
        query: str,
        n_results: int = 10,
        collection: str = "intelligence",
        filter: Optional[dict] = None,
    ) -> List[dict]:
        col = self._get_collection(collection)
        try:
            query_embedding = await self._embed(query)
            kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": n_results,
            }
            if filter:
                kwargs["where"] = filter
            results = col.query(**kwargs)
            return self._format_results(results)
        except Exception as exc:
            logger.error(f"Failed to search {collection}: {exc}")
            return []

    async def search_intelligence(
        self,
        query: str,
        n_results: int = 10,
        filter: Optional[dict] = None,
    ) -> List[dict]:
        try:
            query_embedding = await self._embed(query)
            kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": n_results,
            }
            if filter:
                kwargs["where"] = filter
            results = self._collections["intelligence"].query(**kwargs)
            return self._format_results(results)
        except Exception as exc:
            logger.error(f"Failed to search intelligence: {exc}")
            return []

    async def add_entity(self, entity_id: str, content: str, metadata: dict):
        try:
            embedding = await self._embed(content)
            sanitized = self._sanitize_metadata(metadata)
            async with self._get_lock("entities"):
                self._collections["entities"].add(
                    ids=[entity_id],
                    embeddings=[embedding],
                    documents=[content],
                    metadatas=[sanitized],
                )
            logger.debug(f"Added entity vector: {entity_id}")
        except Exception as exc:
            logger.error(f"Failed to add entity vector {entity_id}: {exc}")
            raise

    async def search_entities(
        self,
        query: str,
        n_results: int = 10,
    ) -> List[dict]:
        try:
            query_embedding = await self._embed(query)
            results = self._collections["entities"].query(
                query_embeddings=[query_embedding],
                n_results=n_results,
            )
            return self._format_results(results)
        except Exception as exc:
            logger.error(f"Failed to search entities: {exc}")
            return []

    async def add_blacktalk(self, term_id: str, content: str, metadata: dict):
        try:
            embedding = await self._embed(content)
            sanitized = self._sanitize_metadata(metadata)
            async with self._get_lock("blacktalk"):
                self._collections["blacktalk"].add(
                    ids=[term_id],
                    embeddings=[embedding],
                    documents=[content],
                    metadatas=[sanitized],
                )
            logger.debug(f"Added blacktalk vector: {term_id}")
        except Exception as exc:
            logger.error(f"Failed to add blacktalk vector {term_id}: {exc}")
            raise

    async def search_blacktalk(
        self,
        query: str,
        n_results: int = 10,
    ) -> List[dict]:
        try:
            query_embedding = await self._embed(query)
            results = self._collections["blacktalk"].query(
                query_embeddings=[query_embedding],
                n_results=n_results,
            )
            return self._format_results(results)
        except Exception as exc:
            logger.error(f"Failed to search blacktalk: {exc}")
            return []

    async def delete(self, collection: str, ids: List[str]):
        try:
            col = self._get_collection(collection)
            async with self._get_lock(collection):
                col.delete(ids=ids)
            logger.debug(f"Deleted {len(ids)} items from {collection}")
        except Exception as exc:
            logger.error(f"Failed to delete from {collection}: {exc}")
            raise

    async def count(self, collection: str) -> int:
        try:
            col = self._get_collection(collection)
            return col.count()
        except Exception as exc:
            logger.error(f"Failed to count {collection}: {exc}")
            return 0

    async def persist(self):
        try:
            backup_data = {
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "collections": {},
            }
            for name, col in self._collections.items():
                try:
                    count = col.count()
                    if count == 0:
                        backup_data["collections"][name] = {"ids": [], "documents": [], "metadatas": [], "embeddings": []}
                        continue
                    results = col.get(include=["documents", "metadatas", "embeddings"])
                    backup_data["collections"][name] = {
                        "ids": results.get("ids", []),
                        "documents": results.get("documents", []),
                        "metadatas": results.get("metadatas", []),
                        "embeddings": results.get("embeddings", []),
                    }
                except Exception as exc:
                    logger.warning(f"Failed to export collection {name} for backup: {exc}")
                    backup_data["collections"][name] = {"error": "向量存储操作失败"}
            self._json_backup_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                suffix=".tmp",
                prefix=self.PERSIST_FILENAME,
                dir=str(self._json_backup_path.parent),
            )
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    json.dump(backup_data, f, ensure_ascii=False, default=str)
                os.replace(tmp_path, str(self._json_backup_path))
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
            total = sum(
                len(c.get("ids", []))
                for c in backup_data["collections"].values()
                if isinstance(c, dict) and "ids" in c
            )
            logger.info(f"VectorStore JSON backup saved: {total} total records across {len(self._collections)} collections")
        except Exception as exc:
            logger.error(f"Failed to persist VectorStore JSON backup: {exc}")

    def _load_from_json(self):
        if not self._json_backup_path.exists():
            logger.debug("No VectorStore JSON backup found, relying on ChromaDB persistence")
            return
        try:
            with open(self._json_backup_path, "r", encoding="utf-8") as f:
                backup_data = json.load(f)
            collections_data = backup_data.get("collections", {})
            if not isinstance(collections_data, dict):
                return
            total_restored = 0
            for name in self.COLLECTION_NAMES:
                col_data = collections_data.get(name)
                if not col_data or not isinstance(col_data, dict) or "ids" not in col_data:
                    continue
                ids = col_data.get("ids", [])
                if not ids:
                    continue
                existing = set(self._collections[name].get().get("ids", []))
                new_ids = [i for i in ids if i not in existing]
                if not new_ids:
                    continue
                idx_map = {i: idx for idx, i in enumerate(ids)}
                documents = [col_data["documents"][idx_map[i]] for i in new_ids if i in idx_map and idx_map[i] < len(col_data.get("documents", []))]
                metadatas = [col_data["metadatas"][idx_map[i]] for i in new_ids if i in idx_map and idx_map[i] < len(col_data.get("metadatas", []))]
                embeddings = [col_data["embeddings"][idx_map[i]] for i in new_ids if i in idx_map and idx_map[i] < len(col_data.get("embeddings", []))]
                if len(new_ids) != len(documents) or len(new_ids) != len(metadatas) or len(new_ids) != len(embeddings):
                    logger.warning(f"VectorStore JSON backup for '{name}' has mismatched lengths, skipping")
                    continue
                try:
                    self._collections[name].add(
                        ids=new_ids,
                        documents=documents,
                        metadatas=metadatas,
                        embeddings=embeddings,
                    )
                    total_restored += len(new_ids)
                except Exception as exc:
                    logger.warning(f"Failed to restore collection '{name}' from JSON backup: {exc}")
            if total_restored > 0:
                logger.info(f"VectorStore restored {total_restored} records from JSON backup")
            else:
                logger.debug("VectorStore JSON backup contained no new records to restore")
        except Exception as exc:
            logger.warning(f"Failed to load VectorStore JSON backup: {exc}")

    def get_status(self) -> Dict:
        collection_info = {}
        for name, col in self._collections.items():
            try:
                count = col.count()
                collection_info[name] = {"document_count": count}
            except Exception:
                collection_info[name] = {"document_count": 0, "error": True}
        return {
            "persist_dir": self.persist_dir,
            "collections": list(self._collections.keys()),
            "collection_details": collection_info,
            "embedding_dim": self._embedding.dim,
        }

    def _format_results(self, results: dict) -> List[dict]:
        formatted = []
        if not results or not results.get("ids") or not results["ids"][0]:
            return formatted
        ids = results["ids"][0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        for i in range(len(ids)):
            item = {
                "id": ids[i],
                "document": documents[i] if i < len(documents) else None,
                "metadata": metadatas[i] if i < len(metadatas) else {},
                "distance": distances[i] if i < len(distances) else None,
            }
            formatted.append(item)
        return formatted
