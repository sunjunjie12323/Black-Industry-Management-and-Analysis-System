import json
import math
import os
import re
from collections import Counter
from typing import Dict, List, Optional

import numpy as np
from loguru import logger


class LocalEmbeddingEngine:
    PERSIST_DIR = "./model_data/local_embedding"
    ST_MODEL_DIR = "./model_data/sentence_transformers"
    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    FALLBACK_MODELS = ["all-paraphrase-MiniLM-L12-v2", "paraphrase-MiniLM-L6-v2"]

    def __init__(self, dim: Optional[int] = None):
        env_dim = os.environ.get("EMBEDDING_DIM")
        self._dim_explicitly_set = env_dim is not None or dim is not None
        self.dim = int(env_dim) if env_dim else (dim or 384)
        self._model_name = os.environ.get("EMBEDDING_MODEL", self.DEFAULT_MODEL)
        self._st_model = None
        self._using_transformers = False
        self._idf: Dict[str, float] = {}
        self._vocab: Dict[str, int] = {}
        self._svd_components: Optional[np.ndarray] = None
        self._trained = False
        self._fallback_proj: Optional[np.ndarray] = None
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            logger.warning("sentence-transformers not available, falling back to TF-IDF+SVD")
            self._try_load()
            return

        model_name = self._model_name
        candidates = [model_name] + [m for m in self.FALLBACK_MODELS if m != model_name]

        for name in candidates:
            try:
                cache_dir = os.path.abspath(self.ST_MODEL_DIR)
                model = SentenceTransformer(name, cache_folder=cache_dir)
                self._st_model = model
                self._model_name = name
                self._using_transformers = True
                actual_dim = model.get_sentence_embedding_dimension()
                if not self._dim_explicitly_set:
                    self.dim = actual_dim
                logger.info(
                    f"LocalEmbeddingEngine: loaded sentence-transformers model '{name}', dim={self.dim}"
                )
                return
            except Exception as exc:
                logger.warning(f"Failed to load sentence-transformers model '{name}': {exc}")
                continue

        logger.warning("All sentence-transformers models failed, falling back to TF-IDF+SVD")
        self._try_load()

    def is_using_transformers(self) -> bool:
        return self._using_transformers

    def get_model_info(self) -> dict:
        return {
            "model_name": self._model_name,
            "dim": self.dim,
            "using_sentence_transformers": self._using_transformers,
        }

    def train(self, documents: List[str]):
        if self._using_transformers:
            logger.info("LocalEmbeddingEngine: skipping training, using pre-trained sentence-transformers")
            return

        logger.info(f"LocalEmbeddingEngine: training on {len(documents)} documents...")
        doc_freq = Counter()
        all_tokens_per_doc = []

        for doc in documents:
            tokens = self._tokenize(doc)
            all_tokens_per_doc.append(tokens)
            unique_tokens = set(tokens)
            for t in unique_tokens:
                doc_freq[t] += 1

        min_df = max(1, len(documents) // 1000)
        max_df_ratio = 0.95
        n_docs = len(documents)

        self._vocab = {}
        idx = 0
        for token, df in doc_freq.items():
            if df >= min_df and df / n_docs <= max_df_ratio:
                self._vocab[token] = idx
                idx += 1

        for token, df in doc_freq.items():
            if token in self._vocab:
                self._idf[token] = math.log((n_docs + 1) / (df + 1)) + 1.0

        vocab_size = len(self._vocab)
        logger.info(f"LocalEmbeddingEngine: vocab size = {vocab_size}")

        if vocab_size == 0:
            self._trained = True
            self._save()
            return

        tfidf_matrix = np.zeros((n_docs, vocab_size), dtype=np.float32)
        for i, tokens in enumerate(all_tokens_per_doc):
            tf = Counter(tokens)
            for token, count in tf.items():
                if token in self._vocab:
                    j = self._vocab[token]
                    tfidf_matrix[i, j] = (1 + math.log(count)) * self._idf.get(token, 1.0)

        norms = np.linalg.norm(tfidf_matrix, axis=1, keepdims=True)
        norms[norms < 1e-10] = 1.0
        tfidf_matrix = tfidf_matrix / norms

        target_dim = min(self.dim, vocab_size, tfidf_matrix.shape[0])
        if target_dim < vocab_size and target_dim > 0:
            try:
                U, S, Vt = np.linalg.svd(tfidf_matrix, full_matrices=False)
                self._svd_components = Vt[:target_dim]
                logger.info(f"LocalEmbeddingEngine: SVD reduced {vocab_size} → {target_dim} dims")
            except Exception as exc:
                logger.warning(f"SVD failed: {exc}, using random projection")
                rng = np.random.RandomState(42)
                self._svd_components = rng.randn(target_dim, vocab_size).astype(np.float32)
                self._svd_components /= np.linalg.norm(self._svd_components, axis=1, keepdims=True)
        else:
            self._svd_components = None

        self._trained = True
        self._save()
        logger.info(f"LocalEmbeddingEngine: training complete, dim={target_dim}")

    def embed(self, text: str) -> List[float]:
        if self._using_transformers and self._st_model is not None:
            return self._st_embed(text)

        if not self._trained or not self._vocab:
            return self._fallback_embed(text)

        tokens = self._tokenize(text)
        if not tokens:
            return self._fallback_embed(text)

        tf = Counter(tokens)
        vocab_size = len(self._vocab)
        vec = np.zeros(vocab_size, dtype=np.float32)
        for token, count in tf.items():
            if token in self._vocab:
                j = self._vocab[token]
                vec[j] = (1 + math.log(count)) * self._idf.get(token, 1.0)

        norm = np.linalg.norm(vec)
        if norm < 1e-10:
            return self._fallback_embed(text)
        vec = vec / norm

        if self._svd_components is not None:
            vec = self._svd_components @ vec
            norm = np.linalg.norm(vec)
            if norm > 1e-10:
                vec = vec / norm

        return vec.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if self._using_transformers and self._st_model is not None:
            return self._st_embed_batch(texts)
        return [self.embed(t) for t in texts]

    def _st_embed(self, text: str) -> List[float]:
        try:
            vec = self._st_model.encode(text, normalize_embeddings=True)
            return vec.tolist()
        except Exception as exc:
            logger.warning(f"sentence-transformers encode failed: {exc}, using fallback")
            return self._fallback_embed(text)

    def _st_embed_batch(self, texts: List[str]) -> List[List[float]]:
        try:
            vecs = self._st_model.encode(texts, normalize_embeddings=True, batch_size=32)
            return [v.tolist() for v in vecs]
        except Exception as exc:
            logger.warning(f"sentence-transformers batch encode failed: {exc}, using fallback")
            return [self._fallback_embed(t) for t in texts]

    def _fallback_embed(self, text: str) -> List[float]:
        if self._fallback_proj is None:
            rng = np.random.RandomState(42)
            self._fallback_proj = rng.randn(self.dim, 256).astype(np.float32)
            self._fallback_proj /= np.linalg.norm(self._fallback_proj, axis=1, keepdims=True)

        ngram_vec = np.zeros(256, dtype=np.float32)
        text_lower = text.lower()
        for i in range(len(text_lower)):
            idx = hash(text_lower[i:i + 3]) % 256
            ngram_vec[idx] += 1.0
            if i + 1 < len(text_lower):
                idx2 = hash(text_lower[i:i + 2]) % 256
                ngram_vec[idx2] += 0.5

        norm = np.linalg.norm(ngram_vec)
        if norm < 1e-10:
            return [0.0] * self.dim
        ngram_vec = ngram_vec / norm

        result = self._fallback_proj @ ngram_vec
        norm = np.linalg.norm(result)
        if norm > 1e-10:
            result = result / norm
        return result.tolist()

    def _tokenize(self, text: str) -> List[str]:
        tokens = []
        en_tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_]{1,}', text.lower())
        tokens.extend(en_tokens)

        cn_tokens = re.findall(r'[\u4e00-\u9fff]{2,}', text)
        for t in cn_tokens:
            for i in range(len(t) - 1):
                tokens.append(t[i:i + 2])

        special = re.findall(
            r'(?:\d{1,3}\.){3}\d{1,3}|'
            r'[a-fA-F0-9]{32,}|'
            r'https?://[^\s]+|'
            r'CVE-\d{4}-\d{4,}|'
            r'[\w.+-]+@[\w-]+\.[\w.-]+',
            text,
        )
        tokens.extend(special)
        return tokens

    def _save(self):
        os.makedirs(self.PERSIST_DIR, exist_ok=True)
        meta_path = os.path.join(self.PERSIST_DIR, "model_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({
                "vocab": self._vocab,
                "idf": self._idf,
                "dim": self.dim,
                "trained": self._trained,
            }, f, ensure_ascii=False)
        if self._svd_components is not None:
            svd_path = os.path.join(self.PERSIST_DIR, "svd_components.npy")
            np.save(svd_path, self._svd_components)

    def _try_load(self):
        meta_path = os.path.join(self.PERSIST_DIR, "model_meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._vocab = data["vocab"]
                self._idf = data["idf"]
                self.dim = data.get("dim", self.dim)
                self._trained = data.get("trained", False)
                svd_path = os.path.join(self.PERSIST_DIR, "svd_components.npy")
                if os.path.exists(svd_path):
                    self._svd_components = np.load(svd_path)
                else:
                    self._svd_components = None
                logger.info(f"LocalEmbeddingEngine: loaded model, vocab={len(self._vocab)}, trained={self._trained}")
            except Exception as exc:
                logger.warning(f"LocalEmbeddingEngine: failed to load model: {exc}")
