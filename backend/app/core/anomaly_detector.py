"""
情报异常检测引擎
基于统计异常检测 + 时间序列异常分析 + 多变量异常检测
"""
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
from loguru import logger
from scipy import stats
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """情报异常检测器"""

    def __init__(self):
        self._historical_data = defaultdict(list)
        self._baseline_stats = {}
        self._anomaly_cache = {}
        self._detection_window = timedelta(hours=24)

    async def detect_anomalies(
        self,
        data_points: list[dict[str, Any]],
        metric_field: str = "confidence",
        time_field: str = "created_at",
        method: str = "auto",
    ) -> dict[str, Any]:
        """
        检测数据中的异常点

        Args:
            data_points: 数据点列表
            metric_field: 用于检测的指标字段
            time_field: 时间字段
            method: 检测方法 (zscore/iqr/dbscan/auto)

        Returns:
            异常检测结果
        """
        if not data_points:
            return {"anomalies": [], "summary": {"total": 0, "anomaly_count": 0}}

        # 提取数值序列
        values = []
        timestamps = []
        valid_points = []

        for point in data_points:
            if metric_field in point and point[metric_field] is not None:
                try:
                    val = float(point[metric_field])
                    values.append(val)
                    timestamps.append(point.get(time_field, datetime.now(timezone.utc)))
                    valid_points.append(point)
                except (ValueError, TypeError):
                    continue

        if len(values) < 3:
            return {"anomalies": [], "summary": {"total": len(data_points), "anomaly_count": 0}}

        # 自动选择检测方法
        if method == "auto":
            method = self._select_detection_method(values)

        # 执行异常检测
        if method == "zscore":
            anomalies = self._zscore_detection(values, valid_points, timestamps)
        elif method == "iqr":
            anomalies = self._iqr_detection(values, valid_points, timestamps)
        elif method == "dbscan":
            anomalies = self._dbscan_detection(values, valid_points, timestamps)
        else:
            anomalies = self._zscore_detection(values, valid_points, timestamps)

        # 时间序列异常检测
        ts_anomalies = self._timeseries_anomaly_detection(values, timestamps, valid_points)

        # 合并结果
        all_anomalies = self._merge_anomalies(anomalies, ts_anomalies)

        # 计算异常严重程度
        for anomaly in all_anomalies:
            anomaly["severity"] = self._calculate_severity(anomaly, values)

        return {
            "anomalies": all_anomalies,
            "summary": {
                "total": len(data_points),
                "analyzed": len(values),
                "anomaly_count": len(all_anomalies),
                "anomaly_rate": len(all_anomalies) / len(values) if values else 0,
                "detection_method": method,
                "mean": statistics.mean(values),
                "std": statistics.stdev(values) if len(values) > 1 else 0,
            },
        }

    def _select_detection_method(self, values: list[float]) -> str:
        """根据数据分布选择检测方法"""
        n = len(values)

        # 小样本用IQR
        if n < 30:
            return "iqr"

        # 检查正态性
        if n >= 8:
            _, p_value = stats.shapiro(values[:min(n, 5000)])
            if p_value > 0.05:
                return "zscore"

        # 非正态分布用DBSCAN
        return "dbscan"

    def _zscore_detection(
        self,
        values: list[float],
        points: list[dict],
        timestamps: list,
        threshold: float = 3.0,
    ) -> list[dict]:
        """Z-score异常检测"""
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0

        if std == 0:
            return []

        anomalies = []
        for i, (val, point, ts) in enumerate(zip(values, points, timestamps)):
            zscore = abs((val - mean) / std)
            if zscore > threshold:
                anomalies.append({
                    "point": point,
                    "value": val,
                    "zscore": zscore,
                    "deviation": val - mean,
                    "direction": "high" if val > mean else "low",
                    "timestamp": ts,
                    "detection_method": "zscore",
                })

        return anomalies

    def _iqr_detection(
        self,
        values: list[float],
        points: list[dict],
        timestamps: list,
        multiplier: float = 1.5,
    ) -> list[dict]:
        """IQR异常检测"""
        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        anomalies = []
        for i, (val, point, ts) in enumerate(zip(values, points, timestamps)):
            if val < lower_bound or val > upper_bound:
                anomalies.append({
                    "point": point,
                    "value": val,
                    "iqr_score": (val - q1) / iqr if iqr > 0 else 0,
                    "bounds": {"lower": lower_bound, "upper": upper_bound},
                    "direction": "high" if val > upper_bound else "low",
                    "timestamp": ts,
                    "detection_method": "iqr",
                })

        return anomalies

    def _dbscan_detection(
        self,
        values: list[float],
        points: list[dict],
        timestamps: list,
        eps: float = 0.5,
        min_samples: int = 5,
    ) -> list[dict]:
        """DBSCAN聚类异常检测"""
        if len(values) < min_samples:
            return []

        # 标准化
        X = np.array(values).reshape(-1, 1)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # DBSCAN聚类
        clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(X_scaled)
        labels = clustering.labels_

        anomalies = []
        for i, (label, val, point, ts) in enumerate(zip(labels, values, points, timestamps)):
            if label == -1:  # 噪声点即为异常
                anomalies.append({
                    "point": point,
                    "value": val,
                    "cluster_label": label,
                    "timestamp": ts,
                    "detection_method": "dbscan",
                })

        return anomalies

    def _timeseries_anomaly_detection(
        self,
        values: list[float],
        timestamps: list,
        points: list[dict],
        window_size: int = 7,
    ) -> list[dict]:
        """时间序列异常检测（移动平均 + 指数平滑）"""
        if len(values) < window_size:
            return []

        # 移动平均
        ma = np.convolve(values, np.ones(window_size)/window_size, mode='valid')
        ma_padded = [np.nan] * (window_size - 1) + ma.tolist()

        # 计算残差
        residuals = [v - m for v, m in zip(values, ma_padded) if not np.isnan(m)]

        if len(residuals) < 3:
            return []

        # 检测残差异常
        residual_mean = statistics.mean(residuals)
        residual_std = statistics.stdev(residuals)

        anomalies = []
        for i, (val, point, ts) in enumerate(zip(values, points, timestamps)):
            if i < window_size - 1:
                continue

            residual = val - ma_padded[i]
            zscore = abs((residual - residual_mean) / residual_std) if residual_std > 0 else 0

            if zscore > 2.5:
                anomalies.append({
                    "point": point,
                    "value": val,
                    "trend_value": ma_padded[i],
                    "residual": residual,
                    "residual_zscore": zscore,
                    "timestamp": ts,
                    "detection_method": "timeseries",
                })

        return anomalies

    def _merge_anomalies(self, *anomaly_lists) -> list[dict]:
        """合并多个检测结果，去重"""
        merged = {}
        for anomalies in anomaly_lists:
            for anomaly in anomalies:
                # 使用point的id或timestamp作为key
                point = anomaly.get("point", {})
                key = point.get("id") or point.get("title") or str(anomaly.get("timestamp"))

                if key not in merged:
                    merged[key] = anomaly
                    merged[key]["detection_methods"] = [anomaly.get("detection_method")]
                else:
                    # 合并检测方法
                    method = anomaly.get("detection_method")
                    if method not in merged[key]["detection_methods"]:
                        merged[key]["detection_methods"].append(method)
                    # 保留更高的zscore
                    if "zscore" in anomaly and anomaly["zscore"] > merged[key].get("zscore", 0):
                        merged[key].update(anomaly)

        return list(merged.values())

    def _calculate_severity(self, anomaly: dict, all_values: list[float]) -> str:
        """计算异常严重程度"""
        zscore = anomaly.get("zscore", 0)
        methods_count = len(anomaly.get("detection_methods", []))

        # 综合评分
        if zscore > 4 or methods_count >= 3:
            return "critical"
        elif zscore > 3 or methods_count >= 2:
            return "high"
        elif zscore > 2:
            return "medium"
        else:
            return "low"

    async def update_baseline(self, data_points: list[dict[str, Any]], metric_field: str = "confidence"):
        """更新基线统计"""
        values = []
        for point in data_points:
            if metric_field in point and point[metric_field] is not None:
                try:
                    values.append(float(point[metric_field]))
                except (ValueError, TypeError):
                    continue

        if len(values) >= 10:
            self._baseline_stats = {
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "std": statistics.stdev(values) if len(values) > 1 else 0,
                "q1": np.percentile(values, 25),
                "q3": np.percentile(values, 75),
                "min": min(values),
                "max": max(values),
                "count": len(values),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            logger.info(f"Baseline updated: mean={self._baseline_stats['mean']:.3f}, std={self._baseline_stats['std']:.3f}")

    def get_baseline_stats(self) -> dict:
        """获取基线统计"""
        return self._baseline_stats.copy()


# 全局实例
anomaly_detector = AnomalyDetector()
