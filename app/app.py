"""Flask 入口：录入叶子/候选中间证书与终端批次，调用链选配求解器并展示结果。"""

from __future__ import annotations

import json
import os
import pathlib

from flask import Flask, jsonify, render_template, request

from .certutil import PemError, bundle_summary, cert_summary, extract_certs
from .planner import MAX_BATCHES, MAX_CANDIDATES, build_planner

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
SAMPLE_PATH = BASE_DIR / "samples" / "sample.json"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False

    @app.get("/")
    def index():  # pragma: no cover - 纯渲染
        sample = None
        if SAMPLE_PATH.exists():
            sample = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
        return render_template("index.html", sample=sample)

    @app.get("/api/sample")
    def get_sample():
        if not SAMPLE_PATH.exists():
            return jsonify({"error": "样例尚未生成，请先运行 generate_samples.py"}), 404
        return jsonify(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))

    @app.post("/api/summaries")
    def summaries():
        """返回粘贴 PEM 的概要，供页面即时确认材料是否解析成功。"""
        payload = request.get_json(force=True, silent=True) or {}
        kind = payload.get("kind")
        pem = payload.get("pem", "")
        try:
            certs = extract_certs(pem)
            if kind == "bundle":
                return jsonify({"ok": True, "summary": bundle_summary(pem)})
            if kind in ("leaf", "candidate"):
                if kind == "leaf" and len(certs) != 1:
                    return jsonify(
                        {"ok": False, "error": f"叶子栏只能含 1 张证书，实际 {len(certs)} 张"}
                    ), 200
                return jsonify(
                    {"ok": True, "summary": cert_summary(certs[0]), "cert_count": len(certs)}
                )
            return jsonify({"ok": False, "error": "kind 须为 leaf、candidate 或 bundle"}), 400
        except PemError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 200

    @app.post("/api/select")
    def select():
        payload = request.get_json(force=True, silent=True) or {}
        hostname = str(payload.get("hostname", "")).strip()
        leaf_pem = str(payload.get("leaf_pem", ""))
        candidate_pems = [
            str(x) for x in (payload.get("candidate_pems") or []) if str(x).strip()
        ]
        raw_batches = payload.get("batches") or []

        if not isinstance(raw_batches, list) or not raw_batches:
            return jsonify({"ok": False, "error": "至少需要 1 批终端"}), 400
        if len(raw_batches) > MAX_BATCHES:
            return jsonify({"ok": False, "error": f"终端批次最多 {MAX_BATCHES} 批"}), 400
        if len(candidate_pems) > MAX_CANDIDATES:
            return jsonify(
                {"ok": False, "error": f"候选中间证书最多 {MAX_CANDIDATES} 张"}
            ), 400

        batch_rows: list[dict] = []
        for idx, row in enumerate(raw_batches, start=1):
            if not isinstance(row, dict):
                return jsonify({"ok": False, "error": f"第 {idx} 批终端数据格式错误"}), 400
            batch_rows.append(
                {
                    "name": str(row.get("name", "") or f"批次{idx}"),
                    "bundle_pem": str(row.get("bundle_pem", "")),
                    "byte_limit": row.get("byte_limit"),
                }
            )

        try:
            planner = build_planner(hostname, leaf_pem, candidate_pems, batch_rows)
            result = planner.solve()
        except PemError as exc:
            return jsonify({"ok": False, "error": f"PEM 解析失败: {exc}"}), 400
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        return jsonify(
            {
                "ok": True,
                "status": result.status,
                "message": result.message,
                "total_bytes": result.total_bytes,
                "leaf_bytes": result.leaf_bytes,
                "pem": result.pem,
                "chain": result.chain,
                "checks": result.checks,
                "required_limits": result.required_limits,
                "infeasibility": result.infeasibility,
                "enumerated_chains": result.enumerated_chains,
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
