"""Flask API 冒烟测试。"""

from __future__ import annotations

import copy
import json
import pathlib

import pytest

from app.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.testing = True
    return app.test_client()


@pytest.fixture()
def payload(sample_data):
    return json.loads(json.dumps(sample_data))  # 深拷贝，避免用例间污染


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "证书链选配器".encode() in resp.data


def test_sample_api(client):
    resp = client.get("/api/sample")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["hostname"]
    assert 1 <= len(data["candidate_pems"]) <= 8
    assert 1 <= len(data["batches"]) <= 4


def test_summaries_leaf_candidate_bundle(client, payload):
    resp = client.post(
        "/api/summaries", json={"kind": "leaf", "pem": payload["leaf_pem"]}
    )
    data = resp.get_json()
    assert data["ok"] and data["summary"]["common_name"] == payload["hostname"]

    resp = client.post(
        "/api/summaries",
        json={"kind": "candidate", "pem": payload["candidate_pems"][0]},
    )
    assert resp.get_json()["ok"]

    resp = client.post(
        "/api/summaries",
        json={"kind": "bundle", "pem": payload["batches"][0]["bundle_pem"]},
    )
    data = resp.get_json()
    assert data["ok"] and data["summary"]["count"] >= 1

    resp = client.post("/api/summaries", json={"kind": "leaf", "pem": "garbage"})
    assert resp.get_json()["ok"] is False


def test_select_api_fit(client, payload):
    resp = client.post("/api/select", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] and data["status"] == "fit"
    assert data["total_bytes"] > 0
    assert "BEGIN CERTIFICATE" in data["pem"]
    assert all(c["ok"] and c["fits_limit"] for c in data["checks"])
    assert data["enumerated_chains"] >= 1


def test_select_api_too_large(client, payload):
    payload["batches"][0]["byte_limit"] = 512
    data = client.post("/api/select", json=payload).get_json()
    assert data["ok"] and data["status"] == "too_large"
    assert data["required_limits"][0]["required_bytes"] == data["total_bytes"]
    assert "BEGIN CERTIFICATE" in data["pem"]


def test_select_api_infeasible(client, payload):
    base = pathlib.Path(__file__).resolve().parent.parent / "samples_test" / "bundles"
    root_a = (base / "root-a-bundle.pem").read_text(encoding="utf-8")
    root_b = (base / "root-b-bundle.pem").read_text(encoding="utf-8")
    # 三批根包互不相交 => 无共用链
    payload["batches"][0]["bundle_pem"] = root_a
    payload["batches"][1]["bundle_pem"] = root_b
    payload["batches"][2]["bundle_pem"] = root_a
    data = client.post("/api/select", json=payload).get_json()
    assert data["ok"] and data["status"] == "infeasible"
    assert len(data["infeasibility"]) == len(payload["batches"])
    assert data["pem"] == ""


def test_select_api_rejects_bad_input(client, payload):
    # 叶子栏放两张证书
    payload["leaf_pem"] = payload["leaf_pem"] + payload["leaf_pem"]
    assert client.post("/api/select", json=payload).status_code == 400

    # 缺批次
    bad = copy.deepcopy(payload)
    bad["batches"] = []
    assert client.post("/api/select", json=bad).status_code == 400

    # 字节上限非正整数
    bad = copy.deepcopy(payload)
    bad["batches"][0]["byte_limit"] = -3
    assert client.post("/api/select", json=bad).status_code == 400

    # 候选超 8 张
    bad = copy.deepcopy(payload)
    bad["candidate_pems"] = [f"slot-{i}" for i in range(9)]
    assert client.post("/api/select", json=bad).status_code == 400

    # 域名缺失
    bad = copy.deepcopy(payload)
    bad["hostname"] = "  "
    assert client.post("/api/select", json=bad).status_code == 400


def test_zero_candidates_accepted_but_infeasible(client, payload):
    payload["candidate_pems"] = []
    data = client.post("/api/select", json=payload).get_json()
    assert data["ok"] and data["status"] == "infeasible"
    assert data["enumerated_chains"] == 1
