"""求解器测试：使用脚本生成的真实 PKI 材料 + 本机 openssl 核验。"""

from __future__ import annotations

import copy
import pathlib

import pytest

from app.certutil import der_size, extract_certs
from app.planner import (
    MAX_BATCHES,
    MAX_CANDIDATES,
    ChainPlanner,
    build_planner,
)


def _planner(data) -> ChainPlanner:
    return build_planner(
        data["hostname"],
        data["leaf_pem"],
        data["candidate_pems"],
        data["batches"],
    )


def test_samples_have_expected_structure(sample_data):
    assert sample_data["hostname"]
    assert len(extract_certs(sample_data["leaf_pem"])) == 1
    assert 1 <= len(sample_data["candidate_pems"]) <= MAX_CANDIDATES
    for pem in sample_data["candidate_pems"]:
        assert len(extract_certs(pem)) == 1
    assert 1 <= len(sample_data["batches"]) <= MAX_BATCHES
    for batch in sample_data["batches"]:
        assert len(extract_certs(batch["bundle_pem"])) >= 1
        assert batch["byte_limit"] > 0


def test_enumeration_includes_leaf_only_and_sorted_by_bytes(sample_data):
    planner = _planner(sample_data)
    options = planner.enumerate_chains()
    # 含仅叶子链
    assert options[0].intermediate_count == 0
    assert options[0].total_bytes == der_size(planner.leaf)
    # 按 DER 总字节升序
    sizes = [o.total_bytes for o in options]
    assert sizes == sorted(sizes)
    # 指纹去重
    fps = [o.fingerprints for o in options]
    assert len(fps) == len(set(fps))


def test_default_sample_fits_and_picks_shortest_common_chain(sample_data):
    result = _planner(sample_data).solve()
    assert result.status == "fit"
    assert result.pem.count("BEGIN CERTIFICATE") == len(result.chain)
    # 最小链 = 叶子 + root-a 直签的 tier2（1 张中间）
    assert len(result.chain) == 2
    assert result.chain[0]["role"] == "叶子证书"
    assert all(c["ok"] and c["fits_limit"] for c in result.checks)
    # 字节统计与链上证书一致
    assert result.total_bytes == sum(m["der_bytes"] for m in result.chain)


def test_minimality_no_smaller_verifiable_chain(sample_data):
    planner = _planner(sample_data)
    result = planner.solve()
    options = planner.enumerate_chains()
    smaller = [o for o in options if o.total_bytes < result.total_bytes]
    # 任何更小的候选链都至少在一批终端核验失败
    for option in smaller:
        outcomes = [planner._verify(option, j).ok for j in range(len(planner.batches))]
        assert not all(outcomes)


def test_too_large_reports_required_bytes(sample_data):
    data = copy.deepcopy(sample_data)
    data["batches"][0]["byte_limit"] = 1024
    result = _planner(data).solve()
    assert result.status == "too_large"
    assert len(result.required_limits) == 1
    req = result.required_limits[0]
    assert req["required_bytes"] == result.total_bytes
    assert req["overflow"] == result.total_bytes - 1024
    # 仍给出可复制 PEM
    assert "BEGIN CERTIFICATE" in result.pem
    # 其它未超限批次不受影响
    assert all(c["ok"] for c in result.checks)


def test_infeasible_when_no_common_root(sample_data):
    data = copy.deepcopy(sample_data)
    # 批次1/3 只信任 root-a，批次2 只信任 root-b：不存在对三者同时成立的链
    root_a = (
        pathlib.Path(__file__).resolve().parent.parent
        / "samples_test"
        / "bundles"
        / "root-a-bundle.pem"
    ).read_text(encoding="utf-8")
    root_b = (
        pathlib.Path(__file__).resolve().parent.parent
        / "samples_test"
        / "bundles"
        / "root-b-bundle.pem"
    ).read_text(encoding="utf-8")
    data["batches"][0]["bundle_pem"] = root_a
    data["batches"][1]["bundle_pem"] = root_b
    data["batches"][2]["bundle_pem"] = root_a
    result = _planner(data).solve()
    assert result.status == "infeasible"
    assert result.enumerated_chains >= 1
    # 每批都有诊断，且失败原因非空
    for info in result.infeasibility:
        assert info["reasons"]
        assert info["chains_total"] == result.enumerated_chains


def test_root_b_only_picks_cross_signed_branch(sample_data):
    data = copy.deepcopy(sample_data)
    root_b = (
        pathlib.Path(__file__).resolve().parent.parent
        / "samples_test"
        / "bundles"
        / "root-b-bundle.pem"
    ).read_text(encoding="utf-8")
    for batch in data["batches"]:
        batch["bundle_pem"] = root_b
    result = _planner(data).solve()
    assert result.status == "fit"
    # root-b 路径必须走交叉签发的 tier1-b：叶子 + tier2 + tier1（2 张中间）
    assert len(result.chain) == 3
    assert result.chain[2]["common_name"] == "Demo Tier1 Cross-Signed CA"


def test_expired_candidate_is_rejected_by_openssl(sample_data):
    data = copy.deepcopy(sample_data)
    # 只保留过期的 tier1 与 tier2（移除直签 tier2 与交叉签发有效证书）
    data["candidate_pems"] = [
        sample_data["candidate_pems"][0],  # tier2（tier1 签发）
        sample_data["candidate_pems"][4],  # tier1 过期版
    ]
    result = _planner(data).solve()
    assert result.status == "infeasible"
    reasons = " ".join(
        r["reason"] for info in result.infeasibility for r in info["reasons"]
    )
    assert "expired" in reasons.lower() or "has expired" in reasons.lower()


def test_zero_candidates_yields_leaf_only_enumeration(sample_data):
    data = copy.deepcopy(sample_data)
    result = build_planner(
        data["hostname"], data["leaf_pem"], [], data["batches"]
    ).solve()
    assert result.enumerated_chains == 1
    assert result.status == "infeasible"  # 根包不含叶子的直接签发者


def test_hostname_mismatch_is_infeasible(sample_data):
    data = copy.deepcopy(sample_data)
    result = build_planner(
        "wrong-name.internal.example",
        data["leaf_pem"],
        data["candidate_pems"],
        data["batches"],
    ).solve()
    assert result.status == "infeasible"
    reasons = " ".join(
        r["reason"] for info in result.infeasibility for r in info["reasons"]
    )
    assert "hostname" in reasons.lower()
    assert "demo.service.internal" in reasons


def test_duplicate_candidates_are_deduplicated(sample_data):
    data = copy.deepcopy(sample_data)
    data["candidate_pems"] = (
        sample_data["candidate_pems"] + [sample_data["candidate_pems"][0]]
    )
    planner = _planner(data)
    unique = {c.fingerprint for c in planner.candidates}
    assert len(planner.candidates) == len(unique)


def test_cycle_is_terminated_by_subject_guard(sample_data):
    # 构造自引用候选（主题==颁发者）不会导致枚举死循环
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Self Loop CA")]
    )
    # 让叶子的颁发者指向该自签名证书，保证它在枚举中被访问
    leaf = extract_certs(sample_data["leaf_pem"])[0]
    loop_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf.issuer)
        .issuer_name(leaf.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    loop_pem = loop_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    data = copy.deepcopy(sample_data)
    data["candidate_pems"] = [loop_pem]
    planner = _planner(data)
    options = planner.enumerate_chains()  # 必须正常返回
    assert all(len(o.certs) <= 2 for o in options)


def test_invalid_inputs_raise(sample_data):
    data = copy.deepcopy(sample_data)
    with pytest.raises(ValueError):
        build_planner("", data["leaf_pem"], data["candidate_pems"], data["batches"])
    with pytest.raises(Exception):
        build_planner(
            data["hostname"],
            "not a pem",
            data["candidate_pems"],
            data["batches"],
        )
    with pytest.raises(Exception):
        # 叶子栏含两张证书
        build_planner(
            data["hostname"],
            data["leaf_pem"] + data["leaf_pem"],
            data["candidate_pems"],
            data["batches"],
        )
    bad_batches = copy.deepcopy(data["batches"])
    bad_batches[0]["byte_limit"] = 0
    with pytest.raises(ValueError):
        build_planner(
            data["hostname"], data["leaf_pem"], data["candidate_pems"], bad_batches
        )
    with pytest.raises(ValueError):
        build_planner(
            data["hostname"],
            data["leaf_pem"],
            data["candidate_pems"],
            [],
        )


def test_too_many_candidates_rejected(sample_data):
    data = copy.deepcopy(sample_data)
    with pytest.raises(ValueError):
        build_planner(
            data["hostname"],
            data["leaf_pem"],
            data["candidate_pems"] * 2,  # 去重前已超 8 槽
            data["batches"],
        )
