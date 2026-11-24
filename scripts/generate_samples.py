"""生成可在网页直接试跑的证书链选配样例。

层级（两套根 PKI，含同一中间 CA 的交叉签发与多级/短链分支）::

    root-a (Root A)                    root-b (Root B)
      |                                   |
      |-- tier1 CA (A 签发, 同主题同公钥) |-- tier1 CA (B 签发, 交叉签发)
      |-- tier1 过期版本 (A 签发)          |
      |-- tier2 CA (root-a 直签, 短链)     |
      |                                   |
      +-- tier1(A) -- tier2 CA -----------+   (tier2 同时被 tier1 与 root-a 签发)
                            |
                          leaf（SAN = demo.service.internal）

另生成一张与任何签发关系都不匹配的“干扰”候选，演示不可达分支被自动忽略。

终端批次：
  批次1 根包=root-a+root-b，上限较宽松；
  批次2 根包=root-a，         上限中等；
  批次3 根包=root-a+root-b， 上限最紧（默认仍可装下最小链）。

另在 samples/bundles/ 下提供 root-b-only 根包，把任一批次换成它即可演示
“没有共用链（无解）”。

产物（默认写入 samples/）：
  roots/         root-a / root-b 自签名证书
  intermediates/ 5 张候选中间证书 PEM
  leaf/          叶子证书 PEM
  bundles/       各根包（含单根包、并集包）
  sample.json    页面表单预填数据

样例仅用于本地演示：私钥在内存生成，不落盘私钥文件，请勿用于真实环境。
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DOMAIN = "demo.service.internal"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str, ou: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Chain Picker Demo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _save(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def make_root(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(cn, "Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_ca_cert(
    cn: str,
    subject_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    *,
    path_length: int | None = 0,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = not_valid_before or (now - datetime.timedelta(days=1))
    not_valid_after = not_valid_after or (now + datetime.timedelta(days=1825))
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn, "Intermediate CA"))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def make_leaf(
    dns_name: str,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(dns_name, "Service"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=398))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return cert


def generate(out_dir: str | os.PathLike = "samples") -> pathlib.Path:
    out = pathlib.Path(out_dir)
    now = datetime.datetime.now(datetime.timezone.utc)

    # ---- 两套独立根 PKI ------------------------------------------------
    root_a, root_a_key = make_root("Demo Root A CA")
    root_b, root_b_key = make_root("Demo Root B CA")

    # ---- 交叉签发的一级中间 CA（同主题、同公钥，分别由 A/B 根签发） -----
    # 叶子的真实签发路径经过它，因此两张证书都会进入枚举并由各批根包选择
    tier1_key = _key()
    tier1_cn = "Demo Tier1 Cross-Signed CA"
    tier1_a = make_ca_cert(tier1_cn, tier1_key, root_a, root_a_key, path_length=1)
    tier1_b = make_ca_cert(tier1_cn, tier1_key, root_b, root_b_key, path_length=1)
    # 同主题、同公钥的过期版本（仍由 A 根签发）：签名链可建立，
    # openssl 会在有效期环节以 certificate has expired 淘汰
    tier1_expired = make_ca_cert(
        tier1_cn,
        tier1_key,
        root_a,
        root_a_key,
        path_length=1,
        not_valid_before=now - datetime.timedelta(days=730),
        not_valid_after=now - datetime.timedelta(days=365),
    )

    # ---- 二级中间 CA，由 tier1 签发，再由它签发叶子 ---------------------
    tier2_key = _key()
    tier2 = make_ca_cert("Demo Tier2 Intermediate CA", tier2_key, tier1_a, tier1_key)

    # ---- 另一条 A 根直连分支：tier2 同时被 root-a 直接签发 --------------
    # 给出“叶子 + tier2”两证书短链（信任锚为 root-a），字节更小
    tier2_direct_a = make_ca_cert(
        "Demo Tier2 Intermediate CA", tier2_key, root_a, root_a_key
    )

    # ---- 无关干扰候选：主题与任何签发关系都不匹配，枚举时不可达 ----------
    decoy_key = _key()
    decoy = make_ca_cert("Demo Unrelated Decoy CA", decoy_key, root_a, root_a_key)

    # ---- 叶子：由 tier2 签发 --------------------------------------------
    leaf = make_leaf(DOMAIN, tier2, tier2_key)

    # ---- 落盘 -----------------------------------------------------------
    _save(out / "roots" / "root-a.pem", _pem_cert(root_a))
    _save(out / "roots" / "root-b.pem", _pem_cert(root_b))

    intermediates = {
        "tier1-cross-a.pem": tier1_a,
        "tier1-cross-b.pem": tier1_b,
        "tier1-expired-a.pem": tier1_expired,
        "tier2.pem": tier2,
        "tier2-direct-a.pem": tier2_direct_a,
        "decoy-unrelated.pem": decoy,
    }
    for fname, cert in intermediates.items():
        _save(out / "intermediates" / fname, _pem_cert(cert))

    _save(out / "leaf" / "leaf.pem", _pem_cert(leaf))

    bundle_a = _pem_cert(root_a)
    bundle_b = _pem_cert(root_b)
    bundle_union = bundle_a + bundle_b
    _save(out / "bundles" / "root-a-bundle.pem", bundle_a)
    _save(out / "bundles" / "root-b-bundle.pem", bundle_b)
    _save(out / "bundles" / "union-bundle.pem", bundle_union)

    sample = {
        "hostname": DOMAIN,
        "leaf_pem": _pem_cert(leaf),
        "candidate_pems": [
            _pem_cert(tier2),
            _pem_cert(tier2_direct_a),
            _pem_cert(tier1_a),
            _pem_cert(tier1_b),
            _pem_cert(tier1_expired),
            _pem_cert(decoy),
        ],
        "batches": [
            {
                "name": "批次1-双根宽松",
                "bundle_pem": bundle_union,
                "byte_limit": 8192,
            },
            {
                "name": "批次2-仅根A",
                "bundle_pem": bundle_a,
                "byte_limit": 4096,
            },
            {
                "name": "批次3-双根紧限",
                "bundle_pem": bundle_union,
                "byte_limit": 4096,
            },
        ],
    }
    meta_path = out / "sample.json"
    meta_path.write_text(json.dumps(sample, ensure_ascii=False, indent=2), "utf-8")
    return meta_path


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "samples"
    path = generate(target)
    print(f"样例证书已生成: {path.resolve()}")
