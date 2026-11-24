"""证书解析与核验工具。

核验基于系统 openssl 命令（``openssl verify``），同时完成：
  1. 链签名、基本约束与有效期核验（核验时刻为当前系统时间）；
  2. 以终端根证书包作为唯一信任锚（``-no-CAfile``，不加载系统默认 CA）；
  3. 按服务域名做 SAN/CN 主机名校验（``-verify_hostname``）。

所有 PEM 数据均视为不可信外部输入，只通过临时文件传给 openssl 子进程。
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


class PemError(ValueError):
    """PEM 内容无法解析为证书时抛出。"""


def extract_certs(pem_text: str) -> list[x509.Certificate]:
    """从一段 PEM 文本中提取全部证书，按文件中的顺序返回。"""
    if not pem_text or not pem_text.strip():
        raise PemError("PEM 内容为空")
    blobs = _PEM_RE.findall(pem_text.encode("utf-8", errors="replace"))
    certs: list[x509.Certificate] = []
    for blob in blobs:
        try:
            certs.append(x509.load_pem_x509_certificate(blob))
        except Exception as exc:  # pragma: no cover - 正则已限定 PEM 结构
            raise PemError(f"无法解析证书: {exc}") from exc
    if not certs:
        raise PemError("未找到 PEM 证书（需要 -----BEGIN CERTIFICATE----- 块）")
    return certs


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii").strip()


def der_size(cert: x509.Certificate) -> int:
    """证书的 DER 编码字节数（部署字节上限按此统计）。"""
    return len(cert_der(cert))


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def name_der(name: x509.Name) -> bytes:
    """主题/颁发者 Name 的 DER 编码，用于签发关系的精确字节级比较。"""
    return name.public_bytes()


def cert_subject(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:  # pragma: no cover
        return "<未知主题>"


def cert_issuer(cert: x509.Certificate) -> str:
    try:
        return cert.issuer.rfc4514_string()
    except Exception:  # pragma: no cover
        return "<未知颁发者>"


def _extension_oid_value(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def cert_summary(cert: x509.Certificate) -> dict:
    """单张证书的概要，供页面粘贴后即时确认。"""
    cn = ""
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            cn = attrs[0].value
    except x509.ExtensionNotFound:
        pass
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    ski = _extension_oid_value(cert, x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki = _extension_oid_value(cert, x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    bc = _extension_oid_value(cert, x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    return {
        "subject": cert_subject(cert),
        "common_name": cn,
        "issuer": cert_issuer(cert),
        "serial": f"{cert.serial_number:X}",
        "sans": sans,
        "is_ca": bool(bc and bc.ca),
        "ski": ski.digest.hex() if ski is not None else "",
        "aki": aki.key_identifier.hex() if aki is not None and aki.key_identifier else "",
        "der_bytes": der_size(cert),
        "not_valid_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "not_valid_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
    }


def bundle_summary(pem_text: str) -> dict:
    """根证书包概要（包内每个证书的主题/序列号/DER 字节）。"""
    certs = extract_certs(pem_text)
    return {
        "count": len(certs),
        "subjects": [cert_subject(c) for c in certs],
        "serials": [f"{c.serial_number:X}"[:16] for c in certs],
        "der_bytes": sum(der_size(c) for c in certs),
    }


def chain_pem(certs: list[x509.Certificate]) -> str:
    """把证书序列拼成叶子在前、中间 CA 依次在后的 PEM 链。"""
    return "\n".join(cert_pem(c) for c in certs)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:  # 方便直接 if result:
        return self.ok


def _write_pem_tmp(directory: str, name: str, pem_text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(pem_text)
    return path


def verify_chain(chain_certs: list[x509.Certificate], bundle_pem: str, hostname: str) -> VerifyResult:
    """用终端根证书包按域名核验服务证书链。

    ``chain_certs`` 为叶子在前、中间 CA 依次在后的证书对象列表（允许只有叶子）。
    返回 :class:`VerifyResult`；失败时 ``reason`` 为 openssl 给出的原因摘要。
    信任锚仅来自 ``bundle_pem``（-no-CAfile），系统默认 CA 不参与。
    """
    if not chain_certs:
        return VerifyResult(False, "证书链为空")
    bundle_certs = extract_certs(bundle_pem)
    if not bundle_certs:
        return VerifyResult(False, "根证书包为空")

    with tempfile.TemporaryDirectory(prefix="tlschain_") as tmp:
        bundle_path = _write_pem_tmp(tmp, "bundle.pem", bundle_pem)
        leaf_path = _write_pem_tmp(tmp, "leaf.pem", cert_pem(chain_certs[0]))
        untrusted_path = None
        if len(chain_certs) > 1:
            intermediates = "\n".join(cert_pem(c) for c in chain_certs[1:])
            untrusted_path = _write_pem_tmp(tmp, "untrusted.pem", intermediates)

        cmd = [
            "openssl",
            "verify",
            "-no-CAfile",
            "-CAfile",
            bundle_path,
            "-verify_hostname",
            hostname,
        ]
        if untrusted_path:
            cmd += ["-untrusted", untrusted_path]
        cmd.append(leaf_path)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    if proc.returncode == 0:
        return VerifyResult(True)
    # openssl 的具体原因在 "error N at X depth lookup: ..." 行，
    # 最后一行只有 "verification failed"，需扫描全部输出。
    detail_lines = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = ""
    for line in detail_lines:
        match = re.search(r"error \d+ at \d+ depth lookup:\s*(.+)$", line)
        if match:
            reason = match.group(1).strip()
            break
    if not reason:
        reason = (
            detail_lines[-1].strip()
            if detail_lines
            else f"openssl 返回码 {proc.returncode}"
        )
    reason = re.sub(r"^[^\s:]+: ", "", reason)
    if "hostname" in reason.lower() or "not match" in reason.lower():
        # 附带叶子实际 SAN，方便值班员定位域名问题
        sans: list[str] = []
        try:
            ext = chain_certs[0].extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        if sans:
            reason = f"{reason}（叶子证书 SAN: {', '.join(sans)}）"
    return VerifyResult(False, reason)
