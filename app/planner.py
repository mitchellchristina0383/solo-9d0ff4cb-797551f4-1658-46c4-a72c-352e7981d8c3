"""证书链选配求解器。

问题模型
========
保留已签发的叶子证书，从至多 8 张候选中间证书中选零张或多张，从叶子开始按
签发关系（证书的颁发者 Name == 下一张证书的主题 Name）排成一条 PEM 链。
每批终端只使用自己的根证书包，在同一核验时刻（当前系统时间）按服务域名核验
这条链；要求**所有批次都验证通过**，并在可行链中取叶子 + 中间证书的 DER
总字节数最小的一条。

候选中允许出现同一中间 CA（相同主题、相同公钥）由不同上级签发的多张证书，
它们在图上表现为同一主题节点的多个并行分支，枚举时都会被走到。

搜索方式
========
以叶子为起点，在“候选证书”构成的签发关系图上做深度优先枚举：

* 下一张候选证书的主题 Name（DER）必须等于当前证书的颁发者 Name（DER）；
* 同一主题 Name 不允许在链中重复（RFC 5280 合法链不会出现重复主题，也借此
  切断交叉签发环）；
* 每个路径前缀（含零张中间证书的“仅叶子”链）都是一条候选链，因为信任锚
  可能在链的任意深度出现；
* 候选去重按证书 DER 指纹，路径去重按链上证书指纹元组。

候选链先按 DER 总字节数升序排序，再逐批调用 openssl 核验（结果按
“链指纹 × 批次”缓存）。第一条全部批次通过的链即全局最小可行链；随后按各批
部署字节上限判定 fit / too_large；没有任何链通过全部批次时判定无解并给出
每批的失败原因明细。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509

from .certutil import (
    PemError,
    cert_der,
    cert_fingerprint,
    cert_issuer,
    cert_subject,
    cert_summary,
    chain_pem,
    der_size,
    extract_certs,
    name_der,
    verify_chain,
)

MAX_CANDIDATES = 8
MAX_BATCHES = 4
# 枚举路径数的安全上限：8 张候选的真实拓扑远达不到，仅用于防御恶意构造
MAX_ENUMERATED_PATHS = 10000


@dataclass
class Candidate:
    cert: x509.Certificate
    der_bytes: int
    fingerprint: str
    subject_der: bytes
    issuer_der: bytes
    slot: int  # 来源录入槽位（1 起），便于页面提示

    @property
    def subject(self) -> str:
        return cert_subject(self.cert)

    @property
    def issuer(self) -> str:
        return cert_issuer(self.cert)


@dataclass
class Batch:
    name: str
    bundle_pem: str
    byte_limit: int


@dataclass
class ChainOption:
    """一条候选链（叶子 + 若干中间证书）及其枚举期元数据。"""

    certs: list[x509.Certificate]
    fingerprints: tuple[str, ...]
    total_bytes: int
    intermediate_count: int


@dataclass
class BatchCheck:
    batch_index: int
    batch_name: str
    ok: bool
    reason: str = ""
    byte_limit: int = 0
    total_bytes: int = 0
    fits_limit: bool = False


@dataclass
class SolveResult:
    status: str  # "fit" | "too_large" | "infeasible"
    message: str = ""
    total_bytes: int = 0
    leaf_bytes: int = 0
    pem: str = ""
    chain: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    # too_large：每个受限批次要求的最小字节
    required_limits: list[dict] = field(default_factory=list)
    # infeasible：每批终端在全部候选链上的核验情况
    infeasibility: list[dict] = field(default_factory=list)
    enumerated_chains: int = 0


class ChainPlanner:
    def __init__(
        self,
        leaf: x509.Certificate,
        hostname: str,
        candidates: list[Candidate],
        batches: list[Batch],
    ):
        self.leaf = leaf
        self.hostname = hostname
        self.candidates = candidates
        self.batches = batches
        self.leaf_bytes = der_size(leaf)
        # 主题 Name(DER) -> 该主题下的全部候选证书（交叉签发 => 多张）
        self._by_subject: dict[bytes, list[Candidate]] = {}
        for cand in candidates:
            self._by_subject.setdefault(cand.subject_der, []).append(cand)
        # 核验缓存：(链指纹元组, 批次下标, 根包内容) -> VerifyResult
        # 根包内容入键，避免不同批次/规划器间同链误命中
        self._verify_cache: dict[tuple, object] = {}
        self._no_cache = object()

    # ------------------------------------------------------------------ #
    # 路径枚举
    # ------------------------------------------------------------------ #
    def enumerate_chains(self) -> list[ChainOption]:
        """枚举全部合法签发路径（含仅叶子链），按 DER 总字节升序返回。"""
        options: list[ChainOption] = []
        seen: set[tuple[str, ...]] = set()

        def emit(certs: list[x509.Certificate]) -> None:
            fps = tuple(cert_fingerprint(c) for c in certs)
            if fps in seen:
                return
            seen.add(fps)
            options.append(
                ChainOption(
                    certs=list(certs),
                    fingerprints=fps,
                    total_bytes=sum(der_size(c) for c in certs),
                    intermediate_count=len(certs) - 1,
                )
            )

        def dfs(current: x509.Certificate, path: list[x509.Certificate],
                used_subjects: set[bytes]) -> None:
            if len(options) >= MAX_ENUMERATED_PATHS:
                return
            # 当前路径本身就是一条候选链（信任锚可能就在此处）
            emit(path)
            issuer = name_der(current.issuer)
            if issuer in used_subjects:
                return  # 主题重复，切断环
            for nxt in self._by_subject.get(issuer, []):
                if len(options) >= MAX_ENUMERATED_PATHS:
                    return
                path.append(nxt.cert)
                used_subjects.add(issuer)
                dfs(nxt.cert, path, used_subjects)
                used_subjects.discard(issuer)
                path.pop()

        dfs(self.leaf, [self.leaf], {name_der(self.leaf.subject)})
        options.sort(key=lambda o: (o.total_bytes, o.intermediate_count, o.fingerprints))
        return options

    # ------------------------------------------------------------------ #
    # 核验
    # ------------------------------------------------------------------ #
    def _verify(self, option: ChainOption, batch_idx: int):
        bundle_pem = self.batches[batch_idx].bundle_pem
        key = (option.fingerprints, batch_idx, bundle_pem)
        cached = self._verify_cache.get(key, self._no_cache)
        if cached is not self._no_cache:
            return cached
        result = verify_chain(
            option.certs, bundle_pem, self.hostname
        )
        self._verify_cache[key] = result
        return result

    def solve(self) -> SolveResult:
        options = self.enumerate_chains()
        if len(options) >= MAX_ENUMERATED_PATHS:
            return SolveResult(
                status="infeasible",
                message=(
                    f"候选签发关系过于复杂，枚举路径达到上限 {MAX_ENUMERATED_PATHS}，"
                    "请减少候选中间证书后重试。"
                ),
                enumerated_chains=len(options),
            )

        # 记录每条链在各批上的核验结果，无解诊断时复用
        per_chain_checks: list[list[BatchCheck]] = []
        best: ChainOption | None = None

        for option in options:
            checks: list[BatchCheck] = []
            all_ok = True
            for j, batch in enumerate(self.batches):
                vr = self._verify(option, j)
                fits = option.total_bytes <= batch.byte_limit
                checks.append(
                    BatchCheck(
                        batch_index=j,
                        batch_name=batch.name,
                        ok=vr.ok,
                        reason=vr.reason,
                        byte_limit=batch.byte_limit,
                        total_bytes=option.total_bytes,
                        fits_limit=fits,
                    )
                )
                if not vr.ok:
                    all_ok = False
            per_chain_checks.append(checks)
            if all_ok:
                best = option
                break  # options 已按字节升序，首个全过即全局最小

        if best is None:
            return self._infeasible(options, per_chain_checks)

        best_idx = next(i for i, o in enumerate(options) if o.fingerprints == best.fingerprints)
        checks = per_chain_checks[best_idx]
        chain_meta = [
            {
                "position": i,
                "role": "叶子证书" if i == 0 else f"中间证书 {i}",
                **cert_summary(cert),
            }
            for i, cert in enumerate(best.certs)
        ]
        result = SolveResult(
            status="pending",
            total_bytes=best.total_bytes,
            leaf_bytes=self.leaf_bytes,
            pem=chain_pem(best.certs),
            chain=chain_meta,
            checks=[self._check_dict(c) for c in checks],
            enumerated_chains=len(options),
        )

        tight = [c for c in checks if not c.fits_limit]
        if tight:
            result.status = "too_large"
            result.required_limits = [
                {
                    "batch_index": c.batch_index,
                    "batch_name": c.batch_name,
                    "byte_limit": c.byte_limit,
                    "required_bytes": c.total_bytes,
                    "overflow": c.total_bytes - c.byte_limit,
                }
                for c in tight
            ]
            detail = "；".join(
                f"批次「{r['batch_name']}」上限 {r['byte_limit']} 字节，"
                f"至少需要 {r['required_bytes']} 字节（超 {r['overflow']} 字节）"
                for r in result.required_limits
            )
            result.message = (
                f"所有批次都能验证通过的最小链为 {best.total_bytes} 字节"
                f"（叶子 {self.leaf_bytes} + 中间 {best.intermediate_count} 张），"
                f"但仍超出部署字节上限：{detail}。"
            )
        else:
            result.status = "fit"
            result.message = (
                f"找到全部 {len(self.batches)} 批终端均可验证通过的最小证书链："
                f"{best.total_bytes} 字节（叶子 {self.leaf_bytes} 字节 + "
                f"{best.intermediate_count} 张中间证书），且均在各批部署字节上限内。"
            )
        return result

    # ------------------------------------------------------------------ #
    # 无解诊断
    # ------------------------------------------------------------------ #
    def _infeasible(
        self,
        options: list[ChainOption],
        per_chain_checks: list[list[BatchCheck]],
    ) -> SolveResult:
        infeasibility: list[dict] = []
        for j, batch in enumerate(self.batches):
            passed = [
                (options[i].total_bytes, options[i].intermediate_count)
                for i, checks in enumerate(per_chain_checks)
                if checks[j].ok
            ]
            reasons: dict[str, int] = {}
            for checks in per_chain_checks:
                reason = checks[j].reason or "未知原因"
                reasons[reason] = reasons.get(reason, 0) + 1
            top_reasons = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
            infeasibility.append(
                {
                    "batch_index": j,
                    "batch_name": batch.name,
                    "byte_limit": batch.byte_limit,
                    "chains_verified": len(passed),
                    "chains_total": len(options),
                    "reasons": [{"reason": r, "occurrences": n} for r, n in top_reasons],
                }
            )
        message = (
            f"无解：枚举了 {len(options)} 条由签发关系可达的候选链"
            "（含仅叶子链），没有任何一条能同时通过全部 "
            f"{len(self.batches)} 批终端的核验。详见各批失败原因。"
        )
        return SolveResult(
            status="infeasible",
            message=message,
            enumerated_chains=len(options),
            infeasibility=infeasibility,
        )

    @staticmethod
    def _check_dict(c: BatchCheck) -> dict:
        return {
            "batch_index": c.batch_index,
            "batch_name": c.batch_name,
            "ok": c.ok,
            "reason": c.reason,
            "byte_limit": c.byte_limit,
            "total_bytes": c.total_bytes,
            "fits_limit": c.fits_limit,
        }


# ---------------------------------------------------------------------- #
# 表单装配与输入校验
# ---------------------------------------------------------------------- #
def build_planner(
    hostname: str,
    leaf_pem: str,
    candidate_pems: list[str],
    batch_rows: list[dict],
) -> ChainPlanner:
    """从页面表单数据构造 :class:`ChainPlanner`，并完成全部输入校验。"""
    hostname = (hostname or "").strip()
    if not hostname:
        raise ValueError("服务域名不能为空")
    if len(hostname) > 253 or any(
        not part or len(part) > 63 for part in hostname.strip(".").split(".")
    ):
        raise ValueError(f"服务域名格式不合法: {hostname}")

    leaf_certs = extract_certs(leaf_pem)
    if len(leaf_certs) != 1:
        raise PemError(
            f"叶子证书栏只能包含 1 张证书，实际解析到 {len(leaf_certs)} 张；"
            "中间证书请放到候选区。"
        )
    leaf = leaf_certs[0]

    if len(candidate_pems) > MAX_CANDIDATES:
        raise ValueError(f"候选中间证书最多 {MAX_CANDIDATES} 张")
    candidates: list[Candidate] = []
    seen_der: set[bytes] = set()
    for slot, pem in enumerate(candidate_pems, start=1):
        text = (pem or "").strip()
        if not text:
            continue
        certs = extract_certs(text)
        if len(certs) != 1:
            raise PemError(
                f"候选中间证书第 {slot} 槽只能包含 1 张证书，"
                f"实际解析到 {len(certs)} 张"
            )
        cert = certs[0]
        raw = cert_der(cert)
        if raw in seen_der:
            continue  # 完全相同的证书重复粘贴，静默去重
        seen_der.add(raw)
        candidates.append(
            Candidate(
                cert=cert,
                der_bytes=len(raw),
                fingerprint=cert_fingerprint(cert),
                subject_der=name_der(cert.subject),
                issuer_der=name_der(cert.issuer),
                slot=slot,
            )
        )
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"去重后候选中间证书仍超过 {MAX_CANDIDATES} 张")

    if not (1 <= len(batch_rows) <= MAX_BATCHES):
        raise ValueError(f"终端批次须在 1~{MAX_BATCHES} 批之间")
    batches: list[Batch] = []
    for idx, row in enumerate(batch_rows, start=1):
        name = (row.get("name") or f"批次{idx}").strip() or f"批次{idx}"
        bundle_pem = row.get("bundle_pem", "")
        if not (bundle_pem or "").strip():
            raise PemError(f"批次「{name}」缺少根证书包 PEM")
        extract_certs(bundle_pem)  # 校验可解析
        try:
            limit = int(row.get("byte_limit"))
        except (TypeError, ValueError):
            raise ValueError(f"批次「{name}」的部署字节上限须为整数")
        if limit <= 0:
            raise ValueError(f"批次「{name}」的部署字节上限须为正整数")
        batches.append(Batch(name=name, bundle_pem=bundle_pem, byte_limit=limit))

    return ChainPlanner(hostname=hostname, leaf=leaf, candidates=candidates, batches=batches)
