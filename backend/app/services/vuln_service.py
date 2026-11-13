from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from backend.app.models.asset import Asset
from backend.app.models.vulnerability import (
    AssetVulnerability,
    RemediationStatus,
    Vulnerability,
    VulnerabilitySeverity,
)
from backend.app.schemas.vulnerability import (
    AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate,
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityScanResult,
    VulnerabilityUpdate,
)


class VulnerabilityService:
    @staticmethod
    def get_by_id(db: Session, vuln_id: str) -> Vulnerability | None:
        return db.get(Vulnerability, vuln_id)

    @staticmethod
    def get_by_cve(db: Session, cve_id: str) -> Vulnerability | None:
        stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper().strip())
        return db.scalars(stmt).first()

    @classmethod
    def create_vulnerability(cls, db: Session, vuln_in: VulnerabilityCreate) -> Vulnerability:
        vuln = Vulnerability(
            cve_id=vuln_in.cve_id.upper().strip() if vuln_in.cve_id else None,
            title=vuln_in.title.strip(),
            description=vuln_in.description,
            severity=vuln_in.severity.value,
            cvss_score=vuln_in.cvss_score,
            cvss_vector=vuln_in.cvss_vector,
            cwe_id=vuln_in.cwe_id.upper().strip() if vuln_in.cwe_id else None,
            affected_component=vuln_in.affected_component.lower().strip(),
            affected_versions=vuln_in.affected_versions,
            fixed_version=vuln_in.fixed_version,
            remediation_guidance=vuln_in.remediation_guidance,
            is_exploited=vuln_in.is_exploited,
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        return vuln

    @classmethod
    def update_vulnerability(
        cls, db: Session, vuln: Vulnerability, vuln_in: VulnerabilityUpdate
    ) -> Vulnerability:
        update_data = vuln_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(vuln, field, value)

        db.commit()
        db.refresh(vuln)
        return vuln

    @classmethod
    def list_vulnerabilities(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 50,
        search: str | None = None,
        severity: str | None = None,
        component: str | None = None,
        is_exploited: bool | None = None,
    ) -> tuple[list[Vulnerability], int]:
        stmt = select(Vulnerability)

        if search:
            term = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(Vulnerability.title).like(term),
                    func.lower(Vulnerability.cve_id).like(term),
                    func.lower(Vulnerability.affected_component).like(term),
                    func.lower(Vulnerability.description).like(term),
                )
            )

        if severity:
            stmt = stmt.where(Vulnerability.severity == severity)
        if component:
            stmt = stmt.where(Vulnerability.affected_component == component.lower())
        if is_exploited is not None:
            stmt = stmt.where(Vulnerability.is_exploited == is_exploited)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = db.scalar(count_stmt) or 0

        stmt = stmt.order_by(Vulnerability.cvss_score.desc().nullslast()).offset(skip).limit(limit)
        items = list(db.scalars(stmt).all())

        return items, total

    @classmethod
    def get_finding_by_id(cls, db: Session, finding_id: str) -> AssetVulnerability | None:
        stmt = (
            select(AssetVulnerability)
            .where(AssetVulnerability.id == finding_id)
            .options(joinedload(AssetVulnerability.vulnerability), joinedload(AssetVulnerability.asset))
        )
        return db.scalars(stmt).first()

    @classmethod
    def list_findings(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 50,
        asset_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
    ) -> tuple[list[AssetVulnerability], int]:
        stmt = select(AssetVulnerability).options(
            joinedload(AssetVulnerability.vulnerability),
            joinedload(AssetVulnerability.asset)
        )

        if asset_id:
            stmt = stmt.where(AssetVulnerability.asset_id == asset_id)
        if status:
            stmt = stmt.where(AssetVulnerability.status == status)
        if severity:
            stmt = stmt.join(Vulnerability).where(Vulnerability.severity == severity)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = db.scalar(count_stmt) or 0

        stmt = stmt.order_by(AssetVulnerability.created_at.desc()).offset(skip).limit(limit)
        findings = list(db.scalars(stmt).all())

        return findings, total

    @classmethod
    def scan_asset_for_vulnerabilities(cls, db: Session, asset: Asset) -> VulnerabilityScanResult:
        """
        Scan asset by correlating its open ports, detected services, and OS family
        against the platform vulnerability knowledgebase.
        """
        # Collect component signatures present on the asset
        components_to_check: set[str] = set()

        # From open ports & services
        open_ports_map: dict[str, int] = {}
        if asset.open_ports:
            for p in asset.open_ports:
                service_name = str(p.get("service") or "").lower().strip()
                port_num = p.get("port")
                if service_name:
                    components_to_check.add(service_name)
                    if port_num:
                        open_ports_map[service_name] = int(port_num)

        # From OS family & version
        if asset.os_family:
            components_to_check.add(asset.os_family.lower().strip())
        if asset.asset_type:
            components_to_check.add(asset.asset_type.lower().strip())

        # Query all vulnerabilities matching these components
        all_vulns = list(db.scalars(select(Vulnerability)).all())

        detected_findings: list[AssetVulnerability] = []

        for v in all_vulns:
            comp = v.affected_component.lower().strip()
            # Match component against asset signatures
            is_match = (
                comp in components_to_check
                or any(comp in s for s in components_to_check)
                or (comp == "ssh" and 22 in open_ports_map.values())
                or (comp in ("http", "https") and (80 in open_ports_map.values() or 443 in open_ports_map.values()))
                or (comp == "postgresql" and 5432 in open_ports_map.values())
                or (comp == "rdp" and 3389 in open_ports_map.values())
            )

            if is_match:
                # Check if this finding already exists
                existing = db.scalars(
                    select(AssetVulnerability).where(
                        AssetVulnerability.asset_id == asset.id,
                        AssetVulnerability.vulnerability_id == v.id,
                    )
                ).first()

                if not existing:
                    new_finding = AssetVulnerability(
                        asset_id=asset.id,
                        vulnerability_id=v.id,
                        status=RemediationStatus.OPEN.value,
                        detected_port=open_ports_map.get(comp),
                        detected_version=asset.os_version,
                        detected_at=datetime.now(UTC),
                    )
                    db.add(new_finding)
                    db.commit()
                    db.refresh(new_finding)
                    detected_findings.append(new_finding)
                else:
                    detected_findings.append(existing)

        # Refresh findings with relationships loaded
        formatted_findings: list[AssetVulnerabilityResponse] = []
        for f in detected_findings:
            v_obj = db.get(Vulnerability, f.vulnerability_id)
            resp = AssetVulnerabilityResponse(
                id=f.id,
                asset_id=f.asset_id,
                vulnerability_id=f.vulnerability_id,
                status=f.status,
                detected_version=f.detected_version,
                detected_port=f.detected_port,
                detected_at=f.detected_at,
                resolved_at=f.resolved_at,
                remediation_notes=f.remediation_notes,
                assigned_to=f.assigned_to,
                created_at=f.created_at,
                updated_at=f.updated_at,
                asset_name=asset.name,
                vulnerability=VulnerabilityResponse.model_validate(v_obj) if v_obj else None,
            )
            formatted_findings.append(resp)

        return VulnerabilityScanResult(
            asset_id=asset.id,
            asset_name=asset.name,
            scanned_at=datetime.now(UTC),
            total_components_checked=len(components_to_check),
            matches_found=len(formatted_findings),
            findings=formatted_findings,
        )

    @classmethod
    def update_remediation(
        cls, db: Session, finding: AssetVulnerability, update_in: AssetVulnerabilityUpdate
    ) -> AssetVulnerability:
        if update_in.status is not None:
            new_status = update_in.status.value
            finding.status = new_status
            if new_status == RemediationStatus.RESOLVED.value:
                finding.resolved_at = datetime.now(UTC)
            elif new_status != RemediationStatus.RESOLVED.value:
                finding.resolved_at = None

        if update_in.remediation_notes is not None:
            finding.remediation_notes = update_in.remediation_notes
        if update_in.assigned_to is not None:
            finding.assigned_to = update_in.assigned_to

        db.commit()
        db.refresh(finding)
        return finding

    @classmethod
    def get_statistics(cls, db: Session) -> dict[str, Any]:
        total_cves = db.scalar(select(func.count(Vulnerability.id))) or 0
        total_findings = db.scalar(select(func.count(AssetVulnerability.id))) or 0

        open_findings = db.scalar(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.status == RemediationStatus.OPEN.value
            )
        ) or 0

        resolved_findings = db.scalar(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.status == RemediationStatus.RESOLVED.value
            )
        ) or 0

        critical_findings = db.scalar(
            select(func.count(AssetVulnerability.id))
            .join(Vulnerability)
            .where(
                Vulnerability.severity == VulnerabilitySeverity.CRITICAL.value,
                AssetVulnerability.status.in_([RemediationStatus.OPEN.value, RemediationStatus.IN_PROGRESS.value]),
            )
        ) or 0

        high_findings = db.scalar(
            select(func.count(AssetVulnerability.id))
            .join(Vulnerability)
            .where(
                Vulnerability.severity == VulnerabilitySeverity.HIGH.value,
                AssetVulnerability.status.in_([RemediationStatus.OPEN.value, RemediationStatus.IN_PROGRESS.value]),
            )
        ) or 0

        exploited_in_wild_count = db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.is_exploited.is_(True))
        ) or 0

        # Breakdown by severity
        crit_rows = db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity)
        ).all()
        by_severity = {row[0]: row[1] for row in crit_rows}

        # Breakdown by status
        status_rows = db.execute(
            select(AssetVulnerability.status, func.count(AssetVulnerability.id)).group_by(AssetVulnerability.status)
        ).all()
        by_remediation_status = {row[0]: row[1] for row in status_rows}

        # Top affected components
        comp_rows = db.execute(
            select(Vulnerability.affected_component, func.count(Vulnerability.id))
            .group_by(Vulnerability.affected_component)
            .order_by(func.count(Vulnerability.id).desc())
            .limit(10)
        ).all()
        top_affected_components = {row[0]: row[1] for row in comp_rows}

        return {
            "total_cves": total_cves,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "resolved_findings": resolved_findings,
            "exploited_in_wild_count": exploited_in_wild_count,
            "by_severity": by_severity,
            "by_remediation_status": by_remediation_status,
            "top_affected_components": top_affected_components,
        }
