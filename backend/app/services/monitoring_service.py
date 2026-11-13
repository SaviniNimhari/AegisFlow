from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.models.monitoring import (
    AlertSeverity,
    AlertStatus,
    DetectionRule,
    EventType,
    SecurityAlert,
    SecurityEvent,
)
from backend.app.schemas.monitoring import (
    DetectionRuleCreate,
    SecurityAlertUpdate,
    SecurityEventCreate,
)

# Known malicious IOC hashes for detection engine testing & signature matching
KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test string MD5
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
    "c750b73c46e01a88b8e05cb1e564d262b9a7be8e78e1c66f7773f554032d1844",  # WannaCry sample
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Suspicious zero-byte exploit
}


class MonitoringService:
    @classmethod
    def seed_default_rules(cls, db: Session) -> list[DetectionRule]:
        """Ensure standard baseline security detection rules exist in the system."""
        defaults = [
            {
                "name": "RULE-AUTH-001: Repeated Failed Login Brute Force",
                "description": "Triggers when 5 or more failed authentication events occur within 5 minutes.",
                "rule_type": "brute_force",
                "severity": AlertSeverity.HIGH.value,
                "mitre_attack_id": "T1110",
                "condition_config": {"threshold": 5, "window_seconds": 300},
            },
            {
                "name": "RULE-IOC-001: Malicious File Hash (Known Threat)",
                "description": "Triggers when an ingested event contains a known malware SHA-256 or MD5 hash.",
                "rule_type": "malicious_hash",
                "severity": AlertSeverity.CRITICAL.value,
                "mitre_attack_id": "T1204",
                "condition_config": {"ioc_hashes": list(KNOWN_MALICIOUS_HASHES)},
            },
            {
                "name": "RULE-PRIV-001: Unusual Privilege Escalation",
                "description": "Triggers upon privilege escalation attempts, su/sudo abuse, or admin creations.",
                "rule_type": "privilege_escalation",
                "severity": AlertSeverity.HIGH.value,
                "mitre_attack_id": "T1078",
                "condition_config": {"keywords": ["sudo", "setuid", "chmod +s", "su root", "net user /add", "runas"]},
            },
            {
                "name": "RULE-NET-001: Unauthorized Inbound Connection to Sensitive Port",
                "description": "Triggers on unauthorized external connections to administrative ports (22, 23, 3389).",
                "rule_type": "unauthorized_connection",
                "severity": AlertSeverity.MEDIUM.value,
                "mitre_attack_id": "T1071",
                "condition_config": {"restricted_ports": [22, 23, 3389, 445]},
            },
        ]

        rules = []
        for d in defaults:
            existing = db.scalars(select(DetectionRule).where(DetectionRule.name == d["name"])).first()
            if not existing:
                r = DetectionRule(
                    name=d["name"],
                    description=d["description"],
                    rule_type=d["rule_type"],
                    severity=d["severity"],
                    is_enabled=True,
                    condition_config=d["condition_config"],
                    mitre_attack_id=d["mitre_attack_id"],
                )
                db.add(r)
                rules.append(r)
            else:
                rules.append(existing)

        db.commit()
        return rules

    @classmethod
    def ingest_event(
        cls, db: Session, event_in: SecurityEventCreate
    ) -> tuple[SecurityEvent, list[SecurityAlert]]:
        """
        Persist incoming security log/event and run through real-time detection rules.
        """
        cls.seed_default_rules(db)

        now = datetime.now(UTC)
        event_time = event_in.timestamp or now
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)

        event = SecurityEvent(
            event_type=event_in.event_type.value,
            source=event_in.source,
            source_ip=event_in.source_ip,
            source_port=event_in.source_port,
            destination_ip=event_in.destination_ip,
            destination_port=event_in.destination_port,
            username=event_in.username,
            asset_id=event_in.asset_id,
            raw_log=event_in.raw_log,
            details=event_in.details or {},
            timestamp=event_time,
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        # Run Real-Time Rule Detection Engine
        triggered_alerts = cls._evaluate_detection_rules(db, event)
        return event, triggered_alerts

    @classmethod
    def _evaluate_detection_rules(cls, db: Session, event: SecurityEvent) -> list[SecurityAlert]:
        alerts_created: list[SecurityAlert] = []

        rules = list(db.scalars(select(DetectionRule).where(DetectionRule.is_enabled.is_(True))).all())

        for rule in rules:
            alert: SecurityAlert | None = None

            # 1. Brute Force Rule
            if rule.rule_type == "brute_force" and event.event_type == EventType.AUTH_FAILURE.value:
                cfg = rule.condition_config or {}
                threshold = cfg.get("threshold", 5)
                window_seconds = cfg.get("window_seconds", 300)

                window_start = event.timestamp - timedelta(seconds=window_seconds)

                # Query count of failed logins for same user or source IP in window
                count_stmt = select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.event_type == EventType.AUTH_FAILURE.value,
                    SecurityEvent.timestamp >= window_start,
                    or_(
                        SecurityEvent.username == event.username,
                        SecurityEvent.source_ip == event.source_ip,
                    ),
                )
                fail_count = db.scalar(count_stmt) or 0

                if fail_count >= threshold:
                    alert = SecurityAlert(
                        title=f"Brute-Force Authentication Attack ({event.username or event.source_ip})",
                        description=(
                            f"Detected {fail_count} failed login attempts within {window_seconds}s "
                            f"from IP {event.source_ip} targeting user '{event.username}'."
                        ),
                        severity=rule.severity,
                        status=AlertStatus.OPEN.value,
                        confidence_score=0.95,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        mitre_attack_id=rule.mitre_attack_id,
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        target_user=event.username,
                        asset_id=event.asset_id,
                        evidence={"fail_count": fail_count, "triggering_event_id": event.id},
                    )

            # 2. Known Malicious File Hash (IOC) Rule
            elif rule.rule_type == "malicious_hash":
                file_hash = (event.details or {}).get("file_hash", "").lower().strip()
                configured_hashes = set(rule.condition_config.get("ioc_hashes", [])) | KNOWN_MALICIOUS_HASHES

                if file_hash and file_hash in configured_hashes:
                    alert = SecurityAlert(
                        title=f"Known Malicious File Hash Detected: {file_hash[:16]}...",
                        description=f"File hash {file_hash[:16]}... matches IOC signature from {event.source}.",
                        severity=rule.severity,
                        status=AlertStatus.OPEN.value,
                        confidence_score=0.99,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        mitre_attack_id=rule.mitre_attack_id,
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        target_user=event.username,
                        asset_id=event.asset_id,
                        evidence={"matched_hash": file_hash, "triggering_event_id": event.id},
                    )

            # 3. Privilege Escalation Rule
            elif rule.rule_type == "privilege_escalation":
                raw = (event.raw_log or "").lower()
                cmd = str((event.details or {}).get("command", "")).lower()
                keywords = rule.condition_config.get("keywords", ["sudo", "setuid", "chmod +s", "su root"])

                is_priv_type = event.event_type == EventType.PRIVILEGE_ESCALATION.value
                matches_cmd = any(k in cmd for k in keywords) if cmd else False
                matches_raw = any(k in raw for k in keywords) if raw else False

                is_match = is_priv_type or (
                    event.event_type not in (EventType.AUTH_SUCCESS.value, EventType.AUTH_FAILURE.value)
                    and (matches_cmd or matches_raw)
                )

                if is_match:
                    alert = SecurityAlert(
                        title=f"Privilege Escalation Detected ({event.username or 'unknown'})",
                        description=f"Administrative escalation command/event triggered by {event.username}.",
                        severity=rule.severity,
                        status=AlertStatus.OPEN.value,
                        confidence_score=0.90,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        mitre_attack_id=rule.mitre_attack_id,
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        target_user=event.username,
                        asset_id=event.asset_id,
                        evidence={"command": cmd or raw, "triggering_event_id": event.id},
                    )

            # 4. Unauthorized Network Connection Rule
            elif rule.rule_type == "unauthorized_connection" and event.event_type == EventType.NETWORK_CONNECTION.value:
                restricted_ports = rule.condition_config.get("restricted_ports", [22, 23, 3389])
                dest_port = event.destination_port

                if dest_port and dest_port in restricted_ports:
                    alert = SecurityAlert(
                        title=f"Inbound Connection to Restricted Port {dest_port}",
                        description=f"Inbound connection from IP {event.source_ip} to sensitive port {dest_port}.",
                        severity=rule.severity,
                        status=AlertStatus.OPEN.value,
                        confidence_score=0.80,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        mitre_attack_id=rule.mitre_attack_id,
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        target_user=event.username,
                        asset_id=event.asset_id,
                        evidence={"port": dest_port, "triggering_event_id": event.id},
                    )

            if alert:
                db.add(alert)
                db.commit()
                db.refresh(alert)
                alerts_created.append(alert)

        return alerts_created

    @classmethod
    def list_events(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 50,
        event_type: str | None = None,
        source_ip: str | None = None,
        username: str | None = None,
    ) -> tuple[list[SecurityEvent], int]:
        stmt = select(SecurityEvent)

        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if source_ip:
            stmt = stmt.where(SecurityEvent.source_ip == source_ip)
        if username:
            stmt = stmt.where(SecurityEvent.username == username)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = db.scalar(count_stmt) or 0

        stmt = stmt.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit)
        items = list(db.scalars(stmt).all())
        return items, total

    @classmethod
    def list_alerts(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 50,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[SecurityAlert], int]:
        stmt = select(SecurityAlert)

        if severity:
            stmt = stmt.where(SecurityAlert.severity == severity)
        if status:
            stmt = stmt.where(SecurityAlert.status == status)
        if search:
            term = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(SecurityAlert.title).like(term),
                    func.lower(SecurityAlert.description).like(term),
                    func.lower(SecurityAlert.source_ip).like(term),
                    func.lower(SecurityAlert.target_user).like(term),
                )
            )

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = db.scalar(count_stmt) or 0

        stmt = stmt.order_by(SecurityAlert.created_at.desc()).offset(skip).limit(limit)
        items = list(db.scalars(stmt).all())
        return items, total

    @classmethod
    def get_alert_by_id(cls, db: Session, alert_id: str) -> SecurityAlert | None:
        return db.get(SecurityAlert, alert_id)

    @classmethod
    def update_alert(
        cls, db: Session, alert: SecurityAlert, update_in: SecurityAlertUpdate
    ) -> SecurityAlert:
        if update_in.status is not None:
            new_status = update_in.status.value
            alert.status = new_status
            if new_status in (AlertStatus.RESOLVED.value, AlertStatus.DISMISSED.value):
                alert.resolved_at = datetime.now(UTC)
            elif new_status != AlertStatus.RESOLVED.value:
                alert.resolved_at = None

        if update_in.assigned_to is not None:
            alert.assigned_to = update_in.assigned_to
        if update_in.resolution_notes is not None:
            alert.resolution_notes = update_in.resolution_notes

        db.commit()
        db.refresh(alert)
        return alert

    @classmethod
    def list_rules(cls, db: Session) -> list[DetectionRule]:
        cls.seed_default_rules(db)
        return list(db.scalars(select(DetectionRule).order_by(DetectionRule.created_at.asc())).all())

    @classmethod
    def create_rule(cls, db: Session, rule_in: DetectionRuleCreate) -> DetectionRule:
        rule = DetectionRule(
            name=rule_in.name.strip(),
            description=rule_in.description,
            rule_type=rule_in.rule_type.strip(),
            severity=rule_in.severity.value,
            is_enabled=rule_in.is_enabled,
            condition_config=rule_in.condition_config,
            mitre_attack_id=rule_in.mitre_attack_id,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    @classmethod
    def get_statistics(cls, db: Session) -> dict[str, Any]:
        total_alerts = db.scalar(select(func.count(SecurityAlert.id))) or 0
        open_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.status == AlertStatus.OPEN.value)
        ) or 0
        investigating_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.status == AlertStatus.INVESTIGATING.value)
        ) or 0
        resolved_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.status == AlertStatus.RESOLVED.value)
        ) or 0

        critical_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(
                SecurityAlert.severity == AlertSeverity.CRITICAL.value,
                SecurityAlert.status.in_([AlertStatus.OPEN.value, AlertStatus.INVESTIGATING.value]),
            )
        ) or 0

        high_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(
                SecurityAlert.severity == AlertSeverity.HIGH.value,
                SecurityAlert.status.in_([AlertStatus.OPEN.value, AlertStatus.INVESTIGATING.value]),
            )
        ) or 0

        # Breakdown by severity
        sev_rows = db.execute(
            select(SecurityAlert.severity, func.count(SecurityAlert.id)).group_by(SecurityAlert.severity)
        ).all()
        by_severity = {row[0]: row[1] for row in sev_rows}

        # Breakdown by status
        st_rows = db.execute(
            select(SecurityAlert.status, func.count(SecurityAlert.id)).group_by(SecurityAlert.status)
        ).all()
        by_status = {row[0]: row[1] for row in st_rows}

        # Top MITRE tactics
        mitre_rows = db.execute(
            select(SecurityAlert.mitre_attack_id, func.count(SecurityAlert.id))
            .where(SecurityAlert.mitre_attack_id.isnot(None))
            .group_by(SecurityAlert.mitre_attack_id)
            .order_by(func.count(SecurityAlert.id).desc())
            .limit(10)
        ).all()
        top_mitre_tactics = {row[0]: row[1] for row in mitre_rows}

        return {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "investigating_alerts": investigating_alerts,
            "resolved_alerts": resolved_alerts,
            "by_severity": by_severity,
            "by_status": by_status,
            "top_mitre_tactics": top_mitre_tactics,
        }
