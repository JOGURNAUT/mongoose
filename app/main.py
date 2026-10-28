import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app.classify import classify
from app.config import MOCK_MODE
from app.enrichment import check_file_hash, check_ip
from app.models import Alert, AlertIn, AlertOut, AlertType
from app.playbook import build_playbook
from app.storage import get_alert, init_db, list_alerts, save_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mongoose")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if MOCK_MODE:
        logger.warning(
            "Starting in MOCK MODE — no ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY set. "
            "Enrichment results are deterministic fakes. Set both in .env for live lookups."
        )
    yield


app = FastAPI(
    title="Mongoose",
    description="SOAR-lite: ingest a security alert, enrich it, classify it, and suggest a response. Fails closed.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {"status": "ok", "mock_mode": MOCK_MODE}


@app.post("/alerts", response_model=AlertOut)
async def ingest_alert(alert_in: AlertIn):
    enrichment = None

    if alert_in.type == AlertType.ip_traffic:
        if not alert_in.source_ip:
            raise HTTPException(status_code=422, detail="source_ip is required for type=ip_traffic")
        enrichment = await check_ip(alert_in.source_ip)
    elif alert_in.type == AlertType.file_hash:
        if not alert_in.file_hash:
            raise HTTPException(status_code=422, detail="file_hash is required for type=file_hash")
        enrichment = await check_file_hash(alert_in.file_hash)
    elif alert_in.type == AlertType.login:
        if alert_in.failed_attempts_last_5min is None and not alert_in.country:
            raise HTTPException(
                status_code=422,
                detail="login alerts need at least failed_attempts_last_5min or country context",
            )

    classification = classify(alert_in, enrichment)
    playbook = build_playbook(classification.severity)

    record = Alert(
        type=alert_in.type.value,
        source_ip=alert_in.source_ip,
        file_hash=alert_in.file_hash,
        user=alert_in.user,
        enrichment=enrichment.model_dump() if enrichment else {},
        severity=classification.severity.value,
        reasons=classification.reasons,
        actions=playbook.actions,
        raw_event=alert_in.raw_event,
    )
    saved = save_alert(record)

    logger.info(
        "alert id=%s type=%s severity=%s reasons=%s",
        saved.id, saved.type, saved.severity, saved.reasons,
    )

    return AlertOut(**saved.model_dump())


@app.get("/alerts", response_model=list[AlertOut])
async def get_alerts(limit: int = 50):
    return [AlertOut(**a.model_dump()) for a in list_alerts(limit=limit)]


@app.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_one_alert(alert_id: int):
    record = get_alert(alert_id)
    if not record:
        raise HTTPException(status_code=404, detail="alert not found")
    return AlertOut(**record.model_dump())
