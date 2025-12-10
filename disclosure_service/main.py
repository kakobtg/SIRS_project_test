from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models
from .db import get_db, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Selective Disclosure Tracker", version="0.1", lifespan=lifespan)


class DisclosureIn(BaseModel):
    id: str
    tx_id: str
    section: str
    from_company: str
    to_company: str
    ek_to: str
    timestamp: str
    layer_hash: str
    sig_share: str


class DisclosureOut(DisclosureIn):
    pass


def _record_to_dict(rec: models.DisclosureRecord) -> dict:
    return {
        "id": rec.id,
        "tx_id": rec.tx_id,
        "section": rec.section,
        "from_company": rec.from_company,
        "to_company": rec.to_company,
        "ek_to": rec.ek_to,
        "timestamp": rec.timestamp,
        "layer_hash": rec.layer_hash,
        "sig_share": rec.sig_share,
    }


@app.post("/disclosures")
def add_disclosure(payload: DisclosureIn, db: Session = Depends(get_db)):
    existing = db.query(models.DisclosureRecord).filter(models.DisclosureRecord.id == payload.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Disclosure already exists")
    rec = models.DisclosureRecord(
        id=payload.id,
        tx_id=payload.tx_id,
        section=payload.section,
        from_company=payload.from_company,
        to_company=payload.to_company,
        ek_to=payload.ek_to,
        timestamp=payload.timestamp,
        layer_hash=payload.layer_hash,
        sig_share=payload.sig_share,
    )
    db.add(rec)
    db.commit()
    return {"status": "recorded", "id": payload.id}


@app.get("/disclosures/{tx_id}", response_model=List[DisclosureOut])
def list_disclosures(
    tx_id: str,
    section: Optional[str] = Query(default=None, description="Filter by section name"),
    db: Session = Depends(get_db),
):
    query = db.query(models.DisclosureRecord).filter(models.DisclosureRecord.tx_id == tx_id)
    if section:
        query = query.filter(models.DisclosureRecord.section == section)
    recs = query.all()
    return [_record_to_dict(r) for r in recs]


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}
