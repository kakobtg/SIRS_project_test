import json
from contextlib import asynccontextmanager
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models
from .db import get_db, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database schema at startup.
    init_db()
    yield


app = FastAPI(title="ChainOfProduct API", version="0.1", lifespan=lifespan)


class CompanyIn(BaseModel):
    name: str
    signing_public: str
    encryption_public: str


class TransactionIn(BaseModel):
    tx_id: str
    ciphertext: str
    tag: str
    nonce: str
    ek_map: dict
    hash_T: str
    sig_seller: str
    sig_buyer: str | None = None
    meta: dict | None = None
    created_at: str | None = None


class BuyerSignIn(BaseModel):
    sig_buyer: str


class ShareIn(BaseModel):
    id: str
    tx_id: str
    from_company: str
    to_company: str
    ek_to: str
    timestamp: str
    sig_share: str


class CompanyOut(BaseModel):
    name: str
    signing_public: str
    encryption_public: str


def _tx_to_dict(tx: models.TransactionRecord) -> dict:
    return {
        "tx_id": tx.tx_id,
        "ciphertext": tx.ciphertext,
        "tag": tx.tag,
        "nonce": tx.nonce,
        "ek_map": json.loads(tx.ek_map),
        "hash_T": tx.hash_T,
        "sig_seller": tx.sig_seller,
        "sig_buyer": tx.sig_buyer,
        "meta": json.loads(tx.meta) if tx.meta else None,
        "created_at": tx.created_at,
    }


def _share_to_dict(share: models.ShareRecord) -> dict:
    return {
        "id": share.id,
        "tx_id": share.tx_id,
        "from_company": share.from_company,
        "to_company": share.to_company,
        "ek_to": share.ek_to,
        "timestamp": share.timestamp,
        "sig_share": share.sig_share,
    }


@app.post("/register_company")
def register_company(payload: CompanyIn, db: Session = Depends(get_db)):
    existing = db.query(models.Company).filter(models.Company.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Company already registered")
    company = models.Company(
        name=payload.name,
        signing_public=payload.signing_public,
        encryption_public=payload.encryption_public,
    )
    db.add(company)
    db.commit()
    return {"status": "registered", "company": payload.name}


@app.get("/companies/{name}", response_model=CompanyOut)
def get_company(name: str, db: Session = Depends(get_db)):
    company = db.query(models.Company).filter(models.Company.name == name).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return CompanyOut(
        name=company.name,
        signing_public=company.signing_public,
        encryption_public=company.encryption_public,
    )


@app.post("/transactions")
def create_transaction(payload: TransactionIn, db: Session = Depends(get_db)):
    existing = db.query(models.TransactionRecord).filter(models.TransactionRecord.tx_id == payload.tx_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Transaction already exists")
    tx = models.TransactionRecord(
        tx_id=payload.tx_id,
        ciphertext=payload.ciphertext,
        tag=payload.tag,
        nonce=payload.nonce,
        ek_map=json.dumps(payload.ek_map),
        hash_T=payload.hash_T,
        sig_seller=payload.sig_seller,
        sig_buyer=payload.sig_buyer,
        meta=json.dumps(payload.meta) if payload.meta else None,
        created_at=payload.created_at,
    )
    db.add(tx)
    db.commit()
    return {"status": "stored", "tx_id": payload.tx_id}


@app.get("/transactions/{tx_id}")
def get_transaction(tx_id: str, db: Session = Depends(get_db)):
    tx = db.query(models.TransactionRecord).filter(models.TransactionRecord.tx_id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return _tx_to_dict(tx)


@app.post("/transactions/{tx_id}/buyer_sign")
def add_buyer_signature(tx_id: str, payload: BuyerSignIn, db: Session = Depends(get_db)):
    tx = db.query(models.TransactionRecord).filter(models.TransactionRecord.tx_id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    tx.sig_buyer = payload.sig_buyer
    db.add(tx)
    db.commit()
    return {"status": "buyer_signed", "tx_id": tx_id}


@app.post("/transactions/{tx_id}/share")
def add_share_record(tx_id: str, payload: ShareIn, db: Session = Depends(get_db)):
    tx = db.query(models.TransactionRecord).filter(models.TransactionRecord.tx_id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    share = models.ShareRecord(
        id=payload.id,
        tx_id=payload.tx_id,
        from_company=payload.from_company,
        to_company=payload.to_company,
        ek_to=payload.ek_to,
        timestamp=payload.timestamp,
        sig_share=payload.sig_share,
    )
    db.add(share)
    db.commit()
    return {"status": "share_stored", "id": payload.id}


@app.get("/transactions/{tx_id}/shares", response_model=List[dict])
def list_shares(tx_id: str, db: Session = Depends(get_db)):
    shares = db.query(models.ShareRecord).filter(models.ShareRecord.tx_id == tx_id).all()
    return [_share_to_dict(s) for s in shares]
