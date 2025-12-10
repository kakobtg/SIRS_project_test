from sqlalchemy import Column, Integer, String, Text

from .db import Base


class TransactionRecord(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    tx_id = Column(String, unique=True, index=True)
    ciphertext = Column(Text, nullable=False)
    tag = Column(Text, nullable=False)
    nonce = Column(Text, nullable=False)
    ek_map = Column(Text, nullable=False)  # JSON string mapping company -> wrapped key
    hash_T = Column(Text, nullable=False)
    sig_seller = Column(Text, nullable=False)
    sig_buyer = Column(Text, nullable=True)
    meta = Column(Text, nullable=True)
    created_at = Column(String, nullable=True)
    layers = Column(Text, nullable=True)  # JSON string for selective disclosure layers


class ShareRecord(Base):
    __tablename__ = "shares"

    id = Column(String, primary_key=True)
    tx_id = Column(String, index=True, nullable=False)
    from_company = Column(String, nullable=False)
    to_company = Column(String, nullable=False)
    ek_to = Column(Text, nullable=False)
    timestamp = Column(String, nullable=False)
    sig_share = Column(Text, nullable=False)


class Company(Base):
    __tablename__ = "companies"

    name = Column(String, primary_key=True)
    signing_public = Column(Text, nullable=False)
    encryption_public = Column(Text, nullable=False)
