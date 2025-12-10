from sqlalchemy import Column, String, Text

from .db import Base


class DisclosureRecord(Base):
    __tablename__ = "disclosures"

    id = Column(String, primary_key=True)
    tx_id = Column(String, index=True, nullable=False)
    section = Column(String, nullable=False)
    from_company = Column(String, nullable=False)
    to_company = Column(String, nullable=False)
    ek_to = Column(Text, nullable=False)
    timestamp = Column(String, nullable=False)
    layer_hash = Column(String, nullable=False)
    sig_share = Column(Text, nullable=False)
