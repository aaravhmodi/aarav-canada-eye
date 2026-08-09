from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, JSON, Boolean, Text, ForeignKey, create_engine
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker
from config import cfg


class Base(DeclarativeBase):
    pass


class RawDocument(Base):
    __tablename__ = "raw_documents"

    id = Column(Integer, primary_key=True)
    source_url = Column(String(2048))
    source_type = Column(String(64))   # tor, paste, rss, ca_gov
    raw_text = Column(Text)
    collected_at = Column(DateTime, default=datetime.utcnow)
    processed = Column(Boolean, default=False)
    canada_relevant = Column(Boolean, default=False)
    iocs = relationship("IOC", back_populates="document")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("raw_documents.id"))
    ioc_type = Column(String(32))   # ip, domain, hash, email, cve
    value = Column(String(512))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    hit_count = Column(Integer, default=1)
    enrichment = Column(JSON, default=dict)
    is_canadian = Column(Boolean, default=False)
    actor_id = Column(Integer, ForeignKey("actor_profiles.id"), nullable=True)
    document = relationship("RawDocument", back_populates="iocs")
    actor = relationship("ActorProfile", back_populates="iocs")


class ActorProfile(Base):
    __tablename__ = "actor_profiles"

    id = Column(Integer, primary_key=True)
    actor_label = Column(String(128), unique=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    incident_count = Column(Integer, default=0)
    ips = Column(JSON, default=list)
    domains = Column(JSON, default=list)
    hashes = Column(JSON, default=list)
    orgs_targeted = Column(JSON, default=list)
    ttps = Column(JSON, default=list)           # MITRE ATT&CK IDs
    misp_event_uuid = Column(String(64), nullable=True)
    iocs = relationship("IOC", back_populates="actor")


def save_iocs(session, document: "RawDocument", iocs: dict) -> int:
    """Upsert extracted IOCs into the `iocs` table against `document`. Previously, extracted
    IOCs were only ever held in-memory for clustering and then discarded — nothing wrote to
    this table, so it was permanently empty. Dedupes by (ioc_type, value): a repeat sighting
    bumps hit_count/last_seen rather than inserting a duplicate row."""
    type_map = {
        "ips": "ip", "domains": "domain", "hashes": "hash",
        "emails": "email", "cves": "cve",
    }
    saved = 0
    for field, ioc_type in type_map.items():
        for value in iocs.get(field, []):
            existing = (
                session.query(IOC)
                .filter_by(document_id=document.id, ioc_type=ioc_type, value=value)
                .first()
            )
            if existing:
                existing.hit_count += 1
                existing.last_seen = datetime.utcnow()
                continue
            session.add(IOC(
                document_id=document.id,
                ioc_type=ioc_type,
                value=value,
                is_canadian=document.canada_relevant,
            ))
            saved += 1
    return saved


# ── Counterfeit Currency Pattern Tracking ────────────────────────────────────

class CounterfeitStat(Base):
    """A single (year, province, denomination) statistic row scraped from the RCMP Forensic
    Science & Identification Services counterfeit currency tables."""
    __tablename__ = "counterfeit_stats"

    id = Column(Integer, primary_key=True)
    year = Column(Integer, index=True)
    province = Column(String(64), nullable=True)   # null for national/denomination-only rows
    denomination = Column(String(16), nullable=True)  # "$5".."$100", null for province-only rows
    passed = Column(Integer, default=0)             # detected in circulation
    seized = Column(Integer, default=0)              # confiscated before circulation
    value_cad = Column(Float, nullable=True)
    production_method = Column(String(64), nullable=True)  # offset, toner, inkjet, other
    source_url = Column(String(2048))
    collected_at = Column(DateTime, default=datetime.utcnow)


class CourtCase(Base):
    """Canadian court case referencing counterfeit currency offences (Criminal Code s.448-462),
    sourced from CanLII."""
    __tablename__ = "court_cases"

    id = Column(Integer, primary_key=True)
    canlii_id = Column(String(128), unique=True)
    case_name = Column(String(512))
    citation = Column(String(128), nullable=True)
    court = Column(String(128), nullable=True)
    jurisdiction = Column(String(16), nullable=True)
    decision_date = Column(DateTime, nullable=True)
    url = Column(String(2048))
    summary = Column(Text, nullable=True)
    collected_at = Column(DateTime, default=datetime.utcnow)


class BanknoteScan(Base):
    """CNN inference result for a single banknote image (demo/synthetic data unless a real
    labeled dataset has been supplied — see processing/banknote_cnn.py)."""
    __tablename__ = "banknote_scans"

    id = Column(Integer, primary_key=True)
    image_path = Column(String(2048))
    denomination = Column(String(16), nullable=True)
    predicted_label = Column(String(16))   # "genuine" | "counterfeit"
    confidence = Column(Float)
    security_features = Column(JSON, default=dict)   # {feature_name: presence_score}
    model_version = Column(String(64))
    is_synthetic = Column(Boolean, default=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)


def get_engine():
    return create_engine(cfg["storage"]["database_url"])


def get_session():
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()


def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
