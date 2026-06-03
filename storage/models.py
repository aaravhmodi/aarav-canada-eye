from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, DateTime, JSON, Boolean, Text, ForeignKey, create_engine
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


def get_engine():
    return create_engine(cfg["storage"]["database_url"])


def get_session():
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()


def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
