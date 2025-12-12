# >>> INSERT: MODELS FILE (BEGIN)
"""
QubitGrid™ Database Models (models.py)
--------------------------------------
Purpose:
- Define all persistent data structures using SQLAlchemy ORM.
- Start with Customer model for Stripe + API key integration.
- Future-ready for Analytics, Scan Logs, and PQC modules.
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

# Path for SQLite database file (persistent on Render or local)
DB_PATH = os.getenv("DB_PATH", "analytics.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create SQLAlchemy engine (connects ORM to SQLite)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Base class for all ORM models
Base = declarative_base()

# Session factory — used to interact with the DB
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ============================================================
# CUSTOMER MODEL
# ============================================================

class Customer(Base):
    """
    Represents a paying or free-tier QubitGrid user.
    Links to Stripe via stripe_customer_id.
    """

    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    stripe_customer_id = Column(String(64), unique=True, nullable=True)
    email = Column(String(255), unique=True, nullable=False)
    api_key_hash = Column(String(128), nullable=True)
    tier = Column(String(50), default="free")
    status = Column(String(50), default="inactive")
    grace_period_start = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Customer(email={self.email}, tier={self.tier}, status={self.status})>"


# ============================================================
# FUTURE TABLES (PHASE 2+)
# ============================================================
# class ScanLog(Base):
#     """Tracks individual scan events and risk scores."""
#     __tablename__ = "scan_logs"
#     id = Column(Integer, primary_key=True)
#     ip = Column(String(45))
#     tier = Column(String(50))
#     result = Column(Text)
#     created_at = Column(DateTime, default=datetime.utcnow)

# ==============================================================
#  MODEL: APIKey
#  Purpose: Store hashed API keys linked to paid Stripe customers.
#  This table connects authentication (API key access) with monetization tiers.
# ==============================================================

from hashlib import sha256
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime

class APIKey(Base):
    """
    Represents a unique API key issued to a customer after payment.
    - The key is stored as a SHA-256 hash (never in plain text).
    - Each key is linked to a customer email and plan tier.
    - `active` allows soft revocation without deleting the record.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, index=True, nullable=False)        # Customer's Stripe email
    key_hash = Column(String, unique=True, nullable=False)          # Hashed version of the API key
    plan = Column(String, nullable=False, default="free")           # e.g. free, indie, pro, lifetime
    active = Column(Boolean, default=True)                          # False if revoked or expired
    created_at = Column(DateTime, default=datetime.utcnow)

    def verify_key(self, api_key: str) -> bool:
        """
        Compare an incoming plaintext API key to this record’s hash.
        Returns True if they match, otherwise False.
        """
        return self.key_hash == sha256(api_key.encode()).hexdigest()

    @staticmethod
    def hash_key(plain_key: str) -> str:
        """
        Static helper to hash any given API key string.
        This is used during insertion and verification.
        """
        return sha256(plain_key.encode()).hexdigest()

# ==============================================================
#  END OF APIKey MODEL
# ==============================================================

# ============================================================
# DATABASE CREATION UTILITY
# ============================================================

def init_db():
    """
    Creates all database tables if they don't already exist.
    Call this once at app startup.
    """
    Base.metadata.create_all(bind=engine)
    print("[DB] Initialized all tables successfully.")


# >>> INSERT: MODELS FILE (END)
