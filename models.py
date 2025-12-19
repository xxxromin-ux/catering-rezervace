from __future__ import annotations

from datetime import datetime
import os
import base64
import hashlib
import hmac

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Resource(db.Model):
    __tablename__ = "resources"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    kind = db.Column(db.String(50), nullable=False, default="team")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    color = db.Column(db.String(20), nullable=False, default="#0b57d0")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    role = db.Column(db.String(20), nullable=False, default="reader")  # admin/reader

    # profil brigádníka
    email = db.Column(db.String(240), nullable=True)
    full_name = db.Column(db.String(240), nullable=True)
    phone = db.Column(db.String(80), nullable=True)

    salt_b64 = db.Column(db.String(64), nullable=False)
    hash_b64 = db.Column(db.String(128), nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @staticmethod
    def _pbkdf2(password: str, salt: bytes, iterations: int = 120_000) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

    @classmethod
    def create(cls, username: str, password: str, role: str = "reader") -> "User":
        salt = os.urandom(16)
        digest = cls._pbkdf2(password, salt)
        return cls(
            username=username,
            role=role,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            hash_b64=base64.b64encode(digest).decode("ascii"),
        )

    def verify(self, password: str) -> bool:
        salt = base64.b64decode(self.salt_b64.encode("ascii"))
        expected = base64.b64decode(self.hash_b64.encode("ascii"))
        got = self._pbkdf2(password, salt)
        return hmac.compare_digest(expected, got)


class Reservation(db.Model):
    __tablename__ = "reservations"

    id = db.Column(db.Integer, primary_key=True)

    resource_id = db.Column(db.Integer, db.ForeignKey("resources.id"), nullable=False)
    resource = db.relationship("Resource")

    title = db.Column(db.String(240), nullable=False)

    client = db.Column(db.String(240), nullable=True)
    contact = db.Column(db.String(240), nullable=True)
    location = db.Column(db.String(240), nullable=True)

    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)

    guests = db.Column(db.Integer, nullable=True)
    note = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(40), nullable=False, default="confirmed")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    signups = db.relationship("ReservationSignup", back_populates="reservation", cascade="all, delete-orphan")

    def to_event(self):
        color = self.resource.color
        if self.status == "cancelled":
            color = "#999999"
        elif self.status == "tentative":
            color = "#f0b429"

        return {
            "id": self.id,
            "title": f"{self.resource.name}: {self.title}",
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "backgroundColor": color,
            "borderColor": color,
        }


class ReservationSignup(db.Model):
    __tablename__ = "reservation_signups"

    id = db.Column(db.Integer, primary_key=True)
    reservation_id = db.Column(db.Integer, db.ForeignKey("reservations.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    minutes = db.Column(db.Integer, nullable=False, default=0)
    note = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    reservation = db.relationship("Reservation", back_populates="signups")
    user = db.relationship("User")

    __table_args__ = (
        db.UniqueConstraint("reservation_id", "user_id", name="uq_signup_reservation_user"),
    )
