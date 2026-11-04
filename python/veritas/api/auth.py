"""Authentication (OIDC or local) and role-based access control.

* **OIDC** (production): bearer JWTs from the configured issuer are verified against its JWKS
  (signature, ``iss``, ``aud``, ``exp``, ``nbf``). Users are provisioned on first login; global
  admin comes from the ``veritas_admin`` group/role claim.
* **Local** (single-workstation and tests): argon2id password hashes and EdDSA-signed tokens issued
  by this API with a per-instance key.

Every case-scoped route depends on :func:`case_access`, which loads the membership and enforces a
minimum role. Handlers never perform their own membership checks. THREAT:T4.3
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import ROLE_RANK, Membership, User

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
_bearer = HTTPBearer(auto_error=False)


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def check_password(stored: str | None, pw: str) -> bool:
    if not stored:
        _ph.hash("timing-equalizer")
        return False
    try:
        return _ph.verify(stored, pw)
    except (VerifyMismatchError, Exception):
        return False


@dataclass(slots=True)
class Principal:
    user_id: str
    display_name: str
    is_admin: bool
    can_unmask_pii: bool


@dataclass(slots=True)
class CaseAccess:
    principal: Principal
    case_id: str
    role: str

    def at_least(self, role: str) -> bool:
        return self.principal.is_admin or ROLE_RANK[self.role] >= ROLE_RANK[role]


class TokenService:
    def __init__(self, ttl_s: int, private_key_pem: bytes | None = None, oidc_issuer: str | None = None, oidc_audience: str | None = None, jwks_url: str | None = None):
        self.ttl_s = ttl_s
        key = serialization.load_pem_private_key(private_key_pem, password=None) if private_key_pem else Ed25519PrivateKey.generate()
        self._priv = key
        self._pub = key.public_key()
        self.oidc_issuer = oidc_issuer
        self.oidc_audience = oidc_audience
        self._jwks = jwt.PyJWKClient(jwks_url or f"{oidc_issuer.rstrip('/')}/.well-known/jwks.json", cache_keys=True) if oidc_issuer else None

    def private_pem(self) -> bytes:
        return self._priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def issue(self, user_id: str) -> str:
        now = int(time.time())
        return jwt.encode({"sub": user_id, "iss": "veritas-local", "aud": "veritas", "iat": now, "nbf": now, "exp": now + self.ttl_s}, self._priv, algorithm="EdDSA")

    def verify(self, token: str) -> dict:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") == "EdDSA":
                return jwt.decode(token, self._pub, algorithms=["EdDSA"], audience="veritas", issuer="veritas-local", options={"require": ["exp", "sub", "iat"]})
            if self._jwks is None:
                raise jwt.InvalidTokenError("OIDC is not configured")
            key = self._jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(token, key, algorithms=["RS256", "ES256", "PS256"], audience=self.oidc_audience, issuer=self.oidc_issuer, options={"require": ["exp", "sub", "iat"]})
        except jwt.PyJWTError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token") from exc


def get_principal_factory(token_service_getter: Callable[[], TokenService], session_getter: Callable[[], Session]):
    def get_principal(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
        token = creds.credentials if creds else request.query_params.get("access_token") if request.scope.get("type") == "websocket" else None
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required", headers={"WWW-Authenticate": "Bearer"})
        claims = token_service_getter().verify(token)
        with session_getter() as s:
            user = s.get(User, claims["sub"])
            if user is None and claims.get("iss") != "veritas-local":
                groups = set(claims.get("groups", []) or []) | set(claims.get("roles", []) or [])
                user = User(id=claims["sub"], display_name=claims.get("name") or claims.get("preferred_username") or claims["sub"], email=claims.get("email"), is_admin="veritas_admin" in groups)
                s.add(user)
                s.commit()
            if user is None or not user.active:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled or unknown")
            p = Principal(user.id, user.display_name, user.is_admin, user.can_unmask_pii or user.is_admin)
        request.state.principal = p
        return p

    return get_principal


def case_access_factory(get_principal, session_getter: Callable[[], Session]):
    def require(min_role: str = "viewer"):
        def dep(case_id: str, principal: Principal = Depends(get_principal)) -> CaseAccess:
            with session_getter() as s:
                m = s.query(Membership).filter_by(case_id=case_id, user_id=principal.user_id).one_or_none()
            if principal.is_admin:
                return CaseAccess(principal, case_id, m.role if m else "lead")
            # 404 rather than 403 so case ids cannot be probed.
            if m is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
            if ROLE_RANK[m.role] < ROLE_RANK[min_role]:
                raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role {min_role}")
            return CaseAccess(principal, case_id, m.role)

        return dep

    return require
