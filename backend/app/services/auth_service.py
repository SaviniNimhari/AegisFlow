from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.core.security import get_password_hash, verify_password
from backend.app.models.user import User, UserRole
from backend.app.schemas.user import UserCreate

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


class AuthService:
    @staticmethod
    def get_by_id(db: Session, user_id: str) -> User | None:
        return db.get(User, user_id)

    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        stmt = select(User).where(User.email == email.lower())
        return db.scalars(stmt).first()

    @staticmethod
    def get_by_username(db: Session, username: str) -> User | None:
        stmt = select(User).where(User.username == username.lower())
        return db.scalars(stmt).first()

    @classmethod
    def create_user(cls, db: Session, user_in: UserCreate) -> User:
        """Register a new user with secure password hashing."""
        role_val = user_in.role.value if isinstance(user_in.role, UserRole) else (user_in.role or UserRole.VIEWER.value)
        user = User(
            email=user_in.email.lower(),
            username=user_in.username.lower(),
            hashed_password=get_password_hash(user_in.password),
            full_name=user_in.full_name,
            role=role_val,
            is_active=True,
            is_verified=False,
            failed_login_attempts=0,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @classmethod
    def authenticate_user(
        cls, db: Session, username_or_email: str, password: str
    ) -> tuple[User | None, str | None]:
        """
        Authenticate user with account lockout defense.
        Returns: (user, error_message)
        """
        identifier = username_or_email.lower().strip()
        stmt = select(User).where(
            or_(User.email == identifier, User.username == identifier)
        )
        user = db.scalars(stmt).first()

        if not user:
            return None, "Invalid username or password"

        now = datetime.now(UTC)

        # Check account lockout
        if user.locked_until:
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=UTC)
            if locked_until > now:
                minutes_left = int((locked_until - now).total_seconds() / 60) + 1
                msg = f"Account is temporarily locked due to failed attempts. Try again in {minutes_left} minutes."
                return None, msg

        # Verify password
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db.commit()
            return None, "Invalid username or password"

        # Check if active
        if not user.is_active:
            return None, "Account is disabled. Contact your security administrator."

        # Successful authentication: reset failed counters
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        db.commit()
        db.refresh(user)

        return user, None
