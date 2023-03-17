from db import DB
from bcrypt import hashpw, gensalt, checkpw
from user import User

from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
    """The hash_password function"""
    password_bytes = password.encode("utf-8")
    hashed_password = hashpw(password_bytes, gensalt())
    return hashed_password


def _generate_uuid() -> str:
    """The Generate UUID function"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """The register_user method"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User <{}> already exists".format(email))
        except NoResultFound as e:
            password = _hash_password(password)
            return self._db.add_user(email, password)

    def valid_login(self, email: str, password: str) -> bool:
        """The valid_login function"""
        try:
            user = self._db.find_user_by(email=email)
            password_bytes = password.encode("utf-8")
            hashed_password_bytes = user.hashed_password.encode("utf-8")
            return checkpw(password_bytes, hashed_password_bytes)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """The Create Session function"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """The Get User from Session Id method"""
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """The Destroy Session method"""
        try:
            self._db.update_user(user_id, session_id=None)
            return None
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """The GET Reset Password Token method"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """The update password method"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password).decode("utf-8")
            self._db.update_user(
                user.id, hashed_password=hashed_password, reset_token=None
            )
            return None
        except NoResultFound:
            raise ValueError
