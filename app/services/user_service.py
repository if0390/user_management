from datetime import datetime
from typing import Optional, Dict
from uuid import UUID
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import ValidationError
from app.dependencies import get_email_service
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.security import generate_verification_token, hash_password
import logging

# Set up logging
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str]) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            existing_user = await cls.get_by_email(session, validated_data["email"])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            validated_data["hashed_password"] = hash_password(validated_data.pop("password"))
            new_user = User(**validated_data)
            new_user.verification_token = generate_verification_token()

            session.add(new_user)
            await session.commit()

            email_service = get_email_service()
            await email_service.send_verification_email(new_user)

            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            validated_data = UserUpdate(**update_data).dict(exclude_unset=True)

            if "password" in validated_data:
                validated_data["hashed_password"] = hash_password(validated_data.pop("password"))

            query = (
                update(User)
                .where(User.id == user_id)
                .values(**validated_data)
                .execution_options(synchronize_session="fetch")
            )
            await cls._execute_query(session, query)

            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
                return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def upgrade_user_professional_status(
        cls, session: AsyncSession, user_id: UUID, new_role: UserRole
    ) -> bool:
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User with ID {user_id} not found.")
                return False

            if user.role == new_role:
                logger.info(f"User {user_id} already has role {new_role}.")
                return False

            user.role = new_role
            session.add(user)
            await session.commit()
            logger.info(f"User {user_id} upgraded to role {new_role}.")
            return True
        except Exception as e:
            logger.error(f"Error upgrading user {user_id} to role {new_role}: {e}")
            return False

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.info(f"User with ID {user_id} not found.")
                return False

            await session.delete(user)
            await session.commit()
            logger.info(f"User {user_id} deleted successfully.")
            return True
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return False
