"""
This Python file is part of a FastAPI application, demonstrating user management functionalities including creating, reading,
updating, and deleting (CRUD) user information. It uses OAuth2 with Password Flow for security, ensuring that only authenticated
users can perform certain operations. Additionally, the file showcases the integration of FastAPI with SQLAlchemy for asynchronous
database operations, enhancing performance by non-blocking database calls.

The implementation emphasizes RESTful API principles, with endpoints for each CRUD operation and the use of HTTP status codes
and exceptions to communicate the outcome of operations. It introduces the concept of HATEOAS (Hypermedia as the Engine of
Application State) by including navigational links in API responses, allowing clients to discover other related operations dynamically.

OAuth2PasswordBearer is employed to extract the token from the Authorization header and verify the user's identity, providing a layer
of security to the operations that manipulate user data.

Key Highlights:
- Use of FastAPI's Dependency Injection system to manage database sessions and user authentication.
- Demonstrates how to perform CRUD operations in an asynchronous manner using SQLAlchemy with FastAPI.
- Implements HATEOAS by generating dynamic links for user-related actions, enhancing API discoverability.
- Utilizes OAuth2PasswordBearer for securing API endpoints, requiring valid access tokens for operations.
"""

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer
from app.dependencies import get_current_user, get_db, require_role
from app.schemas.user_schemas import UserUpdate, UserResponse
from app.services.user_service import UserService
from app.utils.link_generation import create_user_links

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.patch("/users/{user_id}/profile", response_model=UserResponse, tags=["User Management"])
async def update_profile_fields(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(get_current_user)
):
    """
    Update specific fields in the user's profile.

    Args:
        user_id (UUID): The unique identifier of the user.
        user_update (UserUpdate): The fields to be updated.
        request (Request): The request object for generating links.
        db (AsyncSession): Async database session.
        token (str): OAuth2 token for authentication.
        current_user (dict): The current authenticated user.

    Returns:
        UserResponse: Updated user profile.
    """
    if current_user["id"] != str(user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied.")

    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)

    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        id=updated_user.id,
        nickname=updated_user.nickname,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        bio=updated_user.bio,
        profile_picture_url=updated_user.profile_picture_url,
        github_profile_url=updated_user.github_profile_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        role=updated_user.role,
        email=updated_user.email,
        last_login_at=updated_user.last_login_at,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        links=create_user_links(updated_user.id, request)
    )

@router.post("/users/{user_id}/upgrade-status", response_model=UserResponse, tags=["User Management"])
async def upgrade_professional_status(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Upgrade the professional status of a user.

    Args:
        user_id (UUID): The unique identifier of the user.
        request (Request): The request object for generating links.
        db (AsyncSession): Async database session.
        token (str): OAuth2 token for authentication.
        current_user (dict): The current authenticated user with required role.

    Returns:
        UserResponse: User with upgraded professional status.
    """
    user = await UserService.get_by_id(db, user_id)

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.role == "PROFESSIONAL":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a professional."
        )

    updated_user = await UserService.update(db, user_id, {"role": "PROFESSIONAL"})

    return UserResponse.model_construct(
        id=updated_user.id,
        nickname=updated_user.nickname,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        bio=updated_user.bio,
        profile_picture_url=updated_user.profile_picture_url,
        github_profile_url=updated_user.github_profile_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        role=updated_user.role,
        email=updated_user.email,
        last_login_at=updated_user.last_login_at,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        links=create_user_links(updated_user.id, request)
    )