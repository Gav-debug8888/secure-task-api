"""Task CRUD. Every route requires authentication and is scoped to the caller's own tasks.

Object-level authorisation: queries always filter on owner_id, and another user's
task returns 404 (not 403) so IDs cannot be used to probe for existence.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.logging_config import log_security_event
from app.middleware.rate_limiter import TASK_LIMIT, limiter
from app.models import Task, TaskPriority, TaskStatus, User
from app.schemas import TaskCreate, TaskOut, TaskUpdate

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


def _get_owned_task(db: Session, task_id: int, user: User) -> Task:
    task = db.scalar(select(Task).where(Task.id == task_id, Task.owner_id == user.id))
    if task is None:
        if db.get(Task, task_id) is not None:
            log_security_event("task_access_denied", logging.WARNING, user_id=user.id, task_id=task_id)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Task not found")
    return task


@router.get("", response_model=list[TaskOut])
@limiter.limit(TASK_LIMIT)
def list_tasks(
    request: Request,
    status_filter: TaskStatus | None = Query(default=None, alias="status"),
    priority: TaskPriority | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Task).where(Task.owner_id == user.id)
    if status_filter:
        stmt = stmt.where(Task.status == status_filter)
    if priority:
        stmt = stmt.where(Task.priority == priority)
    stmt = stmt.order_by(Task.created_at.desc(), Task.id.desc()).limit(limit).offset(offset)
    return db.scalars(stmt).all()


@router.post("", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(TASK_LIMIT)
def create_task(request: Request, payload: TaskCreate, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    task = Task(**payload.model_dump(), owner_id=user.id)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.get("/{task_id}", response_model=TaskOut)
@limiter.limit(TASK_LIMIT)
def get_task(request: Request, task_id: int, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    return _get_owned_task(db, task_id, user)


@router.patch("/{task_id}", response_model=TaskOut)
@limiter.limit(TASK_LIMIT)
def update_task(request: Request, task_id: int, payload: TaskUpdate,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = _get_owned_task(db, task_id, user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field in ("title", "status", "priority") and value is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"{field} cannot be null")
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(TASK_LIMIT)
def delete_task(request: Request, task_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    task = _get_owned_task(db, task_id, user)
    db.delete(task)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
