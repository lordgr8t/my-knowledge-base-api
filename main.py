from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy import create_engine, ForeignKey, String, Text, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship

# ─── Конфиг ──────────────────────────────────────────────
SECRET_KEY = "change-me-in-production-please-very-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # сутки

# ─── БД ──────────────────────────────────────────────────
engine = create_engine("sqlite:///./knowledge.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    username: Mapped[str] = mapped_column(String)
    hashed_password: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Article(Base):
    __tablename__ = "articles"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(Text, default="")
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("articles.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Безопасность ────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    # bcrypt обрезает пароль до 72 байт — делаем это явно
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    pw_bytes = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(pw_bytes, hashed.encode("utf-8"))


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Невалидный токен",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise credentials_exception

    user = db.get(User, user_id)
    if user is None:
        raise credentials_exception
    return user


# ─── Схемы (Pydantic) ────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    username: str


class AuthResponse(BaseModel):
    accessToken: str
    user: UserOut


class ArticleCreate(BaseModel):
    title: str
    content: str = ""
    parentId: Optional[int] = None


class ArticleUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    parentId: Optional[int] = None


class ArticleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: int
    title: str
    content: str
    parentId: Optional[int] = None
    createdAt: datetime
    updatedAt: datetime


# ─── FastAPI ─────────────────────────────────────────────
app = FastAPI(title="My Knowledge Base API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Auth ────────────────────────────────────────────────
@app.post("/api/auth/register", response_model=AuthResponse)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email уже занят")

    user = User(
        email=data.email,
        username=data.username,
        hashed_password=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return AuthResponse(accessToken=create_access_token(user.id), user=user)


@app.post("/api/auth/login", response_model=AuthResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(401, "Неверный email или пароль")

    return AuthResponse(accessToken=create_access_token(user.id), user=user)


@app.get("/api/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


# ─── Articles ────────────────────────────────────────────
@app.get("/api/articles", response_model=list[ArticleOut])
def list_articles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(Article).filter(Article.user_id == current_user.id).all()


@app.get("/api/articles/{article_id}", response_model=ArticleOut)
def get_article(
    article_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    article = (
        db.query(Article)
        .filter(Article.id == article_id, Article.user_id == current_user.id)
        .first()
    )
    if not article:
        raise HTTPException(404, "Статья не найдена")
    return article


@app.post("/api/articles", response_model=ArticleOut, status_code=201)
def create_article(
    data: ArticleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Проверка, что parent принадлежит пользователю (если указан)
    if data.parentId is not None:
        parent = (
            db.query(Article)
            .filter(Article.id == data.parentId, Article.user_id == current_user.id)
            .first()
        )
        if not parent:
            raise HTTPException(400, "Родительская статья не найдена")

    article = Article(
        user_id=current_user.id,
        title=data.title,
        content=data.content,
        parent_id=data.parentId,
    )
    db.add(article)
    db.commit()
    db.refresh(article)
    return article


@app.put("/api/articles/{article_id}", response_model=ArticleOut)
def update_article(
    article_id: int,
    data: ArticleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    article = (
        db.query(Article)
        .filter(Article.id == article_id, Article.user_id == current_user.id)
        .first()
    )
    if not article:
        raise HTTPException(404, "Статья не найдена")

    if data.title is not None:
        article.title = data.title
    if data.content is not None:
        article.content = data.content
    if data.parentId is not None:
        article.parent_id = data.parentId

    db.commit()
    db.refresh(article)
    return article


@app.delete("/api/articles/{article_id}", status_code=204)
def delete_article(
    article_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    article = (
        db.query(Article)
        .filter(Article.id == article_id, Article.user_id == current_user.id)
        .first()
    )
    if not article:
        raise HTTPException(404, "Статья не найдена")

    db.delete(article)
    db.commit()
