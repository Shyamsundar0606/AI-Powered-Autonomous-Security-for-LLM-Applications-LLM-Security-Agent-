from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from admin.routes import router as admin_router
from auth.auth_handler import initialize_auth_db
from auth.routes import router as auth_router
from logstore.db import init_db
from utils.errors import register_exception_handlers
from utils.logger import configure_logging


configure_logging()

app = FastAPI(
    title="LLM Security Gateway",
    description="Secure AI input/output firewall with modular prompt risk detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)
initialize_auth_db()
init_db()
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
