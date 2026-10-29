# app/main.py
import logging
import threading
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import store
from app.api import alerts, audit, health, identities, metrics
from app.config import STATIC_DIR
from app.pipeline import run_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("identityshield")

_pipeline_lock = threading.Lock()


def get_or_run_pipeline(target_app: FastAPI | None = None):
    a = target_app or app
    res = getattr(a.state, "result", None)
    if res is not None:
        return res
    with _pipeline_lock:
        res = getattr(a.state, "result", None)
        if res is not None:
            return res
        store.init_db()
        try:
            res = run_pipeline()
            a.state.result = res
            a.state.startup_error = ""
            return res
        except Exception as exc:  # noqa: BLE001
            log.exception("Pipeline initialization failed")
            a.state.result = None
            a.state.startup_error = str(exc)
            return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_or_run_pipeline(app)
    yield


app = FastAPI(title="IdentityShield", version="1.0", lifespan=lifespan)
app.state.result = None
app.state.startup_error = ""


def _err(status: int, error: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error, "detail": detail, "request_id": uuid.uuid4().hex[:12]}
    )


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    code = {404: "not_found", 409: "conflict", 422: "validation_error", 503: "pipeline_not_ready"}.get(
        exc.status_code, "http_error"
    )
    return _err(exc.status_code, code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    return _err(422, "validation_error", str(exc.errors()))


@app.exception_handler(Exception)
async def unhandled_error(_: Request, exc: Exception):
    log.exception("Unhandled error")
    return _err(500, "internal_error", "Unexpected server error. See server log.")


for module in (health, alerts, identities, metrics, audit):
    app.include_router(module.router, prefix="/api")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/index.html")


from app.api import v21 as _v21_api  # v2.1 kit
app.include_router(_v21_api.router, prefix="/api")

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
