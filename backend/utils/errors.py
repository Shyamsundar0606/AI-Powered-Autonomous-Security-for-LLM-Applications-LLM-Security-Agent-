import importlib.machinery
import importlib.util
import sysconfig

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError


def _load_stdlib_logging():
    stdlib_path = sysconfig.get_path("stdlib")
    spec = importlib.machinery.PathFinder.find_spec("logging", [stdlib_path])
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load standard library logging module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


logging = _load_stdlib_logging()
logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ValueError)
    async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
        logger.warning("Value error: %s", exc)
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_: Request, exc: ValidationError) -> JSONResponse:
        logger.warning("Validation error: %s", exc)
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    @app.exception_handler(Exception)
    async def generic_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error while processing the request."},
        )
