"""REST API server for anonymizer."""

import logging
import os
from contextlib import asynccontextmanager
from logging.config import fileConfig
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor

DEFAULT_PORT = "3000"

LOGGING_CONF_FILE = "logging.ini"

WELCOME_MESSAGE = r"""
 _______  _______  _______  _______ _________ ______  _________ _______
(  ____ )(  ____ )(  ____ \(  ____ \\__   __/(  __  \ \__   __/(  ___  )
| (    )|| (    )|| (    \/| (    \/   ) (   | (  \  )   ) (   | (   ) |
| (____)|| (____)|| (__    | (_____    | |   | |   ) |   | |   | |   | |
|  _____)|     __)|  __)   (_____  )   | |   | |   | |   | |   | |   | |
| (      | (\ (   | (            ) |   | |   | |   ) |   | |   | |   | |
| )      | ) \ \__| (____/\/\____) |___) (___| (__/  )___) (___| (___) |
|/       |/   \__/(_______/\_______)\_______/(______/ \_______/(_______)
"""


# --- Global engine instances ---

anonymizer: Optional[AnonymizerEngine] = None
deanonymizer: Optional[DeanonymizeEngine] = None
logger: Optional[logging.Logger] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global anonymizer, deanonymizer, logger

    fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
    logger = logging.getLogger("presidio-anonymizer")
    logger.setLevel(os.environ.get("LOG_LEVEL", logger.level))

    logger.info("Starting anonymizer engine")
    anonymizer = AnonymizerEngine()
    deanonymizer = DeanonymizeEngine()
    logger.info(WELCOME_MESSAGE)

    yield

    # Shutdown (cleanup if needed)


app = FastAPI(
    title="Presidio Anonymizer",
    description="PII anonymization and deanonymization service",
    lifespan=lifespan,
)


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    """Return basic health probe result."""
    return "Presidio Anonymizer service is up"


@app.post("/anonymize")
async def anonymize(request: Request) -> Response:
    """Anonymize the given text."""
    try:
        content = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request json")
    if not content:
        raise HTTPException(status_code=400, detail="Invalid request json")

    anonymizers_config = AppEntitiesConvertor.operators_config_from_json(
        content.get("anonymizers")
    )
    if AppEntitiesConvertor.check_custom_operator(anonymizers_config):
        raise HTTPException(
            status_code=400, detail="Custom type anonymizer is not supported"
        )

    analyzer_results = AppEntitiesConvertor.analyzer_results_from_json(
        content.get("analyzer_results")
    )
    anonymizer_result = anonymizer.anonymize(
        text=content.get("text", ""),
        analyzer_results=analyzer_results,
        operators=anonymizers_config,
    )
    return Response(anonymizer_result.to_json(), media_type="application/json")


@app.post("/deanonymize")
async def deanonymize(request: Request) -> Response:
    """Deanonymize the given text."""
    try:
        content = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request json")
    if not content:
        raise HTTPException(status_code=400, detail="Invalid request json")

    text = content.get("text", "")
    deanonymize_entities = AppEntitiesConvertor.deanonymize_entities_from_json(content)
    deanonymize_config = AppEntitiesConvertor.operators_config_from_json(
        content.get("deanonymizers")
    )
    deanonymized_response = deanonymizer.deanonymize(
        text=text, entities=deanonymize_entities, operators=deanonymize_config
    )
    return Response(deanonymized_response.to_json(), media_type="application/json")


@app.get("/anonymizers")
async def get_anonymizers():
    """Return a list of supported anonymizers."""
    return anonymizer.get_anonymizers()


@app.get("/deanonymizers")
async def get_deanonymizers():
    """Return a list of supported deanonymizers."""
    return deanonymizer.get_deanonymizers()


@app.exception_handler(InvalidParamError)
async def invalid_param_handler(request: Request, exc: InvalidParamError):
    """Handle invalid parameter errors."""
    logger.warning(f"Request failed with parameter validation error: {exc.err_msg}")
    return JSONResponse(
        status_code=422,
        content={"error": exc.err_msg},
    )


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    return JSONResponse(
        status_code=422,
        content={"error": str(exc)},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"A fatal error occurred during execution: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", DEFAULT_PORT))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
