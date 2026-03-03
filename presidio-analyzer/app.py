"""REST API server for analyzer."""

import json
import logging
import os
import re
from contextlib import asynccontextmanager
from logging.config import fileConfig
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from presidio_analyzer import (
    AnalyzerEngine,
    AnalyzerEngineProvider,
    BatchAnalyzerEngine,
    PatternRecognizer,
)
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_PORT = "3000"
DEFAULT_BATCH_SIZE = "500"
DEFAULT_N_PROCESS = "1"

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


# --- Pydantic models ---


class AdHocRecognizer(BaseModel):
    """An ad-hoc recognizer definition. Allows extra fields for PatternRecognizer."""

    model_config = ConfigDict(extra="allow")

    name: str
    supported_language: str
    patterns: Optional[List[Dict[str, Any]]] = None
    deny_list: Optional[List[str]] = None
    context: Optional[List[str]] = None
    supported_entity: str


class AnalyzeRequest(BaseModel):
    """Request body for the /analyze endpoint."""

    model_config = ConfigDict(extra="ignore")

    text: Optional[Union[str, List[str]]] = None
    language: Optional[str] = None
    entities: Optional[List[str]] = None
    correlation_id: Optional[str] = None
    score_threshold: Optional[float] = None
    return_decision_process: Optional[bool] = False
    ad_hoc_recognizers: Optional[List[AdHocRecognizer]] = None
    context: Optional[List[str]] = None
    allow_list: Optional[List[str]] = None
    allow_list_match: Optional[str] = "exact"
    regex_flags: Optional[int] = Field(
        default=re.DOTALL | re.MULTILINE | re.IGNORECASE
    )


# --- Global engine instances ---

engine: Optional[AnalyzerEngine] = None
batch_engine: Optional[BatchAnalyzerEngine] = None
logger: Optional[logging.Logger] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global engine, batch_engine, logger

    # Startup
    fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
    logger = logging.getLogger("presidio-analyzer")
    logger.setLevel(os.environ.get("LOG_LEVEL", logger.level))

    analyzer_conf_file = os.environ.get("ANALYZER_CONF_FILE")
    nlp_engine_conf_file = os.environ.get("NLP_CONF_FILE")
    recognizer_registry_conf_file = os.environ.get("RECOGNIZER_REGISTRY_CONF_FILE")

    logger.info("Starting analyzer engine")
    engine = AnalyzerEngineProvider(
        analyzer_engine_conf_file=analyzer_conf_file,
        nlp_engine_conf_file=nlp_engine_conf_file,
        recognizer_registry_conf_file=recognizer_registry_conf_file,
    ).create_engine()

    batch_engine = BatchAnalyzerEngine(engine)
    logger.info(WELCOME_MESSAGE)

    yield

    # Shutdown (cleanup if needed)


app = FastAPI(
    title="Presidio Analyzer",
    description="PII detection and analysis service",
    lifespan=lifespan,
)


def _exclude_attributes_from_dto(recognizer_result_list):
    """Exclude internal attributes from response."""
    excluded_attributes = [
        "recognition_metadata",
    ]
    for result in recognizer_result_list:
        for attr in excluded_attributes:
            if hasattr(result, attr):
                delattr(result, attr)


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    """Return basic health probe result."""
    return "Presidio Analyzer service is up"


@app.post("/analyze")
async def analyze(req_data: AnalyzeRequest):
    """Execute the analyzer function."""
    try:
        if not req_data.text:
            raise Exception("No text provided")

        batch_request = isinstance(req_data.text, list)
        batch = req_data.text if batch_request else [req_data.text]

        if not req_data.language:
            raise Exception("No language provided")
        else:
            # Make sure the language is supported by the engine.
            engine.get_supported_entities(req_data.language)

        ad_hoc_recognizers = []
        if req_data.ad_hoc_recognizers:
            ad_hoc_recognizers = [
                PatternRecognizer.from_dict(rec.model_dump(exclude_none=True))
                for rec in req_data.ad_hoc_recognizers
            ]

        iterator = batch_engine.analyze_iterator(
            texts=batch,
            batch_size=min(
                len(batch), int(os.environ.get("BATCH_SIZE", DEFAULT_BATCH_SIZE))
            ),
            language=req_data.language,
            correlation_id=req_data.correlation_id,
            score_threshold=req_data.score_threshold,
            entities=req_data.entities,
            return_decision_process=req_data.return_decision_process,
            ad_hoc_recognizers=ad_hoc_recognizers,
            context=req_data.context,
            allow_list=req_data.allow_list,
            allow_list_match=req_data.allow_list_match,
            regex_flags=req_data.regex_flags,
            n_process=min(
                len(batch), int(os.environ.get("N_PROCESS", DEFAULT_N_PROCESS))
            ),
        )
        results = []
        for recognizer_result_list in iterator:
            _exclude_attributes_from_dto(recognizer_result_list)
            results.append(recognizer_result_list)

        response_data = results if batch_request else results[0]
        return Response(
            content=json.dumps(
                response_data,
                default=lambda o: o.to_dict(),
                sort_keys=True,
            ),
            media_type="application/json",
        )
    except TypeError as te:
        error_msg = (
            f"Failed to parse /analyze request "
            f"for AnalyzerEngine.analyze(). {te.args[0]}"
        )
        logger.error(error_msg)
        return JSONResponse(status_code=400, content={"error": error_msg})
    except Exception as e:
        logger.error(
            f"A fatal error occurred during execution of "
            f"AnalyzerEngine.analyze(). {e}"
        )
        return JSONResponse(status_code=500, content={"error": e.args[0]})


@app.get("/recognizers")
async def recognizers(language: Optional[str] = Query(None)) -> List[str]:
    """Return a list of supported recognizers."""
    try:
        recognizers_list = engine.get_recognizers(language)
        names = [o.name for o in recognizers_list]
        return names
    except Exception as e:
        logger.error(
            f"A fatal error occurred during execution of "
            f"AnalyzerEngine.get_recognizers(). {e}"
        )
        return JSONResponse(status_code=500, content={"error": e.args[0]})


@app.get("/supportedentities")
async def supported_entities(language: Optional[str] = Query(None)) -> List[str]:
    """Return a list of supported entities."""
    try:
        entities_list = engine.get_supported_entities(language)
        return entities_list
    except Exception as e:
        logger.error(
            f"A fatal error occurred during execution of "
            f"AnalyzerEngine.supported_entities(). {e}"
        )
        return JSONResponse(status_code=500, content={"error": e.args[0]})


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
