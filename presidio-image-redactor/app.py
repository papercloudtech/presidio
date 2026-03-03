"""REST API server for image redactor."""

import base64
import logging
import os
from contextlib import asynccontextmanager
from io import BytesIO
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from PIL import Image
from presidio_image_redactor import ImageRedactorEngine
from presidio_image_redactor.entities import InvalidParamError
from presidio_image_redactor.entities.api_request_convertor import (
    color_fill_string_to_value,
    get_json_data,
    image_to_byte_array,
)
from pydantic import BaseModel, ConfigDict

DEFAULT_PORT = "3000"

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


class RedactJsonRequest(BaseModel):
    """Request body for the /redact endpoint (JSON payload)."""

    model_config = ConfigDict(extra="ignore")

    image: str
    analyzer_entities: Optional[List[str]] = None


# --- Global engine instance ---

engine: Optional[ImageRedactorEngine] = None
logger: Optional[logging.Logger] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global engine, logger

    # Startup
    logger = logging.getLogger("presidio-image-redactor")

    logger.info("Starting image redactor engine")
    engine = ImageRedactorEngine()
    logger.info(WELCOME_MESSAGE)

    yield

    # Shutdown (cleanup if needed)


app = FastAPI(
    title="Presidio Image Redactor",
    description="PII redaction service for images",
    lifespan=lifespan,
)


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    """Return basic health probe result."""
    return "Presidio Image Redactor service is up"


@app.post("/redact")
async def redact(request: Request) -> Response:
    """Return a redacted image."""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        params = get_json_data(form.get("data"))
        color_fill = color_fill_string_to_value(params)

        image_file = form.get("image")
        if image_file:
            contents = await image_file.read()
            im = Image.open(BytesIO(contents))
            redacted_image = engine.redact(im, color_fill, score_threshold=0.4)
            img_byte_arr = image_to_byte_array(redacted_image, im.format)
            return Response(img_byte_arr, media_type="application/octet-stream")
    else:
        try:
            json_data = await request.json()
        except Exception:
            json_data = None

        if json_data and "image" in json_data:
            req_data = RedactJsonRequest(**json_data)
            params = get_json_data(None)
            color_fill = color_fill_string_to_value(params)
            im = Image.open(BytesIO(base64.b64decode(req_data.image)))
            redacted_image = engine.redact(
                im, color_fill, entities=req_data.analyzer_entities
            )
            img_byte_arr = image_to_byte_array(redacted_image, im.format)
            return Response(
                base64.b64encode(img_byte_arr),
                media_type="application/octet-stream",
            )

    raise InvalidParamError("Invalid parameter, please add image data")


@app.exception_handler(InvalidParamError)
async def invalid_param_handler(request: Request, exc: InvalidParamError):
    """Handle invalid parameter errors."""
    logger.warning(f"Failed to redact image with validation error: {exc.err_msg}")
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
