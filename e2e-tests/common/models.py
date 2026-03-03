"""Pydantic models mirroring the service API request/response schemas.

These models match the Pydantic models defined in each service's app.py,
ensuring consistency between tests and service code.
"""

import re
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

# --- Analyzer models ---


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


# --- Anonymizer models ---


class AnalyzerResult(BaseModel):
    """A single analyzer result from the analyzer service."""

    start: int
    end: int
    score: float
    entity_type: str


class OperatorConfigModel(BaseModel):
    """Operator configuration with extra params passed through."""

    type: str
    model_config = ConfigDict(extra="allow")


class AnonymizeRequest(BaseModel):
    """Request body for the /anonymize endpoint."""

    text: str = ""
    anonymizers: Optional[Dict[str, OperatorConfigModel]] = None
    analyzer_results: Optional[List[AnalyzerResult]] = None


class AnonymizeItemResponse(BaseModel):
    """A single anonymized item in the response."""

    operator: str
    entity_type: str
    start: int
    end: int
    text: str


class AnonymizeResponse(BaseModel):
    """Response body for the /anonymize endpoint."""

    text: str
    items: List[AnonymizeItemResponse]


class AnonymizerResultItem(BaseModel):
    """A single anonymizer result item for deanonymization."""

    start: int
    end: int
    entity_type: str
    text: Optional[str] = None
    operator: Optional[str] = None


class DeanonymizeRequest(BaseModel):
    """Request body for the /deanonymize endpoint."""

    text: str = ""
    deanonymizers: Optional[Dict[str, OperatorConfigModel]] = None
    anonymizer_results: Optional[List[AnonymizerResultItem]] = None


# --- Image Redactor models ---


class RedactJsonRequest(BaseModel):
    """Request body for the /redact endpoint (JSON payload)."""

    model_config = ConfigDict(extra="ignore")

    image: str
    analyzer_entities: Optional[List[str]] = None
