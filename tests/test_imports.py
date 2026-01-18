def test_import_analyzer():
    from presidio import AnalyzerEngine, RecognizerRegistry

    assert AnalyzerEngine is not None
    assert RecognizerRegistry is not None


def test_import_anonymizer():
    from presidio import AnonymizerEngine

    assert AnonymizerEngine is not None


def test_import_evaluator():
    from presidio import EvaluatorEngine

    assert EvaluatorEngine is not None


def test_import_image_redactor():
    from presidio import ImageRedactorEngine

    assert ImageRedactorEngine is not None


def test_import_structured():
    from presidio import StructuredEngine

    assert StructuredEngine is not None
