# Presidio

Presidio is a small aggregation library whose objective is to provide a single, stable, and ergonomic entry point to the Microsoft Presidio ecosystem. Instead of installing and importing multiple Presidio packages independently, this repository defines a thin facade that centralizes dependency management and exposes commonly used engines through a unified namespace. The library does not alter behavior, reimplement logic, or introduce abstractions that could diverge from upstream Presidio. Its responsibility is limited to composition, consistency, and ease of use.

The primary audience for this package is engineers who already rely on Presidio for PII detection, anonymization, evaluation, image redaction, or structured data handling and want a simpler installation and import experience. By installing one package, you gain access to all supported Presidio components, while still interacting with the original engines exactly as they are defined upstream.

## Installation

The package is published to PyPI under the name `presidio`. Installing it without extras provides a batteries included experience and installs all supported Presidio components.

```sh
pip install presidio
```

In addition to the full installation, the package defines subgroup extras that correspond to common Presidio usage patterns. These extras are additive and are primarily intended to document functional groupings and support advanced dependency management workflows.

To install analysis related components:

```sh
pip install presidio[analyzer]
```

To install anonymization support, including the required analyzer dependency:

```sh
pip install presidio[anonymization]
```

To install evaluation tooling:

```sh
pip install presidio[evaluation]
```

To install image redaction support:

```sh
pip install presidio[image]
```

To install structured data processing support:

```sh
pip install presidio[structured]
```

## Usage

Once installed, all major Presidio engines can be imported from a single namespace. This removes the need to remember individual package names and results in more readable application code. The objects you import are the original Presidio classes and behave identically to direct imports from their source packages.

```python
from presidio import AnalyzerEngine, AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

results = analyzer.analyze(text="My email is test@example.com", language="en")
output = anonymizer.anonymize(
    text="My email is test@example.com",
    analyzer_results=results
)
```

The same pattern applies to evaluation, image redaction, and structured data use cases. Each domain specific engine is exposed through a dedicated module and reexported at the top level for convenience. This design keeps the learning curve flat while preserving full access to Presidio’s configuration options and extension points.

## Design Philosophy

This repository intentionally avoids adding orchestration logic, opinionated pipelines, or convenience wrappers that could become a maintenance burden or limit flexibility. Presidio evolves quickly, and the safest abstraction is one that stays close to the source. Presidio therefore focuses on three guarantees: a single install surface, a consistent import path, and transparent pass through to upstream functionality.

As a result, upgrading Presidio versions remains straightforward, debugging remains intuitive, and users can always fall back to official Presidio documentation without translation or adaptation.

## Versioning and Upstream Compatibility

Presidio follows a compatibility driven versioning strategy rather than feature driven semantic versioning. Because the package does not introduce original functionality and instead aggregates upstream Presidio libraries, version numbers are used to communicate stability of the public import surface and tested compatibility with upstream releases.

Patch releases are reserved for packaging fixes, documentation updates, and dependency resolution issues that do not change the exposed API. Minor releases indicate that the package has been validated against newer versions of one or more Presidio components while preserving the same import paths and symbols. Major releases are reserved for intentional breaking changes to the public namespace, such as renamed modules or removed reexports, and are expected to be rare.

The package does not pin exact upstream versions unless required to prevent known incompatibilities. Instead, it relies on Presidio’s own version constraints and validates that the aggregated packages work together as a set. The versions of the upstream libraries included in a given release can always be inspected via the resolved dependency graph after installation, and changes in upstream compatibility are reflected in the release notes rather than encoded directly into the API.

This approach ensures that users can upgrade Presidio with confidence, knowing that a new release represents tested compatibility rather than hidden behavioral changes.

## License and Maintenance

Presidio is released under the MIT license and is intended to be lightweight and low maintenance. Contributions should preserve the core goal of aggregation and ergonomics and should not introduce behavioral divergence from upstream Presidio packages.
