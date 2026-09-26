"""Fixtures for the Spark test suite.

These tests need a JVM and a matching Python on both driver and worker, so they
live apart from the core suite and skip cleanly when that environment is absent
(`make test` in the main venv skips them; `make test-spark` runs them).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

pyspark = pytest.importorskip("pyspark", reason="pyspark not installed")

from pyspark.sql import SparkSession  # noqa: E402


def _java_major_version() -> int | None:
    """Best-effort major version of the JVM Spark will launch."""
    java_home = os.environ.get("JAVA_HOME")
    java = f"{java_home}/bin/java" if java_home else "java"
    try:
        out = subprocess.run(
            [java, "-version"], capture_output=True, text=True, timeout=30
        ).stderr
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r'version "(\d+)', out)
    return int(match.group(1)) if match else None


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Session-scoped local SparkSession.

    Starting a JVM costs seconds, so it is shared across the module. Each test
    builds its own DataFrames, so there is no shared mutable state.
    """
    major = _java_major_version()
    if major is None:
        pytest.skip("no JVM found on PATH or at JAVA_HOME")
    if major >= 24:
        # JEP 486 removed the Security Manager; Hadoop's UserGroupInformation
        # calls Subject.getSubject(), which now throws. Spark 4.0 supports 17/21.
        pytest.skip(
            f"Java {major} is incompatible with Spark 4.0 "
            "(Subject.getSubject removed in 24+); set JAVA_HOME to a JDK 17 or 21"
        )
    if major < 17:
        pytest.skip(f"Spark 4.0 requires Java 17+, found {major}")

    # Driver and worker must run the *same* Python minor version. Pinning both
    # to the interpreter running pytest removes the most common local failure.
    os.environ["PYSPARK_PYTHON"] = sys.executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable

    session = (
        SparkSession.builder.appName("forensics-tests")
        .master("local[2]")
        .config("spark.ui.enabled", "false")
        # Small shuffle width keeps the suite fast; the default 200 would spawn
        # hundreds of empty tasks per aggregation.
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.legacy.timeParserPolicy", "CORRECTED")
        .getOrCreate()
    )
    session.sparkContext.setLogLevel("ERROR")
    yield session
    session.stop()
