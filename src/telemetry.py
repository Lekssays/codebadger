"""OpenTelemetry helpers for CodeBadger.

Provides a safe get_tracer() that returns a no-op tracer when OTel is not installed,
so callers can always use `with tracer.start_as_current_span(...)` without guards.
"""

import logging

logger = logging.getLogger(__name__)

_TRACER_NAME = "codebadger"


def get_tracer():
    """Return an OpenTelemetry tracer.

    Falls back to a no-op tracer if the OTel SDK is not installed or configured.
    """
    try:
        from opentelemetry import trace
        return trace.get_tracer(_TRACER_NAME)
    except ImportError:
        from contextlib import contextmanager

        class _NoOpSpan:
            def set_attribute(self, key, value):
                pass

            def set_status(self, status):
                pass

            def record_exception(self, exception):
                pass

        class _NoOpTracer:
            @contextmanager
            def start_as_current_span(self, name, **kwargs):
                yield _NoOpSpan()

        return _NoOpTracer()
