"""Incident timeline core engine.

Collects log files as hashed, read-only evidence, parses them, normalises
every timestamp to UTC (inferring missing years and correcting clock skew)
and writes a merged, line-traceable timeline.
"""

__version__ = "0.1.0"
