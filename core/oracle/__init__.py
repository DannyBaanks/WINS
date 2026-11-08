"""WINS Behavioral Oracle Subsystem.
Validates Win32 API shims against genuine runtime contracts, multi-threaded isolation,
and edge-case error conditions to power CEGIS synthesis.
"""

from .runner import OracleResult, run_behavioral_harness
from .tls_oracle import TlsBehavioralOracle
from .memory_oracle import MemoryBehavioralOracle

__all__ = [
    "OracleResult",
    "run_behavioral_harness",
    "TlsBehavioralOracle",
    "MemoryBehavioralOracle",
]
