"""P5: Continuous Update and Verification Engine."""

from .coordinator import UpdateCoordinator
from .dependencies import DependencyIndex
from .engine import UpdateEngine, VerificationReport
from .events import (
    EdgeInvalidationApplier,
    EventIntake,
    EventOutcome,
    NotifyingGraphRepository,
)
from .models import UpdateResult, UpdateStrategy
from .reconciliation import (
    DriftItem,
    DriftKind,
    Reconciler,
    ReconciliationResult,
    ReconciliationStatus,
    SourceInventory,
)
from .scheduler import ReconciliationScheduler
from .status import OverallState, SourceState, StatusTracker, SystemStatus
from .verification import (
    RemediationVerifier,
    SourceEvidence,
    VerificationResult,
)
from .versioning import EpochGuard

__all__ = [
    "UpdateCoordinator", "DependencyIndex", "UpdateResult", "UpdateStrategy",
    "UpdateEngine", "VerificationReport",
    "EventIntake", "EventOutcome", "NotifyingGraphRepository", "EdgeInvalidationApplier",
    "Reconciler", "ReconciliationResult", "ReconciliationStatus", "SourceInventory",
    "DriftItem", "DriftKind", "ReconciliationScheduler",
    "StatusTracker", "SystemStatus", "SourceState", "OverallState",
    "RemediationVerifier", "SourceEvidence", "VerificationResult", "EpochGuard",
]
