"""ML-based likelihood estimator (separate from rule-based scoring and impact).

Status: PROOF OF CONCEPT. No real outcome labels exist in this repo, so any
model trained here uses SYNTHETIC labels and its outputs are NOT real attack
probabilities. See README.md in this folder.

Person 4 entry point: `estimate_likelihood(path, snapshot)`.
"""
from .interface import MLLikelihoodEstimate, estimate_likelihood, estimate_many
from .persistence import ModelLoadError, load_model, save_model

__all__ = ["MLLikelihoodEstimate", "estimate_likelihood", "estimate_many",
           "ModelLoadError", "load_model", "save_model"]