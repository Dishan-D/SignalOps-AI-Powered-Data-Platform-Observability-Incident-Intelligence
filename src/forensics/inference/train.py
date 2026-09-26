"""Training loop for the LogBERT detector.

One-class training: the model sees benign sequences only. Attack labels are
withheld entirely and used afterwards purely to measure the result — see
:mod:`forensics.inference.evaluate`.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from forensics.common.logging import get_logger
from forensics.inference.model import (
    LogBERT,
    ModelConfig,
    count_parameters,
    mask_tokens,
    select_device,
)
from forensics.inference.sequences import SequenceBuilder, SequenceWindow

if TYPE_CHECKING:
    # Type-only: evaluate.py imports windows_to_tensor from this module, so a
    # runtime import here would be a cycle. `from __future__ import annotations`
    # makes the annotation a string, and reading threshold.cuts needs no import.
    from forensics.inference.evaluate import Threshold

logger = get_logger(__name__, component="training")


@dataclass(frozen=True, slots=True)
class TrainingConfig:
    epochs: int = 12
    batch_size: int = 128
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    mask_probability: float = 0.25
    # Weight on the hypersphere term. Small: MLM is the primary objective, and
    # an over-weighted sphere term collapses every representation to the centre,
    # which scores perfectly on its own loss and destroys the MLM signal.
    hypersphere_weight: float = 0.1
    # Epochs of MLM-only training before the centre is fixed. Fixing it against
    # a randomly-initialised encoder would anchor it to noise.
    center_warmup_epochs: int = 2
    validation_fraction: float = 0.1
    seed: int = 1337
    grad_clip: float = 1.0


@dataclass(slots=True)
class TrainingResult:
    model: LogBERT
    builder: SequenceBuilder
    config: ModelConfig
    training_config: TrainingConfig
    history: list[dict[str, float]]
    device: str


def set_seed(seed: int) -> None:
    """Make a run reproducible."""
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def windows_to_tensor(windows: list[SequenceWindow]) -> torch.Tensor:
    return torch.tensor([w.token_ids for w in windows], dtype=torch.long)


def train(
    benign_windows: list[SequenceWindow],
    builder: SequenceBuilder,
    *,
    config: TrainingConfig | None = None,
    model_config: ModelConfig | None = None,
    device: torch.device | None = None,
) -> TrainingResult:
    """Fit the model on benign sequences."""
    training_config = config or TrainingConfig()
    set_seed(training_config.seed)

    if any(w.is_anomaly for w in benign_windows):
        # Loud, not a warning: silently training on attack data would inflate
        # every metric downstream and the mistake is invisible in the output.
        raise ValueError(
            "training set contains windows labelled anomalous; the detector is "
            "trained one-class on benign traffic only"
        )

    resolved_device = device or select_device()
    vocab_size = builder.vocabulary.size
    architecture = model_config or ModelConfig(
        vocab_size=vocab_size, max_sequence_length=builder.window_size
    )
    if architecture.vocab_size < vocab_size:
        raise ValueError(
            f"model vocab_size {architecture.vocab_size} is smaller than the "
            f"fitted vocabulary {vocab_size}"
        )

    tensor = windows_to_tensor(benign_windows)
    generator = torch.Generator().manual_seed(training_config.seed)
    permutation = torch.randperm(tensor.size(0), generator=generator)
    tensor = tensor[permutation]

    split = max(1, int(tensor.size(0) * training_config.validation_fraction))
    validation_tensor = tensor[:split]
    train_tensor = tensor[split:]

    loader = DataLoader(
        TensorDataset(train_tensor),
        batch_size=training_config.batch_size,
        shuffle=True,
        generator=generator,
    )

    model = LogBERT(architecture).to(resolved_device)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=training_config.learning_rate,
        weight_decay=training_config.weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=max(training_config.epochs, 1)
    )
    # -100 is the label for "not masked"; cross-entropy skips those positions.
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    logger.info(
        "Training LogBERT",
        extra={
            "device": str(resolved_device),
            "parameters": count_parameters(model),
            "vocab_size": vocab_size,
            "sequence_length": builder.window_size,
            "train_windows": int(train_tensor.size(0)),
            "validation_windows": int(validation_tensor.size(0)),
            "epochs": training_config.epochs,
        },
    )

    mask_generator = torch.Generator(device=resolved_device).manual_seed(
        training_config.seed
    )
    history: list[dict[str, float]] = []

    for epoch in range(1, training_config.epochs + 1):
        model.train()
        started = time.perf_counter()
        total_mlm = total_sphere = 0.0
        correct = counted = 0
        batches = 0

        for (batch,) in loader:
            batch = batch.to(resolved_device)
            corrupted, labels = mask_tokens(
                batch,
                mask_probability=training_config.mask_probability,
                vocab_size=architecture.vocab_size,
                generator=mask_generator,
            )

            logits, pooled = model(corrupted)
            mlm_loss = criterion(
                logits.reshape(-1, logits.size(-1)), labels.reshape(-1)
            )

            loss = mlm_loss
            sphere_loss = torch.zeros((), device=resolved_device)
            if model.center_initialised:
                sphere_loss = model.hypersphere_loss(pooled)
                loss = loss + training_config.hypersphere_weight * sphere_loss

            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            # Small transformers without warmup are prone to a single huge step
            # early on; clipping is cheap insurance.
            nn.utils.clip_grad_norm_(model.parameters(), training_config.grad_clip)
            optimizer.step()

            total_mlm += float(mlm_loss)
            total_sphere += float(sphere_loss)
            batches += 1

            masked = labels != -100
            if masked.any():
                predicted = logits.argmax(dim=-1)
                correct += int((predicted[masked] == labels[masked]).sum())
                counted += int(masked.sum())

        scheduler.step()

        # Fix the hypersphere centre once the encoder is no longer random.
        if epoch == training_config.center_warmup_epochs and not model.center_initialised:
            model.eval()
            with torch.no_grad():
                _, pooled = model(train_tensor.to(resolved_device))
                model.initialise_center(pooled)
            logger.info("Hypersphere centre initialised", extra={"epoch": epoch})

        validation_loss = _validation_loss(
            model, validation_tensor, criterion, training_config, architecture,
            resolved_device, mask_generator,
        )

        entry = {
            "epoch": epoch,
            "mlm_loss": total_mlm / max(batches, 1),
            "sphere_loss": total_sphere / max(batches, 1),
            "mlm_accuracy": correct / max(counted, 1),
            "validation_loss": validation_loss,
            "seconds": time.perf_counter() - started,
        }
        history.append(entry)
        logger.info("Epoch complete", extra=entry)

    return TrainingResult(
        model=model,
        builder=builder,
        config=architecture,
        training_config=training_config,
        history=history,
        device=str(resolved_device),
    )


def _validation_loss(
    model: LogBERT,
    tensor: torch.Tensor,
    criterion: nn.Module,
    training_config: TrainingConfig,
    architecture: ModelConfig,
    device: torch.device,
    generator: torch.Generator,
) -> float:
    if tensor.numel() == 0:
        return float("nan")
    model.eval()
    with torch.no_grad():
        batch = tensor.to(device)
        corrupted, labels = mask_tokens(
            batch,
            mask_probability=training_config.mask_probability,
            vocab_size=architecture.vocab_size,
            generator=generator,
        )
        logits, _ = model(corrupted)
        return float(criterion(logits.reshape(-1, logits.size(-1)), labels.reshape(-1)))


# --------------------------------------------------------------------------- #
# Persistence                                                                  #
# --------------------------------------------------------------------------- #

def save_bundle(
    result: TrainingResult,
    directory: str | Path,
    *,
    threshold: Threshold,
) -> Path:
    """Persist weights, architecture, miner, vocabulary and calibration together.

    They are saved as one bundle because they are only meaningful together: the
    weights are indexed by vocabulary ids, those ids are produced by this
    specific miner, and the thresholds were measured against this model's score
    distribution. Loading a model against a differently-fitted miner, or
    thresholds from a different run, would silently mean something else.

    ``threshold`` is a REQUIRED keyword argument, not an optional extra. A bundle
    without calibrated cuts cannot make a decision, so the scorer refuses to
    start on one — which makes saving an uncalibrated bundle a bug rather than a
    valid state. Making it required means that bug cannot be written.
    """
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)

    torch.save(result.model.state_dict(), path / "model.pt")
    (path / "config.json").write_text(
        json.dumps(
            {
                "model": result.config.to_dict(),
                "window_size": result.builder.window_size,
                "stride": result.builder.stride,
                "device_trained_on": result.device,
                "history": result.history,
                # Read back by forensics.inference.scorer, which exits non-zero
                # if they are absent.
                "thresholds": dict(threshold.cuts),
                "target_false_positive_rate": threshold.target_false_positive_rate,
            },
            indent=2,
        )
    )
    (path / "templates.json").write_text(json.dumps(result.builder.miner.to_dict(), indent=2))
    (path / "vocabulary.json").write_text(
        json.dumps(result.builder.vocabulary.to_dict(), indent=2)
    )
    logger.info("Saved model bundle", extra={"path": str(path)})
    return path


def load_bundle(
    directory: str | Path, *, device: torch.device | None = None
) -> tuple[LogBERT, SequenceBuilder, dict]:
    """Reload a bundle saved by :func:`save_bundle`."""
    from forensics.inference.templates import DrainTemplateMiner
    from forensics.inference.vocabulary import LogKeyVocabulary

    path = Path(directory)
    metadata = json.loads((path / "config.json").read_text())
    architecture = ModelConfig(**metadata["model"])

    resolved_device = device or select_device()
    model = LogBERT(architecture)
    state = torch.load(path / "model.pt", map_location=resolved_device)
    model.load_state_dict(state)
    # The centre is a buffer, so it round-trips with the state dict; mark it
    # initialised or scoring would silently use a zero centre.
    model._center_initialised = True  # noqa: SLF001 - intentional, see docstring
    model.to(resolved_device).eval()

    miner = DrainTemplateMiner.from_dict(json.loads((path / "templates.json").read_text()))
    vocabulary = LogKeyVocabulary.from_dict(
        json.loads((path / "vocabulary.json").read_text())
    )
    builder = SequenceBuilder(
        miner=miner,
        vocabulary=vocabulary,
        window_size=metadata["window_size"],
        stride=metadata["stride"],
    )
    return model, builder, metadata
