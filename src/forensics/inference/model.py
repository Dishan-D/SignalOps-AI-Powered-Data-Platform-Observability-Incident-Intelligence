"""LogBERT-style anomaly model.

A small bidirectional transformer over log-key sequences, trained on *benign
traffic only* with two objectives:

1. **Masked Log Key Prediction (MLM).** Random positions are replaced with
   ``[MASK]`` and the model predicts what belonged there. Learning the
   distribution of normal continuations is the whole trick: at inference, a
   sequence the model cannot reconstruct is one it has not seen the like of.

2. **Volume of Hypersphere Minimisation (VHM).** Sequence representations are
   pulled toward a single learned centre. MLM alone can be satisfied by a model
   that memorises local bigrams; the hypersphere term forces a *global* notion
   of "normal", and its radius gives a second, independent anomaly signal.

Trained one-class, on benign data only. That is a deliberate choice, not a
convenience: real estates have no labelled attacks, novel tradecraft is by
definition absent from any label set, and the 1-in-10 000 class imbalance makes
supervised training on real base rates hopeless. The synthetic labels exist
solely to *measure* the detector, never to fit it.

Detection rule follows the paper: mask each position in turn and ask whether the
true key is within the model's top-``g`` predictions. The anomaly score is the
fraction of positions that miss.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import torch
from torch import Tensor, nn

from forensics.inference.vocabulary import FIRST_FREE_ID, MASK_ID, PAD_ID


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Architecture. Small on purpose — the vocabulary is tens of keys, not
    tens of thousands of word pieces, so a BERT-base-sized model would have far
    more parameters than there is signal to fit and would simply memorise."""

    vocab_size: int
    max_sequence_length: int = 16
    d_model: int = 64
    n_heads: int = 4
    n_layers: int = 2
    d_feedforward: int = 128
    dropout: float = 0.1

    def __post_init__(self) -> None:
        if self.d_model % self.n_heads:
            raise ValueError(
                f"d_model ({self.d_model}) must be divisible by n_heads ({self.n_heads})"
            )

    def to_dict(self) -> dict:
        return asdict(self)


class LogBERT(nn.Module):
    """Bidirectional encoder over log keys with an MLM head."""

    def __init__(self, config: ModelConfig) -> None:
        super().__init__()
        self.config = config

        self.token_embedding = nn.Embedding(
            config.vocab_size, config.d_model, padding_idx=PAD_ID
        )
        # Learned positional embeddings: sequences are short and fixed-length,
        # so there is nothing to extrapolate to and no reason to pay for the
        # sinusoidal scheme's complexity.
        self.position_embedding = nn.Embedding(
            config.max_sequence_length, config.d_model
        )
        self.embedding_norm = nn.LayerNorm(config.d_model)
        self.embedding_dropout = nn.Dropout(config.dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.n_heads,
            dim_feedforward=config.d_feedforward,
            dropout=config.dropout,
            activation="gelu",
            batch_first=True,
            # Pre-norm: markedly more stable for small models trained without a
            # long warmup schedule.
            norm_first=True,
        )
        # enable_nested_tensor is incompatible with norm_first and would be
        # silently ignored; setting it explicitly documents the choice and stops
        # PyTorch warning on every construction.
        self.encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=config.n_layers, enable_nested_tensor=False
        )
        self.mlm_head = nn.Linear(config.d_model, config.vocab_size)

        # Hypersphere centre. A buffer, not a parameter: if it were learned by
        # gradient descent alongside everything else, the trivial solution is to
        # collapse the encoder to a constant and drive the radius to zero.
        # It is set from the data after a warmup instead.
        self.register_buffer("center", torch.zeros(config.d_model))
        self._center_initialised = False

        self.apply(self._init_weights)

    @staticmethod
    def _init_weights(module: nn.Module) -> None:
        if isinstance(module, nn.Linear):
            nn.init.normal_(module.weight, std=0.02)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, std=0.02)
            if module.padding_idx is not None:
                with torch.no_grad():
                    module.weight[module.padding_idx].fill_(0)

    # -- forward --------------------------------------------------------------

    def encode(self, tokens: Tensor) -> Tensor:
        """Contextual representation per position. ``(B, L) -> (B, L, D)``."""
        batch, length = tokens.shape
        positions = torch.arange(length, device=tokens.device).unsqueeze(0).expand(batch, -1)

        hidden = self.token_embedding(tokens) + self.position_embedding(positions)
        hidden = self.embedding_dropout(self.embedding_norm(hidden))

        # Padding must not be attended to, or a short sequence's representation
        # is diluted by however much padding it happened to receive.
        padding_mask = tokens == PAD_ID
        return self.encoder(hidden, src_key_padding_mask=padding_mask)

    def forward(self, tokens: Tensor) -> tuple[Tensor, Tensor]:
        """Returns (MLM logits ``(B, L, V)``, pooled representation ``(B, D)``)."""
        hidden = self.encode(tokens)
        logits = self.mlm_head(hidden)

        # Mean over real positions only.
        mask = (tokens != PAD_ID).unsqueeze(-1).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
        return logits, pooled

    # -- objectives -----------------------------------------------------------

    def hypersphere_loss(self, pooled: Tensor) -> Tensor:
        """Mean squared distance from the centre."""
        return ((pooled - self.center) ** 2).sum(dim=1).mean()

    @torch.no_grad()
    def initialise_center(self, pooled: Tensor) -> None:
        """Fix the centre at the mean representation of benign data.

        Tiny components are nudged away from zero: a centre coordinate at
        exactly zero lets the network satisfy the objective by zeroing that
        dimension, which is collapse rather than learning.
        """
        center = pooled.mean(dim=0)
        epsilon = 0.01
        center[(center.abs() < epsilon) & (center < 0)] = -epsilon
        center[(center.abs() < epsilon) & (center >= 0)] = epsilon
        self.center.copy_(center)
        self._center_initialised = True

    @property
    def center_initialised(self) -> bool:
        return self._center_initialised

    # -- inference ------------------------------------------------------------

    @torch.no_grad()
    def position_surprise(self, tokens: Tensor, *, top_g: int) -> dict[str, Tensor]:
        """Per-position negative log-likelihood and top-``g`` miss mask.

        Every position is masked in turn, because a model that can see the token
        it is predicting will simply copy it — self-attention makes the task
        trivial and the score meaningless.

        Done as one batched pass over ``B * L`` variants rather than a Python
        loop over positions: ``L`` is small and the GPU would otherwise sit idle
        between tiny forward passes.
        """
        batch, length = tokens.shape
        device = tokens.device
        valid = tokens != PAD_ID

        expanded = tokens.unsqueeze(1).expand(batch, length, length).clone()
        diagonal = torch.arange(length, device=device)
        expanded[:, diagonal, diagonal] = MASK_ID
        flat = expanded.reshape(batch * length, length)

        logits, _ = self.forward(flat)                      # (B*L, L, V)
        logits = logits.reshape(batch, length, length, -1)
        at_masked = logits[:, diagonal, diagonal, :]        # (B, L, V)

        # Negative log-likelihood of the key that actually occurred. Unlike a
        # top-g hit test this uses the whole distribution, so it degrades
        # gracefully when the baseline itself is high-entropy — which is exactly
        # the regime this data sits in.
        log_probs = at_masked.log_softmax(dim=-1)
        true_log_prob = log_probs.gather(-1, tokens.unsqueeze(-1)).squeeze(-1)
        nll = (-true_log_prob).masked_fill(~valid, 0.0)

        effective_g = min(top_g, at_masked.size(-1))
        top_ids = at_masked.topk(effective_g, dim=-1).indices
        hit = (top_ids == tokens.unsqueeze(-1)).any(dim=-1)

        return {"nll": nll, "misses": (~hit) & valid, "valid": valid}

    @torch.no_grad()
    def position_miss_mask(self, tokens: Tensor, *, top_g: int) -> tuple[Tensor, Tensor]:
        """For each real position, is the true key outside the top-``g``?

        Every position is masked in turn, because a model that can see the token
        it is predicting will simply copy it — self-attention makes the task
        trivial and the score meaningless.

        Done as one batched pass over ``B * L`` variants rather than a Python
        loop over positions: ``L`` is small and the GPU would otherwise sit idle
        between tiny forward passes.

        Returns ``(misses, valid)``, both ``(B, L)`` booleans.
        """
        surprise = self.position_surprise(tokens, top_g=top_g)
        return surprise["misses"], surprise["valid"]

    @torch.no_grad()
    def anomaly_scores(self, tokens: Tensor, *, top_g: int = 3) -> dict[str, Tensor]:
        """Per-sequence anomaly signals.

        Four, because they fail differently:

        * ``max_nll`` — the single most surprising position. This is the one
          that catches a *short* attack inside a long window: a two-event
          exfiltration chain is 12% of a 16-event window, so any averaged
          statistic dilutes it below threshold. Measured: mean-based scoring
          gave exfiltration recall 0.13.
        * ``mean_nll`` — sustained surprise across the window, which is what a
          40-event brute-force burst looks like.
        * ``miss_ratio`` — LogBERT's published top-``g`` rule, kept for
          comparison. Brittle here: with ~2 bits of irreducible entropy in the
          benign baseline, benign windows miss top-3 routinely.
        * ``sphere_distance`` — global novelty, independent of local transitions.
        """
        self.eval()
        surprise = self.position_surprise(tokens, top_g=top_g)
        nll, misses, valid = surprise["nll"], surprise["misses"], surprise["valid"]

        counts = valid.sum(dim=1).clamp(min=1)
        mean_nll = nll.sum(dim=1) / counts.float()
        # Padding is filled with -inf so it cannot win the max.
        max_nll = nll.masked_fill(~valid, float("-inf")).max(dim=1).values
        max_nll = torch.nan_to_num(max_nll, neginf=0.0)

        _, pooled = self.forward(tokens)
        sphere_distance = ((pooled - self.center) ** 2).sum(dim=1).sqrt()

        return {
            "max_nll": max_nll,
            "mean_nll": mean_nll,
            "miss_ratio": misses.sum(dim=1).float() / counts.float(),
            "sphere_distance": sphere_distance,
            "valid_positions": counts,
        }


def mask_tokens(
    tokens: Tensor,
    *,
    mask_probability: float,
    vocab_size: int,
    generator: torch.Generator | None = None,
) -> tuple[Tensor, Tensor]:
    """Build an MLM training batch.

    Follows BERT's 80/10/10 recipe: of the selected positions, 80% become
    ``[MASK]``, 10% become a random key, 10% are left alone. The corruption
    matters — training only on ``[MASK]`` leaves the model unprepared for
    inference inputs that contain no mask token at all, and the random
    replacements stop it assuming an unmasked token is always correct.

    Returns ``(corrupted_tokens, labels)`` where labels are ``-100`` (ignored by
    cross-entropy) everywhere except the selected positions.
    """
    device = tokens.device
    labels = tokens.clone()

    selectable = tokens != PAD_ID
    probability = torch.full(tokens.shape, mask_probability, device=device)
    probability[~selectable] = 0.0
    selected = torch.bernoulli(probability, generator=generator).bool()

    # A batch where nothing was selected produces a NaN loss; force one position.
    if not selected.any() and selectable.any():
        first = selectable.float().argmax(dim=1)
        selected[torch.arange(tokens.size(0), device=device), first] = selectable.any(dim=1)

    labels[~selected] = -100

    corrupted = tokens.clone()
    replace = torch.bernoulli(
        torch.full(tokens.shape, 0.8, device=device), generator=generator
    ).bool() & selected
    corrupted[replace] = MASK_ID

    randomise = (
        torch.bernoulli(torch.full(tokens.shape, 0.5, device=device), generator=generator).bool()
        & selected
        & ~replace
    )
    # Random replacements are drawn from real keys only — never from the
    # reserved PAD/UNK/MASK ids, which are not log types.
    random_ids = torch.randint(
        FIRST_FREE_ID, max(vocab_size, FIRST_FREE_ID + 1), tokens.shape,
        device=device, generator=generator,
    )
    corrupted[randomise] = random_ids[randomise]

    return corrupted, labels


def select_device(preference: str = "auto") -> torch.device:
    """Pick a compute device.

    MPS (Apple GPU) is checked before CUDA because this project is developed on
    Apple silicon; both fall back to CPU, which is entirely adequate for a model
    this size.
    """
    if preference != "auto":
        return torch.device(preference)
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def positional_capacity_check(config: ModelConfig, sequence_length: int) -> None:
    """Guard against a sequence longer than the position embedding table."""
    if sequence_length > config.max_sequence_length:
        raise ValueError(
            f"sequence length {sequence_length} exceeds model capacity "
            f"{config.max_sequence_length}; retrain with a larger "
            "max_sequence_length or shorten the window"
        )


__all__ = [
    "LogBERT",
    "ModelConfig",
    "count_parameters",
    "mask_tokens",
    "positional_capacity_check",
    "select_device",
]
