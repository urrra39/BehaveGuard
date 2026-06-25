# BehaveGuard ML Models

BehaveGuard does not ship a fixed model of "bad." It learns a **per-process
baseline of normal** and flags deviation. The detection engine is an **ensemble**
of two complementary reconstruction models:

- an **LSTM sequence autoencoder** that learns the temporal *shape* of a
  process's behavior across consecutive windows, and
- a **Variational Autoencoder (VAE)** that learns the distribution of a single
  window's 427-dim feature vector.

Both are trained per process; both report a **reconstruction error** that is high
when input doesn't look like what they were trained on; and both are combined,
calibrated, and turned into a **0–100 anomaly score**.

Source: [`behaveguard/models/`](../behaveguard/models/) and
[`behaveguard/scoring/`](../behaveguard/scoring/). The model classes use
`torch`, imported lazily and confined to those modules; everything downstream
(scoring, thresholds-as-data, registry) is torch-free.

---

## 1. Why two models

| | LSTM autoencoder | VAE |
|---|---|---|
| Input | a **sequence** of window vectors `(T, 427)` | a **single** window vector `(427,)` |
| Learns | temporal dynamics — *order and rhythm* of behavior | the static distribution of a normal window |
| Catches | "this process never does X right after Y" | "this single window is off-manifold" |
| Signal | sequence reconstruction error | reconstruction error + KL term (ELBO) |

A point anomaly (one weird window) is caught best by the VAE; a contextual
anomaly (a normal-looking window in an abnormal sequence) is caught best by the
LSTM. The ensemble gets both.

---

## 2. LSTMDetector — sequence autoencoder

`models/lstm_detector.py` defines a **seq2seq LSTM autoencoder**:

- **Encoder.** An LSTM consumes the window sequence `(T, input_dim)` and
  compresses it into a fixed-size latent (the final hidden/cell state). `T` is
  the sequence length of recent windows; `input_dim` is
  `FeatureExtractor.NUM_FEATURES` (**427**, read dynamically so the model never
  hard-codes the feature count).
- **Decoder.** A second LSTM reconstructs the original sequence from the latent
  state.
- **Objective.** Mean reconstruction error (MSE) between the input sequence and
  its reconstruction. Trained only on *normal* sequences, the network learns to
  reconstruct normal behavior well and abnormal behavior poorly.
- **Score.** At inference, the per-sequence reconstruction error is the anomaly
  signal: low for in-distribution sequences, high for novel behavior.

This is what gives BehaveGuard its memory of *behavioral order*, e.g. an
exploitation chain where a server process execs `sh`, which execs `nc` — each
window may look individually plausible, but the sequence does not.

---

## 3. BehaviorAutoencoder — VAE over single windows

`models/autoencoder.py` defines a **Variational Autoencoder** over a single
427-dim feature vector:

- **Encoder → latent distribution.** The encoder maps the input to the parameters
  (μ, log σ²) of a Gaussian latent; a sample is drawn via the reparameterization
  trick.
- **Decoder → reconstruction.** The decoder maps the latent sample back to the
  427-dim space.
- **Objective (ELBO).** Reconstruction loss + a KL-divergence regularizer pulling
  the latent toward a standard normal. Training on normal windows shapes a latent
  manifold of normal behavior.
- **Score.** The reconstruction error (optionally combined with the KL term) for a
  new window is the anomaly signal — high when the window lies off the learned
  manifold.

Because it scores a single window, the VAE reacts immediately to a sharply
anomalous window without needing sequence context.

---

## 4. EnsembleDetector — weighted combination

`models/ensemble.py` combines the two model signals into a single number in
**0–100**:

- Each model's reconstruction error is normalized against its own training-time
  error distribution (so the LSTM's and VAE's errors are comparable).
- The normalized errors are combined with **configurable weights** into a unified
  ensemble score.
- The combined signal is mapped onto the **0–100** scale used everywhere
  downstream.

Weighting lets an operator bias toward sequence sensitivity (LSTM) or point
sensitivity (VAE) per environment. The ensemble is the single point that the
scorer consumes — the individual model outputs never leak past this layer.

---

## 5. Per-process model bundles

Detection is **per process**: `nginx` and `sshd` have entirely different normal
behavior, so each gets its own trained models. A bundle is persisted by
`models/model_store.py` under:

```
~/.behaveguard/models/<process>/
├── lstm.pt          # LSTM autoencoder weights (torch)
├── vae.pt           # VAE weights (torch)
├── normalizer.pkl   # feature normalization state
└── metadata.json    # input_dim, thresholds, training stats, versions
```

`metadata.json` records the calibrated thresholds and training statistics, so the
runtime can score without re-deriving them. The `ModelStore` handles save/load of
the bundle; `storage/model_registry.py` tracks which processes have models via an
atomic-JSON registry.

---

## 6. BaselineBuilder — training loop

`models/baseline_builder.py` drives training (invoked by `behaveguard train`):

1. **Collect.** Gather windows of *normal* behavior for a target process (the CLI
   supports `--duration N` minutes and `--process NAME`).
2. **Normalize.** Fit the feature normalizer on the collected windows.
3. **Fit.** Train the LSTM autoencoder on window *sequences* and the VAE on
   individual windows.
4. **Calibrate.** Compute the reconstruction-error distribution on held-out
   normal data and hand it to the `ThresholdTuner`.
5. **Persist.** Write the bundle (`lstm.pt`, `vae.pt`, `normalizer.pkl`,
   `metadata.json`) via `ModelStore` and register it.

Training assumes the observation period is representative of normal operation —
this is the standard contract of an anomaly-detection baseline.

---

## 7. ThresholdTuner — calibrated, FPR-bounded thresholds

`models/threshold_tuner.py` is **pure Python** (no torch) and turns raw
reconstruction errors into an actionable threshold:

- **Statistical threshold.** The base threshold is `mean + n·σ` of the normal-data
  error distribution. `n` controls strictness.
- **False-positive bound.** The threshold is additionally constrained to keep the
  empirical **false-positive rate** on normal data under a target — so raising
  sensitivity cannot silently flood operators with alerts.
- **Separability (ROC-AUC via Mann–Whitney).** When labeled abnormal samples are
  available, the tuner evaluates how well the score separates normal from
  abnormal using **ROC-AUC**, computed via the **Mann–Whitney U** statistic
  (AUC = U / (n₁·n₂)). This needs no numpy/torch and yields the rank-based area
  under the ROC curve directly from the two score populations.

The tuned threshold and its statistics are stored in the bundle's
`metadata.json`.

---

## 8. Calibrated anomaly scoring

The model layer produces an ensemble value; `scoring/anomaly_scorer.py` turns it
into the final `AnomalyScore` an operator acts on:

1. **Ensemble.** Start from the `EnsembleDetector` 0–100 output for the window.
2. **Per-PID sequence context.** Blend in the recent sequence history for that
   specific PID (so a single noisy window doesn't spike on its own and a
   sustained drift is reinforced).
3. **Known-safe-PID suppression.** PIDs on the whitelist (added via `behaveguard
   whitelist add`) are suppressed, eliminating expected-but-unusual behavior from
   trusted processes.
4. **Severity.** `scoring/severity.py` maps the final 0–100 score to **LOW /
   MEDIUM / HIGH / CRITICAL**.
5. **Explanation.** `scoring/explainer.py` produces a **SHAP-style**, salience-
   weighted attribution naming the top contributing features — and explicitly
   calls out the advanced **defense layers** (process injection, container
   escape, LOLBin, anti-forensic, DNS tunnel) when they drive the score, giving
   the operator a human-readable "why."

The result is an `AnomalyScore` (0–100) with a severity and an explanation,
handed to the alert pipeline. See [`api_reference.md`](api_reference.md) for how
scores and alerts are exposed, and
[`architecture.md`](architecture.md#4-the-427-dimension-feature-vector) for the
feature vector these models consume.
