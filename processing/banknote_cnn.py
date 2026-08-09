"""
CNN-based banknote security-feature analysis.

IMPORTANT — read this before trusting any output from this module in production:

There is no public dataset of genuine vs. counterfeit Canadian bank notes to train on.
That's not an oversight here — it's true generally, for the obvious reason that a labeled
counterfeit-detection dataset is itself a target for counterfeiters, so the RCMP/Bank of
Canada don't publish one. Public research datasets exist for other currencies (Jordanian,
Bangladeshi, Indian/Thai banknotes — see e.g. the "JaalTaka" and "NoteShieldBD" Kaggle sets),
but nothing for CAD.

So what's actually implemented here:
  - A real, trainable CNN architecture (`BanknoteCNN`) sized for this task: binary
    genuine/counterfeit classification plus a multi-label head for 5 security-feature
    regions (raised ink, colour-shift ink, transparent window, metallic portrait, hologram
    stripe — the features actually present on Bank of Canada polymer notes).
  - `generate_synthetic_demo_dataset()`, which renders simple synthetic note-like images
    with procedurally-placed "security features" so the full train -> infer pipeline can
    run end-to-end and be demonstrated without real data.
  - `train()` / `analyze_banknote()` that work against either the synthetic set or a real
    `ImageFolder`-style directory (`real/`, `counterfeit/` subfolders) if you point it at one.

Treat any confidence score from a synthetic-trained model as a pipeline smoke test, not a
real fraud signal. Production use requires a real labeled image dataset — realistically
obtained via a partnership with RCMP/Bank of Canada forensic services, not scraped.
"""
import random
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from PIL import Image, ImageDraw
from loguru import logger
from config import cfg

CFG = cfg["counterfeit"]["cnn"]
IMG_SIZE = CFG["image_size"]
FEATURES = CFG["security_features"]
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


class BanknoteCNN(nn.Module):
    """Small conv net: shared trunk, two heads (genuine/counterfeit + per-feature presence)."""

    def __init__(self, num_features: int = len(FEATURES)):
        super().__init__()
        self.trunk = nn.Sequential(
            nn.Conv2d(3, 16, 3, padding=1), nn.BatchNorm2d(16), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 3, padding=1), nn.BatchNorm2d(32), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.BatchNorm2d(64), nn.ReLU(), nn.MaxPool2d(2),
            nn.AdaptiveAvgPool2d(4),
        )
        flat = 64 * 4 * 4
        self.classifier = nn.Sequential(nn.Linear(flat, 64), nn.ReLU(), nn.Linear(64, 1))
        self.feature_head = nn.Sequential(nn.Linear(flat, 64), nn.ReLU(), nn.Linear(64, num_features))

    def forward(self, x):
        z = self.trunk(x).flatten(1)
        return self.classifier(z).squeeze(-1), self.feature_head(z)


class BanknoteDataset(Dataset):
    """Expects `root/real/*.png` and `root/counterfeit/*.png`. Feature labels are read from a
    sidecar `<image>.features.txt` (one feature name per line) if present, else all-zero."""

    def __init__(self, root: str):
        self.root = Path(root)
        self.samples = []
        for label, subdir in ((0, "real"), (1, "counterfeit")):
            for p in sorted((self.root / subdir).glob("*.png")):
                self.samples.append((p, label))
        if not self.samples:
            raise FileNotFoundError(f"No images found under {root}/real or {root}/counterfeit")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        img = Image.open(path).convert("RGB").resize((IMG_SIZE, IMG_SIZE))
        arr = torch.tensor(np.array(img), dtype=torch.float32).permute(2, 0, 1) / 255.0

        feat_path = path.with_suffix(".features.txt")
        present = set(feat_path.read_text().split()) if feat_path.exists() else set()
        feat_labels = torch.tensor([1.0 if f in present else 0.0 for f in FEATURES])

        return arr, torch.tensor(float(label)), feat_labels


# ── Synthetic demo data (NOT real currency imagery) ─────────────────────────

def generate_synthetic_demo_dataset(out_dir: str | None = None, n_samples: int | None = None) -> str:
    """Render simple procedural rectangles standing in for "notes": genuine ones get all 5
    security-feature marks drawn in consistent positions; counterfeits get 0-3 of them
    randomly missing/shifted, mimicking the actual failure mode a security-feature classifier
    is trained to catch. This is synthetic geometry, not real banknote imagery."""
    out_dir = out_dir or CFG["synthetic_demo_dir"]
    n_samples = n_samples or CFG["demo_train_samples"]
    root = Path(out_dir)
    (root / "real").mkdir(parents=True, exist_ok=True)
    (root / "counterfeit").mkdir(parents=True, exist_ok=True)

    rng = random.Random(42)
    feature_positions = {
        feat: (rng.randint(10, IMG_SIZE - 30), rng.randint(10, IMG_SIZE - 30))
        for feat in FEATURES
    }

    for i in range(n_samples):
        is_counterfeit = i % 2 == 1
        img = Image.new("RGB", (IMG_SIZE, IMG_SIZE), color=(rng.randint(180, 220), rng.randint(180, 220), rng.randint(150, 190)))
        draw = ImageDraw.Draw(img)
        present_features = []
        for feat in FEATURES:
            skip = is_counterfeit and rng.random() < 0.5
            if skip:
                continue
            x, y = feature_positions[feat]
            if is_counterfeit:
                x, y = x + rng.randint(-8, 8), y + rng.randint(-8, 8)  # feature drift
            color = (rng.randint(0, 80), rng.randint(0, 80), rng.randint(0, 80))
            draw.ellipse([x, y, x + 18, y + 18], outline=color, width=3)
            present_features.append(feat)

        label_dir = "counterfeit" if is_counterfeit else "real"
        path = root / label_dir / f"{label_dir}_{i:04d}.png"
        img.save(path)
        path.with_suffix(".features.txt").write_text("\n".join(present_features))

    logger.info(f"Synthetic demo dataset written to {root} ({n_samples} images)")
    return str(root)


# ── Train / infer ────────────────────────────────────────────────────────────

def train(data_dir: str, epochs: int | None = None, model_path: str | None = None) -> BanknoteCNN:
    epochs = epochs or CFG["demo_epochs"]
    model_path = model_path or CFG["model_path"]

    ds = BanknoteDataset(data_dir)
    loader = DataLoader(ds, batch_size=16, shuffle=True)

    model = BanknoteCNN().to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    cls_loss_fn = nn.BCEWithLogitsLoss()
    feat_loss_fn = nn.BCEWithLogitsLoss()

    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for x, y, feat_y in loader:
            x, y, feat_y = x.to(DEVICE), y.to(DEVICE), feat_y.to(DEVICE)
            opt.zero_grad()
            logits, feat_logits = model(x)
            loss = cls_loss_fn(logits, y) + feat_loss_fn(feat_logits, feat_y)
            loss.backward()
            opt.step()
            total_loss += loss.item() * x.size(0)
        logger.info(f"[banknote_cnn] epoch {epoch + 1}/{epochs} loss={total_loss / len(ds):.4f}")

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), model_path)
    logger.info(f"Saved model to {model_path}")
    return model


_model_cache: BanknoteCNN | None = None


def load_model(model_path: str | None = None) -> BanknoteCNN | None:
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    model_path = model_path or CFG["model_path"]
    if not Path(model_path).exists():
        return None
    model = BanknoteCNN().to(DEVICE)
    model.load_state_dict(torch.load(model_path, map_location=DEVICE))
    model.eval()
    _model_cache = model
    return model


def analyze_banknote(image_path: str, model: BanknoteCNN | None = None) -> dict:
    """Run inference on a single image. Returns predicted label, confidence, and a
    per-security-feature presence score in [0, 1]."""
    model = model or load_model()
    if model is None:
        raise RuntimeError(
            "No trained model found. Run processing.banknote_cnn.train() first "
            "(see main.py's counterfeit pipeline for the synthetic-demo bootstrap)."
        )
    model.eval()
    img = Image.open(image_path).convert("RGB").resize((IMG_SIZE, IMG_SIZE))
    arr = torch.tensor(np.array(img), dtype=torch.float32).permute(2, 0, 1).unsqueeze(0) / 255.0
    arr = arr.to(DEVICE)

    with torch.no_grad():
        logit, feat_logits = model(arr)
        prob_counterfeit = torch.sigmoid(logit).item()
        feat_scores = torch.sigmoid(feat_logits).squeeze(0).tolist()

    return {
        "image_path": image_path,
        "predicted_label": "counterfeit" if prob_counterfeit >= 0.5 else "genuine",
        "confidence": prob_counterfeit if prob_counterfeit >= 0.5 else 1 - prob_counterfeit,
        "security_features": dict(zip(FEATURES, feat_scores)),
    }
