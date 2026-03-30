from __future__ import annotations

import math
import random
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from torch.utils.data import DataLoader, TensorDataset

from data.csic_actions import make_action_token
from lstm_model import LSTM

DATA_PATH = Path("data/output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv")
DEFAULT_THRESHOLDS = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]


def load_sequences(history_len: int) -> list[tuple[list[str], str]]:
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df["action"] = df.apply(lambda row: make_action_token(row["method"], row["url"]), axis=1)

    actions = df["action"].tolist()
    sequences: list[tuple[list[str], str]] = []
    for idx in range(len(actions) - history_len):
        history = actions[idx : idx + history_len]
        target = actions[idx + history_len]
        sequences.append((history, target))
    return sequences


def train_and_prepare(
    *,
    hidden_dim: int = 32,
    epochs: int = 10,
    history_len: int = 5,
) -> tuple[LSTM, list[tuple[list[str], str]], dict[str, int]]:
    sequences = load_sequences(history_len)

    split_idx = int(len(sequences) * 0.7)
    train_sequences = sequences[:split_idx]
    test_sequences = sequences[split_idx:]

    all_actions: list[str] = []
    for history, target in train_sequences:
        all_actions.extend(history)
        all_actions.append(target)

    action_to_id = {action: idx for idx, action in enumerate(set(all_actions))}

    x_rows = []
    y_rows = []
    for history, target in train_sequences:
        try:
            x_rows.append([action_to_id[action] for action in history])
            y_rows.append(action_to_id[target])
        except KeyError:
            continue

    X = torch.tensor(x_rows, dtype=torch.long)
    y = torch.tensor(y_rows, dtype=torch.long)

    val_size = max(1, int(len(X) * 0.1))
    X_train, X_val = X[:-val_size], X[-val_size:]
    y_train, y_val = y[:-val_size], y[-val_size:]

    train_loader = DataLoader(TensorDataset(X_train, y_train), batch_size=128, shuffle=True)
    model = LSTM(len(action_to_id), hidden_dim=hidden_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss()

    best_val_loss = float("inf")
    best_state = None
    patience = 5
    patience_left = patience

    for _ in range(epochs):
        model.train()
        for xb, yb in train_loader:
            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_logits = model(X_val)
            val_loss = criterion(val_logits, y_val).item()

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = model.state_dict()
            patience_left = patience
        else:
            patience_left -= 1
            if patience_left == 0:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    model.eval()
    return model, test_sequences, action_to_id


def _score_sequence(
    model: LSTM,
    history: list[str],
    target: str,
    action_to_id: dict[str, int],
) -> float:
    try:
        x = torch.tensor([[action_to_id[action] for action in history]], dtype=torch.long)
        logits = model(x)
        probs = F.softmax(logits, dim=1)
        probability = probs[0, action_to_id[target]].item()
        return -math.log(probability + 1e-9)
    except KeyError:
        return 5.0


def _make_automated_bot_attack(history: list[str], target: str) -> tuple[list[str], str]:
    fake_history = history.copy()
    cycle = fake_history[-min(3, len(fake_history)) :]
    repeated: list[str] = []
    while len(repeated) < len(fake_history):
        for action in cycle:
            if len(repeated) < len(fake_history):
                repeated.append(action)
    return repeated, cycle[0]


def _make_business_logic_bypass(
    history: list[str],
    target: str,
    action_to_id: dict[str, int],
) -> tuple[list[str], str]:
    fake_target = target
    if any("LOGIN" in action for action in history):
        critical = [action for action in action_to_id if "DELETE" in action or "PAY" in action]
        if critical:
            fake_target = random.choice(critical)
    return history.copy(), fake_target


def evaluate_with_attack(
    model: LSTM,
    test_sequences: list[tuple[list[str], str]],
    action_to_id: dict[str, int],
    *,
    attack_type: str,
    thresholds: list[float] | None = None,
    normal_samples: int = 700,
    attack_samples: int = 700,
    noise_prob: float = 0.2,
) -> list[dict[str, float]]:
    if thresholds is None:
        thresholds = DEFAULT_THRESHOLDS

    normal_scores: list[float] = []
    attack_scores: list[float] = []

    sample_normal = random.sample(test_sequences, min(normal_samples, len(test_sequences)))
    sample_attack = random.sample(test_sequences, min(attack_samples, len(test_sequences)))

    for history, target in sample_normal:
        noisy_history = history.copy()
        for idx in range(len(noisy_history)):
            if random.random() < noise_prob:
                noisy_history[idx] = random.choice(list(action_to_id.keys()))
        normal_scores.append(_score_sequence(model, noisy_history, target, action_to_id))

    for history, target in sample_attack:
        if attack_type == "automated_bot_attack":
            fake_history, fake_target = _make_automated_bot_attack(history, target)
        elif attack_type == "business_logic_bypass":
            fake_history, fake_target = _make_business_logic_bypass(history, target, action_to_id)
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")
        attack_scores.append(_score_sequence(model, fake_history, fake_target, action_to_id))

    labels = [0] * len(normal_scores) + [1] * len(attack_scores)
    scores = normal_scores + attack_scores
    auc = roc_auc_score(labels, scores)

    rows: list[dict[str, float]] = []
    for threshold in thresholds:
        preds = [1 if score > threshold else 0 for score in scores]
        rows.append(
            {
                "threshold": threshold,
                "roc_auc": auc,
                "accuracy": accuracy_score(labels, preds),
                "precision": precision_score(labels, preds),
                "recall": recall_score(labels, preds),
            }
        )
    return rows
