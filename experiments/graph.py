from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

INPUT_CSV = Path("experiments/results.csv")
OUTPUT_DIR = Path("experiments/graphs")
METRICS = ["roc_auc", "accuracy", "precision", "recall"]
ATTACK_LABELS = {
    "automated_bot_attack": "Automated Bot Attack",
    "business_logic_bypass": "Business Logic Bypass",
}


def _plot_by_axis(
    df: pd.DataFrame,
    *,
    x_col: str,
    fixed_cols: dict[str, float | int],
    metric: str,
    out_name: str,
    title: str,
) -> None:
    subset = df.copy()
    for col, value in fixed_cols.items():
        subset = subset[subset[col] == value]
    if subset.empty:
        return

    plt.figure(figsize=(8, 6))
    for attack, label in ATTACK_LABELS.items():
        attack_df = subset[subset["attack"] == attack].sort_values(x_col)
        if attack_df.empty:
            continue
        plt.plot(attack_df[x_col], attack_df[metric], marker="o", label=label)

    plt.title(title)
    plt.xlabel(x_col.replace("_", " ").title())
    plt.ylabel(metric.upper())
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / out_name)
    plt.close()


def main() -> None:
    df = pd.read_csv(INPUT_CSV)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    hidden_dims = sorted(df["hidden_dim"].unique())
    history_lengths = sorted(df["history_len"].unique())
    epochs_list = sorted(df["epochs"].unique())
    thresholds = sorted(df["threshold"].unique())

    for history_len in history_lengths:
        for epochs in epochs_list:
            for threshold in thresholds:
                for metric in METRICS:
                    _plot_by_axis(
                        df,
                        x_col="hidden_dim",
                        fixed_cols={"history_len": history_len, "epochs": epochs, "threshold": threshold},
                        metric=metric,
                        out_name=f"{metric}_by_hidden_hist{history_len}_ep{epochs}_thr{threshold}.png",
                        title=f"{metric.upper()} | history={history_len}, epochs={epochs}, threshold={threshold}",
                    )

    for hidden_dim in hidden_dims:
        for epochs in epochs_list:
            for threshold in thresholds:
                for metric in METRICS:
                    _plot_by_axis(
                        df,
                        x_col="history_len",
                        fixed_cols={"hidden_dim": hidden_dim, "epochs": epochs, "threshold": threshold},
                        metric=metric,
                        out_name=f"{metric}_by_history_hidden{hidden_dim}_ep{epochs}_thr{threshold}.png",
                        title=f"{metric.upper()} | hidden={hidden_dim}, epochs={epochs}, threshold={threshold}",
                    )

    for hidden_dim in hidden_dims:
        for history_len in history_lengths:
            for threshold in thresholds:
                for metric in METRICS:
                    _plot_by_axis(
                        df,
                        x_col="epochs",
                        fixed_cols={"hidden_dim": hidden_dim, "history_len": history_len, "threshold": threshold},
                        metric=metric,
                        out_name=f"{metric}_by_epochs_hidden{hidden_dim}_hist{history_len}_thr{threshold}.png",
                        title=f"{metric.upper()} | hidden={hidden_dim}, history={history_len}, threshold={threshold}",
                    )

    print(f"Saved graphs to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
