from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

INPUT_CSV = Path("experiments/results.csv")
OUTPUT_DIR = Path("experiments/heatmaps")
ATTACK_LABELS = {
    "automated_bot_attack": "Automated Bot Attack",
    "business_logic_bypass": "Business Logic Bypass",
}


def main() -> None:
    df = pd.read_csv(INPUT_CSV)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for attack_key, attack_label in ATTACK_LABELS.items():
        attack_df = df[df["attack"] == attack_key].copy()
        if attack_df.empty:
            continue

        if attack_key == "automated_bot_attack":
            attack_df = attack_df[attack_df["history_len"] <= 10]

        best_by_pair = (
            attack_df.groupby(["hidden_dim", "history_len"], as_index=False)["roc_auc"]
            .max()
        )
        if best_by_pair.empty:
            continue

        pivot = best_by_pair.pivot(index="hidden_dim", columns="history_len", values="roc_auc")
        pivot = pivot.sort_index(ascending=True)

        plt.figure(figsize=(8, 6))
        ax = sns.heatmap(pivot, annot=True, fmt=".3f", cmap="viridis")
        ax.invert_yaxis()
        plt.title(attack_label)
        plt.xlabel("History Length")
        plt.ylabel("Hidden Dimension")
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / f"{attack_label.replace(' ', '_')}.png")
        plt.close()

    print(f"Saved heatmaps to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
