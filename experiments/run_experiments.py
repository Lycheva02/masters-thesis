from __future__ import annotations

from pathlib import Path

import pandas as pd

from data.train_lstm import DEFAULT_THRESHOLDS, evaluate_with_attack, train_and_prepare

HIDDEN_DIMS = [16, 32, 64, 128]
HISTORY_LENGTHS = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
EPOCHS_LIST = [60]
ATTACK_TYPES = ["business_logic_bypass", "automated_bot_attack"]
OUTPUT_CSV = Path("experiments/results.csv")


def main() -> None:
    rows: list[dict[str, float | int | str]] = []

    for hidden_dim in HIDDEN_DIMS:
        for history_len in HISTORY_LENGTHS:
            for epochs in EPOCHS_LIST:
                model, test_sequences, action_to_id = train_and_prepare(
                    hidden_dim=hidden_dim,
                    history_len=history_len,
                    epochs=epochs,
                )

                for attack in ATTACK_TYPES:
                    metrics = evaluate_with_attack(
                        model,
                        test_sequences,
                        action_to_id,
                        attack_type=attack,
                        thresholds=DEFAULT_THRESHOLDS,
                    )
                    for item in metrics:
                        rows.append(
                            {
                                "attack": attack,
                                "hidden_dim": hidden_dim,
                                "history_len": history_len,
                                "epochs": epochs,
                                **item,
                            }
                        )

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(OUTPUT_CSV, index=False)
    print(f"Saved results to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
