from pathlib import Path

def save_alerts(df, out_dir: str, base_name: str):
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_path = out_path / f"{base_name}.csv"
    json_path = out_path / f"{base_name}.json"

    df.to_csv(csv_path, index=False)
    df.to_json(
        json_path,
        orient="records",
        indent=2,
        date_format="iso"
    )

    return str(csv_path), str(json_path)
