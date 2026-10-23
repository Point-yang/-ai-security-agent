"""Explicit download of the local embedding model; API requests stay offline."""

from zhidu.config import Settings
from zhidu.semantic import prepare_model

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path")
    args = parser.parse_args()
    print(json.dumps(prepare_model(Settings(), args.model_path), indent=2))
