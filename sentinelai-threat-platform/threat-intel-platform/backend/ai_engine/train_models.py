"""
train_models.py
-----------------
Run this script directly to (re)train both AI models from scratch and
save them to ai_engine/trained_models/*.pkl

    cd backend
    python ai_engine/train_models.py

This is OPTIONAL - app.py automatically trains the models on first run
if the .pkl files do not exist yet. You only need to run this manually
if you want to retrain (e.g. after changing the training data or
feature engineering).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engine.url_classifier import train_url_model
from ai_engine.text_classifier import train_text_model


def main():
    print("=" * 60)
    print("Training SentinelAI ML models")
    print("=" * 60)

    print("\n[1/2] Training URL / IOC maliciousness classifier...")
    train_url_model()

    print("\n[2/2] Training threat description text classifier...")
    train_text_model()

    print("\nDone. Models saved to ai_engine/trained_models/")


if __name__ == "__main__":
    main()
