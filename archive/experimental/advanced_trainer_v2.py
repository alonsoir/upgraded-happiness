import os
import argparse
import json
from collections import Counter

import joblib
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")


def load_config(config_path):
    with open(config_path, 'r') as f:
        return json.load(f)


def load_dataset(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found: {csv_path}")
    df = pd.read_csv(csv_path)
    return df


def preprocess(df, target_column):
    if target_column not in df.columns:
        raise ValueError(f"Target column '{target_column}' not found in dataset.")

    # Drop non-numeric or irrelevant columns (like IPs or timestamps, if any)
    df = df.select_dtypes(include=[np.number])
    df = df.dropna()

    X = df.drop(columns=[target_column])
    y = df[target_column].astype(int)
    return X, y


def balance_data(X, y):
    label_counts = Counter(y)
    if len(label_counts) <= 1:
        print(f"⚠️  Dataset has only one class ({list(label_counts.keys())[0]}). Skipping SMOTE.")
        return X, y
    smote = SMOTE(random_state=42)
    X_res, y_res = smote.fit_resample(X, y)
    print(f"✅ Applied SMOTE: Original samples = {len(y)}, Resampled = {len(y_res)}")
    return X_res, y_res


def train_random_forest(X_train, y_train, rf_params):
    clf = RandomForestClassifier(**rf_params)
    clf.fit(X_train, y_train)

    with open("models/feature_order.txt", "w") as f:
        f.write("\n".join(X_train.columns))

    return clf


def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    print("\n📊 Classification Report:\n")
    print(classification_report(y_test, y_pred))
    print("🧩 Confusion Matrix:\n")
    print(confusion_matrix(y_test, y_pred))


def main():
    parser = argparse.ArgumentParser(description="Train Random Forest on any labeled traffic dataset.")
    parser.add_argument('--input_csv', required=True, help='Path to the CSV dataset.')
    parser.add_argument('--output_model', required=True, help='Path to save the trained .joblib model.')
    parser.add_argument('--config_file', default='config/training_config.json', help='Training config JSON file.')

    args = parser.parse_args()
    config = load_config(args.config_file)

    dataset = load_dataset(args.input_csv)
    target_column = config.get("target_column", "label")

    print(f"📥 Loaded dataset: {args.input_csv} (shape={dataset.shape})")
    X, y = preprocess(dataset, target_column)
    print(f"✅ Preprocessed: X shape = {X.shape}, y shape = {y.shape}")

    if config.get("apply_smote", True):
        X, y = balance_data(X, y)
        print("🔁 Applied SMOTE for balancing.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=config.get("test_size", 0.25), random_state=42)

    model = train_random_forest(X_train, y_train, config.get("random_forest", {}))

    print(f"\n📈 Evaluating model '{args.output_model}'...")
    evaluate_model(model, X_test, y_test)

    joblib.dump(model, args.output_model)
    print(f"\n✅ Model saved to: {args.output_model}")


if __name__ == "__main__":
    main()
