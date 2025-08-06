import os

import matplotlib.pyplot as plt
import seaborn as sns
import json
import datetime
from sklearn.metrics import (
    confusion_matrix,
    roc_curve,
    auc,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

def timestamp():
    return datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

def save_feature_lists(general_features, selected_features, model_name):
    os.makedirs("training_reports", exist_ok=True)
    with open(f"training_reports/{model_name}_features.json", "w") as f:
        json.dump({
            "general_numeric_features": general_features,
            "selected_features": selected_features
        }, f, indent=4)

def save_metrics_report(report_text, model_name):
    os.makedirs("training_reports", exist_ok=True)
    report_path = f"training_reports/{model_name}_metrics.md"
    with open(report_path, "w") as f:
        f.write(report_text)

def plot_confusion_matrix(y_true, y_pred, model_name):
    cm = confusion_matrix(y_true, y_pred)
    labels = sorted(list(set(y_true)))
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.title(f"Matriz de Confusión - {model_name}")
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    os.makedirs("training_reports", exist_ok=True)
    path = f"training_reports/{model_name}_confusion_matrix.png"
    plt.savefig(path)
    plt.close()
    return path

def plot_roc_curve(y_true, y_prob, model_name):
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f"ROC curve (area = {roc_auc:.2f})")
    plt.plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"Curva ROC - {model_name}")
    plt.legend(loc="lower right")
    os.makedirs("training_reports", exist_ok=True)
    path = f"training_reports/{model_name}_roc_curve.png"
    plt.savefig(path)
    plt.close()
    return path
