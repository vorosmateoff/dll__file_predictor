import pandas as pd
from transformations import load_data, preprocess_data
from models import (
    train_model,
    plot_confusion_matrix,
    evaluate_models,
    tune_hyperparameters,
    calculate_scale_pos_ratio,
    predict_proba_for_dlls,
)
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from pefile import PEfile
import joblib
import os
import numpy as np
import warnings
warnings.filterwarnings("ignore")

def process_df(
    filepath: str = "data/16_Ransomware_Detection_Using_PE_Imports.csv",
    retrain_base_model: bool = False,
    hyperparameter_tuning: bool = False,
):
    if retrain_base_model:
        try:
            df = load_data(filepath)
            # Preprocess dataa
            result_df, label_encoder = preprocess_data(df)

            # Split data into train and test sets
            X = result_df.drop(["SHA256", "label"], axis=1)
            y = result_df["label"]
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Initialize models
            models = {
                "RandomForestClassifier": RandomForestClassifier(random_state=42),
                "XGBClassifier": XGBClassifier(
                    random_state=42, scale_pos_weight=calculate_scale_pos_ratio(y_train)
                ),
            }

            # Evaluate models
            model_f1_scores = evaluate_models(models, X_train, X_test, y_train, y_test)

            # Tune hyperparameters for the best performing model
            best_model_name = max(model_f1_scores, key=model_f1_scores.get)
            best_model = models[best_model_name]
            return best_model
        except Exception as e:
            print(f"Error: {e}")
    if hyperparameter_tuning:
        try:
            param_grid = {
                "n_estimators": [50, 100, 150, 200],
                "max_depth": [None, 5, 10],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
            }

            # Tune hyperparameters
            best_model_tuned = tune_hyperparameters(
                best_model, param_grid, X_train, y_train, X_test, y_test
            )
            return best_model_tuned
        except Exception as e:
            print(f"Error: {e}")
    else:
        return None


def load_pretrained(model_path: str = "model/best_model_rf.pkl"):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}")
    else:
        print(f"Loading model from {model_path}")
        return joblib.load(model_path)


def main():
    best_model_tuned = process_df()
    best_model_tuned = load_pretrained()
    example_pefile = PEfile(
        "example_sha256", 0, ["function1_dll1", "function2_dll2", "function3_dll3"]
    )
    probabilities = predict_proba_for_dlls(
        best_model_tuned, example_pefile.function_dlls
    )
    print(f"Prediction probabilities for {example_pefile.sha256}: {probabilities}")


if __name__ == "__main__":
    main()
