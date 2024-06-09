from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, f1_score
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt
from sklearn.feature_extraction import FeatureHasher
import pandas as pd
import numpy as np

def train_model(model, X_train, y_train) -> None:
    """Train the specified model."""
    model.fit(X_train, y_train)


def plot_confusion_matrix(model, X_test, y_test, model_name)-> None:
    """Plot confusion matrix for the specified model."""
    predictions = model.predict(X_test)
    cm = confusion_matrix(y_test, predictions)

    # Specify display labels
    display_labels = ["B", "M"]

    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
    disp.plot(cmap=plt.cm.Blues)
    plt.title(f"Confusion Matrix - {model_name}")
    plt.show()


def evaluate_models(models, X_train, X_test, y_train, y_test)-> dict:
    """Evaluate models based on F1 score."""
    model_f1_scores = {}
    for model_name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        f1 = f1_score(y_test, predictions)
        model_f1_scores[model_name] = f1
        print(f"{model_name} F1 Score: {f1}")
        # Plot confusion matrix
        plot_confusion_matrix(model, X_test, y_test, model_name)
    return model_f1_scores


def tune_hyperparameters(model, param_grid, X_train, y_train, X_test, y_test):
    """Tune hyperparameters for the specified model."""
    grid_search = GridSearchCV(
        estimator=model, param_grid=param_grid, scoring="f1", cv=5
    )
    grid_search.fit(X_train, y_train)
    best_hyperparameters = grid_search.best_params_
    best_model_tuned = grid_search.best_estimator_
    predictions_tuned = best_model_tuned.predict(X_test)
    f1_tuned = f1_score(y_test, predictions_tuned)
    print(f"Tuned {model.__class__.__name__} F1 Score: {f1_tuned}")
    plot_confusion_matrix(
        best_model_tuned, X_test, y_test, f"Tuned {model.__class__.__name__}"
    )
    return best_model_tuned


def calculate_scale_pos_ratio(y_train:pd.Series)->float:
    """Calculate scale_pos_weight ratio."""
    class_counts = y_train.value_counts()
    return class_counts[0] / class_counts[1]


def format_predict_proba(probabilities:np.ndarray,threshold:float=0.5)-> list:
    """Format predicted probabilities."""
    probabilities = probabilities.flatten().astype(np.float32).tolist()
    print(f"File is mostly: {'Malicious' if probabilities[1] > threshold else 'Benign'}")
    return [round(probability, 4) for probability in probabilities]

def predict_proba_for_dlls(model, dll_list:list=[])-> list:
    """Predict probabilities for a given list of DLLs using the trained model."""
    # Create a dataframe with the input data
    input_df = pd.DataFrame({"function_dll": [dll_list]})

    # Hash the input features
    hashed_features = []
    hasher = FeatureHasher(n_features=1000, input_type="string")
    hashed_features.append(
        hasher.fit_transform([dll_list]).toarray().flatten().astype(np.float32).tolist()
    )
    hashed_df = pd.DataFrame(hashed_features)

    # Predict probabilities
    probabilities = model.predict_proba(hashed_df)

    return format_predict_proba(probabilities[0])
