
- `pefile.py`: Contains the `PEfile` class which represents a PE file.
- `transformations.py`: Contains functions for data loading and preprocessing.
- `models.py`: Contains functions for model training, evaluation, and prediction.
- `main.py`: Main script to execute the workflow from data loading to model prediction.
- `16_Ransomware_Detection_Using_PE_Imports.csv`: The dataset used for training and testing the models.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your_username/dll_file_predictor.git
    cd dll_file_predictor
    ```

2. Create a virtual environment and activate it:

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
    ```

3. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Data Preprocessing

The `transformations.py` file contains functions to load and preprocess the data:

- `load_data(filepath: str) -> pd.DataFrame`: Load data from a CSV file.
- `encode_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, LabelEncoder]`: Encode labels using `LabelEncoder`.
- `create_feature_hasher(df: pd.DataFrame) -> pd.DataFrame`: Create hashed features using `FeatureHasher`.
- `group_data_by_hash(df: pd.DataFrame) -> pd.DataFrame`: Group functions and DLLs by SHA256 hash.
- `preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, LabelEncoder]`: Preprocess data by encoding labels and creating hashed features.

### Model Training and Evaluation

The `models.py` file contains functions for model training and evaluation:

- `train_model(model, X_train, y_train)`: Train the specified model.
- `plot_confusion_matrix(model, X_test, y_test, model_name)`: Plot confusion matrix for the specified model.
- `evaluate_models(models, X_train, X_test, y_train, y_test) -> dict`: Evaluate models based on F1 score.
- `tune_hyperparameters(model, param_grid, X_train, y_train, X_test, y_test) -> model`: Tune hyperparameters for the specified model.
- `calculate_scale_pos_ratio(y_train) -> float`: Calculate scale_pos_weight ratio.
- `format_predict_proba(probabilities) -> list`: Format predicted probabilities.
- `predict_proba_for_dlls(model, dll_list) -> list`: Predict probabilities for a given list of DLLs using the trained model.

### Main Script

The `main.py` file orchestrates the workflow:

1. Load and preprocess the data.
2. Split the data into training and test sets.
3. Initialize and evaluate models.
4. Tune hyperparameters for the best performing model.
5. Use the trained model to predict probabilities for a given list of DLLs.

### Running the Script

To run the main script:

```bash
python main.py


from pefile import PEfile
from models import predict_proba_for_dlls
from joblib import load

# Load the best model
best_model = load("model/best_model_rf.pkl")

# Create an example PEfile instance
example_pefile = PEfile("example_sha256", 0, ['function1_dll1', 'function2_dll2', 'function3_dll3'])

# Predict probabilities
probabilities = predict_proba_for_dlls(best_model, example_pefile.function_dlls)
print(f"Prediction probabilities for {example_pefile.sha256}: {probabilities}")

 ```


License
This project is licensed under the MIT License.

Acknowledgments
The dataset used in this project is 16_Ransomware_Detection_Using_PE_Imports.csv.
Libraries used include pandas, numpy, sklearn, xgboost, matplotlib, and joblib.
