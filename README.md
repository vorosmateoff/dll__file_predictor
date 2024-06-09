
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

You can run the `main.py` script from the command line and provide a JSON string as an argument. The JSON string should contain the SHA256 hash, label, and a list of function-DLL pairs for a PE file. Here's the format of the JSON string:

```json
{
  "sha256": "example_sha256",
  "label": 0,
  "function_dlls": ["function1_dll1", "function2_dll2", "function3_dll3"]
}
```
```bash
python main.py "{\"sha256\": \"example_sha256\", \"label\": 0, \"function_dlls\": [\"function1_dll1\", \"function2_dll2\", \"function3_dll3\"]}"
 ```


License
This project is licensed under the MIT License.

Acknowledgments
The dataset used in this project is 16_Ransomware_Detection_Using_PE_Imports.csv.
Libraries used include pandas, numpy, sklearn, xgboost, matplotlib, and joblib.
