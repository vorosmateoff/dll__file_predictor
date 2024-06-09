import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction import FeatureHasher
from pefile import PEfile
from typing import Tuple

def load_data(filepath: str = "data/16_Ransomware_Detection_Using_PE_Imports.csv")-> pd.DataFrame:
    """Load data from CSV file."""
    df = pd.read_csv(filepath, index_col=0)
    return df.dropna(axis=0)


def encode_labels(df) -> Tuple[pd.DataFrame, LabelEncoder]:
    """Encode labels using LabelEncoder."""
    label_encoder = LabelEncoder()
    df["label"] = label_encoder.fit_transform(df["label"])
    return df, label_encoder


def create_feature_hasher(pefiles)-> pd.DataFrame:
    """Create hashed features using FeatureHasher."""
    hashed_features = []
    hasher = FeatureHasher(n_features=1000, input_type="string")
    for pefile in pefiles:
        hashed_features.append(
            hasher.fit_transform([pefile.function_dlls])
            .toarray()
            .flatten()
            .astype(np.float32)
            .tolist()
        )
    hashed_df = pd.DataFrame(hashed_features)
    return hashed_df


def preprocess_data(df) -> Tuple[pd.DataFrame, LabelEncoder]:
    """Preprocess data: encode labels and create hashed features."""
    df["function_dll"] = df["function_name"] + "_" + df["dll"]
    df, label_encoder = encode_labels(df)
    df = (
        df.groupby("SHA256")
        .agg({"label": "first", "function_dll": lambda x: list(x)})
        .reset_index()
    )

    pefiles = PEfile.from_dataframe(df)
    hashed_df = create_feature_hasher(pefiles)
    result_df = pd.concat(
        [
            pd.DataFrame(
                [{"sha256": pefile.sha256, "label": pefile.label} for pefile in pefiles]
            ),
            hashed_df,
        ],
        axis=1,
    )
    result_df.columns = ["SHA256", "label"] + [f"feature_{i}" for i in range(1000)]
    return result_df, label_encoder
