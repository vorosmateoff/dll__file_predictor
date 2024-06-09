class PEfile:
    def __init__(self, sha256, label, function_dlls):
        self.sha256 = sha256
        self.label = label
        self.function_dlls = function_dlls

    @classmethod
    def from_dataframe(cls, df):
        """Create PEfile instances from DataFrame."""
        return [
            cls(row["SHA256"], row["label"], row["function_dll"])
            for _, row in df.iterrows()
        ]
