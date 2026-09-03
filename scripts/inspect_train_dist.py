import pandas as pd
df = pd.read_parquet('data/processed/sequences_train.parquet')
print(f"Train Shape: {df.shape}")
print(f"Columns: {len(df.columns)}")
print("\nClass Distribution:")
print(df['label'].value_counts())
