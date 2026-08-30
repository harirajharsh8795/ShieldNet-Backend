import pyarrow.parquet as pq
import pyarrow as pa
import pandas as pd
import os

input_path = "data/processed/fused_flow_packet_v1.parquet"
output_config_a = "data/processed/fused_matched_v1.parquet"
output_config_b = "data/processed/flow_only_full.parquet"

packet_cols = [
    "session_group", "five_tuple_key", "is_packet_matched", 
    "ttl_mean", "ttl_variance", "tcp_window_mean", 
    "tcp_window_min", "tcp_window_max", "ip_fragment_flag_present", 
    "retransmission_count"
]

print("Opening fused parquet dataset...")
pf = pq.ParquetFile(input_path)
all_cols = pf.schema.names
flow_cols = [c for c in all_cols if c not in packet_cols]

print(f"Total columns in input: {len(all_cols)}")
print(f"Total flow-only columns: {len(flow_cols)}")

print("\nProcessing Config A (fused_matched_v1.parquet) and Config B (flow_only_full.parquet)...")

# We can read in row groups or batches to be completely memory safe
writer_a = None
writer_b = None

total_rows = 0
matched_rows = 0

config_a_label_counts = {}
config_b_label_counts = {}

# Use batches
for batch in pf.iter_batches(batch_size=200_000):
    df_batch = batch.to_pandas()
    total_rows += len(df_batch)
    
    # Config B: all rows, flow-only cols
    df_b = df_batch[flow_cols]
    table_b = pa.Table.from_pandas(df_b, preserve_index=False)
    if writer_b is None:
        writer_b = pq.ParquetWriter(output_config_b, table_b.schema, compression="snappy")
    writer_b.write_table(table_b)
    
    # Accumulate Config B counts
    for lbl, count in df_b["Label"].value_counts().items():
        config_b_label_counts[lbl] = config_b_label_counts.get(lbl, 0) + count
        
    # Config A: matched only, all cols
    df_a = df_batch[df_batch["is_packet_matched"] == True]
    matched_rows += len(df_a)
    if len(df_a) > 0:
        table_a = pa.Table.from_pandas(df_a, preserve_index=False)
        if writer_a is None:
            writer_a = pq.ParquetWriter(output_config_a, table_a.schema, compression="snappy")
        writer_a.write_table(table_a)
        
        # Accumulate Config A counts
        for lbl, count in df_a["Label"].value_counts().items():
            config_a_label_counts[lbl] = config_a_label_counts.get(lbl, 0) + count

if writer_a:
    writer_a.close()
if writer_b:
    writer_b.close()

print(f"\nFinished exporting configs!")
print(f"Config A rows: {matched_rows:,} -> {output_config_a}")
print(f"Config B rows: {total_rows:,} -> {output_config_b}")

# Format distribution tables
df_dist_b = pd.DataFrame(list(config_b_label_counts.items()), columns=["Label", "Count_B"]).sort_values(by="Count_B", ascending=False)
df_dist_b["Pct_B"] = (df_dist_b["Count_B"] / total_rows) * 100

df_dist_a = pd.DataFrame(list(config_a_label_counts.items()), columns=["Label", "Count_A"]).sort_values(by="Count_A", ascending=False)
df_dist_a["Pct_A"] = (df_dist_a["Count_A"] / matched_rows) * 100

df_merged = pd.merge(df_dist_b, df_dist_a, on="Label", how="outer").fillna(0)
df_merged["Match_Rate_Pct"] = (df_merged["Count_A"] / df_merged["Count_B"]) * 100

print("\n=== CLASS DISTRIBUTION SUMMARY ===")
print(df_merged.to_string(index=False))

# Save distribution summary to a CSV/text file for reporting
df_merged.to_csv("data/processed/config_distributions.csv", index=False)
