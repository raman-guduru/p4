#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import json
import os
import sys
from pandas import json_normalize # Helper for nested JSON

# --- Configuration ---
INPUT_FILE = "./reports/int_report.jsonl" # Path relative to the script location
OUTPUT_DIR = "./plots" # Directory to save plots

# --- Data Loading (Unchanged) ---
def load_data(filename=INPUT_FILE):
    """Loads data from the JSON Lines file into a Pandas DataFrame."""
    if not os.path.exists(filename):
        print(f"[ERROR] Input file not found: {filename}", file=sys.stderr)
        return None
    try:
        data = []
        with open(filename, 'r') as f:
            for i, line in enumerate(f):
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[WARN] Skipping malformed JSON on line {i+1}: {e}", file=sys.stderr)
        if not data:
            print("[WARN] No valid JSON data found in the file.", file=sys.stderr)
            return None

        df = pd.DataFrame(data)
        df['collector_datetime'] = pd.to_datetime(df['collector_timestamp_utc'], unit='s')
        df.set_index('collector_datetime', inplace=True)
        print(f"[*] Successfully loaded {len(df)} reports from {filename}")
        return df
    except Exception as e:
        print(f"[ERROR] Failed to load or process data from {filename}: {e}", file=sys.stderr)
        return None

# --- Data Processing ---
def process_hop_data(df):
    """Flattens the hop data into a plottable DataFrame."""
    if df is None or df.empty or 'hops' not in df.columns:
        print("[INFO] No hop data available for processing.")
        return None

    # Filter out rows where 'hops' is missing or not a list
    df_hops = df[df['hops'].apply(lambda x: isinstance(x, list) and len(x) > 0)].copy()
    if df_hops.empty:
        print("[INFO] No valid hop lists found in the data.")
        return None

    # Explode the list of hops into separate rows
    df_exploded = df_hops.explode('hops')

    # Normalize the hop dictionaries into columns, handling potential None values
    def safe_normalize(hop_dict):
        return hop_dict if isinstance(hop_dict, dict) else {}
    hops_normalized = json_normalize(df_exploded['hops'].apply(safe_normalize))
    hops_normalized.index = df_exploded.index # Align index with datetime

    # Combine normalized hop data with original index
    df_combined = pd.concat([df_exploded.drop(columns=['hops']), hops_normalized], axis=1)

    # Convert potential numeric columns, coercing errors to NaN
    numeric_cols = ['int_switch_id', 'int_hop_latency', 'q_occupancy',
                    'int_ingress_tstamp', 'int_egress_tstamp']
    for col in numeric_cols:
        if col in df_combined.columns:
            df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce')

    # Drop rows where essential data is missing (e.g., switch_id)
    df_combined.dropna(subset=['int_switch_id'], inplace=True)

    print(f"[*] Processed hop data into {len(df_combined)} rows.")
    return df_combined

# --- Plotting Functions ---
def plot_metric_per_switch(df_hops, metric_col, ylabel, title, filename):
    """Generic function to plot a specific metric per switch over time."""
    if df_hops is None or df_hops.empty or metric_col not in df_hops.columns:
        print(f"[INFO] Cannot plot '{title}'. Missing data or column '{metric_col}'.")
        return

    plt.figure(figsize=(12, 6))
    switches = df_hops['int_switch_id'].unique()

    # Drop rows where the specific metric is NaN for plotting
    df_plot = df_hops.dropna(subset=[metric_col])

    if df_plot.empty:
        print(f"[INFO] No valid data points found for metric '{metric_col}'. Cannot plot '{title}'.")
        return

    for switch_id in sorted(switches):
        # Ensure switch_id is not NaN before filtering
        if pd.isna(switch_id):
            continue
        switch_data = df_plot[df_plot['int_switch_id'] == switch_id]
        if not switch_data.empty:
            # Ensure index is sorted for correct line plotting
            switch_data = switch_data.sort_index()
            plt.plot(switch_data.index, switch_data[metric_col], marker='.', linestyle='-', markersize=4, label=f'Switch {int(switch_id)}')

    plt.xlabel("Time Reported by Collector")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=45)
    # Only show legend if there are multiple lines plotted
    if len(switches) > 1 and any(not df_plot[df_plot['int_switch_id'] == sw_id].empty for sw_id in switches if not pd.isna(sw_id)):
         plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename)
    print(f"[*] Plot saved to {filename}")
    plt.close() # Close the figure to free memory

# --- Main Execution ---
if __name__ == "__main__":
    print("[*] Loading INT report data...")
    main_df = load_data()

    if main_df is not None:
        print("[*] Processing hop data...")
        hop_df = process_hop_data(main_df)

        if hop_df is not None:
            print("[*] Generating plots...")
            os.makedirs(OUTPUT_DIR, exist_ok=True) # Ensure output directory exists

            # Plot Hop Latency
            plot_metric_per_switch(hop_df,
                                   metric_col='int_hop_latency',
                                   ylabel="Hop Latency (ns)",
                                   title="INT Hop Latency per Switch",
                                   filename=os.path.join(OUTPUT_DIR, "hop_latency_plot.png"))

            # Plot Queue Occupancy
            plot_metric_per_switch(hop_df,
                                   metric_col='q_occupancy',
                                   ylabel="Queue Occupancy",
                                   title="INT Queue Occupancy per Switch",
                                   filename=os.path.join(OUTPUT_DIR, "queue_occupancy_plot.png"))

            # Plot Ingress Timestamp
            plot_metric_per_switch(hop_df,
                                   metric_col='int_ingress_tstamp',
                                   ylabel="Ingress Timestamp (ns)",
                                   title="INT Ingress Timestamp per Switch",
                                   filename=os.path.join(OUTPUT_DIR, "ingress_tstamp_plot.png"))

            # Plot Egress Timestamp
            plot_metric_per_switch(hop_df,
                                   metric_col='int_egress_tstamp',
                                   ylabel="Egress Timestamp (ns)",
                                   title="INT Egress Timestamp per Switch",
                                   filename=os.path.join(OUTPUT_DIR, "egress_tstamp_plot.png"))

            print("[*] Plotting complete.")
        else:
            print("[!] No valid hop data processed. Skipping plotting.")
    else:
        print("[!] No data loaded. Exiting.")