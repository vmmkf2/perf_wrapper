from perfetto.trace_processor import TraceProcessor
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
 
def query_counters_with_sum(trace_file, window_ms=1000):
    """Query Perfetto counters and SUM all values within each window"""
    
    tp = TraceProcessor(trace=trace_file)
    
    # SQL query to SUM counter values per window
    query = f"""
    WITH counter_data AS (
        SELECT 
            c.ts,
            CAST((c.ts - (SELECT MIN(ts) FROM counter)) / 1000000 AS INTEGER) / {window_ms} AS window_id,
            t.name as counter_name,
            c.value as value
        FROM counter c
        JOIN counter_track t ON c.track_id = t.id
        WHERE t.name IN (
            'cpu-cycles', 'CPU_CYCLES',
            'inst_retired', 'INST_RETIRED',
            'inst_spec', 'INST_SPEC',
            'stall_frontend', 'STALL_FRONTEND',
            'stall_backend', 'STALL_BACKEND',
            'br_mis_pred', 'BR_MIS_PRED'
        )
    ),
    window_sums AS (
        SELECT 
            window_id,
            window_id * {window_ms} as time_ms,
            counter_name,
            -- SUM all counter values within this window
            SUM(value) as sum_value
        FROM counter_data
        GROUP BY window_id, counter_name
    )
    SELECT 
        window_id,
        time_ms,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%cycles%' THEN sum_value END), 0) as cpu_cycles,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%inst_retired%' THEN sum_value END), 0) as inst_retired,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%inst_spec%' THEN sum_value END), 0) as inst_spec,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%stall_frontend%' THEN sum_value END), 0) as stall_frontend,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%stall_backend%' THEN sum_value END), 0) as stall_backend,
        COALESCE(MAX(CASE WHEN LOWER(counter_name) LIKE '%br_mis_pred%' THEN sum_value END), 0) as br_mis_pred
    FROM window_sums
    GROUP BY window_id, time_ms
    HAVING cpu_cycles > 0  -- Filter out empty windows
    ORDER BY window_id
    """
    
    df = tp.query(query).as_pandas_dataframe()
    
    print(f"Loaded {len(df)} time windows")
    print(f"Summed counter values per window:")
    print(df.head())
    
    return df
 
def calculate_topdown_metrics(df, slots_per_cycle=4):
    """
    Calculate 4 topdown metrics for each window:
    1. Retiring
    2. Bad Speculation
    3. Frontend Bound
    4. Backend Bound
    """
    
    # Total slots available in each window
    df['total_slots'] = df['cpu_cycles'] * slots_per_cycle
    
    # Metric 1: Retiring (% of slots used for retired operations)
    df['Retiring'] = (df['inst_retired'] / df['total_slots'] * 100).fillna(0)
    
    # Metric 2: Bad Speculation (% of slots used for non-retired speculative operations)
    if 'inst_spec' in df.columns and df['inst_spec'].sum() > 0:
        # If we have inst_spec, calculate precisely
        df['Bad_Speculation'] = ((df['inst_spec'] - df['inst_retired']) / df['total_slots'] * 100).fillna(0)
    else:
        # Estimate from branch mispredictions (14 cycle penalty)
        df['Bad_Speculation'] = ((df['br_mis_pred'] * 14 * slots_per_cycle) / df['total_slots'] * 100).fillna(0)
    
    # Metric 3: Frontend Bound (% of cycles stalled in frontend)
    # stall_frontend is in cycles, need to convert to slot percentage
    df['Frontend_Bound'] = (df['stall_frontend'] / df['cpu_cycles'] * 100).fillna(0)
    
    # Metric 4: Backend Bound (% of cycles stalled in backend)
    # stall_backend is in cycles, need to convert to slot percentage
    df['Backend_Bound'] = (df['stall_backend'] / df['cpu_cycles'] * 100).fillna(0)
    
    # Ensure non-negative values
    df['Retiring'] = df['Retiring'].clip(lower=0)
    df['Bad_Speculation'] = df['Bad_Speculation'].clip(lower=0)
    df['Frontend_Bound'] = df['Frontend_Bound'].clip(lower=0)
    df['Backend_Bound'] = df['Backend_Bound'].clip(lower=0)
    
    # Normalize to 100% (all 4 metrics should sum to 100%)
    df['total_pct'] = df['Retiring'] + df['Bad_Speculation'] + df['Frontend_Bound'] + df['Backend_Bound']
    
    # Only normalize if total > 0
    mask = df['total_pct'] > 0
    df.loc[mask, 'Retiring'] = (df.loc[mask, 'Retiring'] / df.loc[mask, 'total_pct'] * 100)
    df.loc[mask, 'Bad_Speculation'] = (df.loc[mask, 'Bad_Speculation'] / df.loc[mask, 'total_pct'] * 100)
    df.loc[mask, 'Frontend_Bound'] = (df.loc[mask, 'Frontend_Bound'] / df.loc[mask, 'total_pct'] * 100)
    df.loc[mask, 'Backend_Bound'] = (df.loc[mask, 'Backend_Bound'] / df.loc[mask, 'total_pct'] * 100)
    
    return df
 
def plot_topdown_100_stacked(df, output_file='topdown_stacked.png'):
    """Create 100% stacked bar chart"""
    
    if len(df) == 0:
        print("No data to plot!")
        return
    
    # Prepare data
    x_pos = np.arange(len(df))
    width = 0.9
    
    retiring = df['Retiring'].values
    bad_spec = df['Bad_Speculation'].values
    backend = df['Backend_Bound'].values
    frontend = df['Frontend_Bound'].values
    
    # Colors matching standard topdown visualization
    colors = {
        'Retiring': '#4472C4',        # Blue
        'Bad_Speculation': '#ED7D31',  # Orange
        'Backend_Bound': '#A5A5A5',    # Gray
        'Frontend_Bound': "#A1DB0F"    # Yellow
    }
    
    # Create figure
    fig, ax = plt.subplots(figsize=(16, 6))
    
    # Create stacked bars
    p1 = ax.bar(x_pos, retiring, width, label='Retiring', 
                color=colors['Retiring'], edgecolor='white', linewidth=0.5)
    p2 = ax.bar(x_pos, bad_spec, width, bottom=retiring,
                label='Bad Speculation', color=colors['Bad_Speculation'],
                edgecolor='white', linewidth=0.5)
    p3 = ax.bar(x_pos, backend, width, bottom=retiring + bad_spec,
                label='Backend Bound', color=colors['Backend_Bound'],
                edgecolor='white', linewidth=0.5)
    p4 = ax.bar(x_pos, frontend, width, bottom=retiring + bad_spec + backend,
                label='Frontend Bound', color=colors['Frontend_Bound'],
                edgecolor='white', linewidth=0.5)
    
    # Customize plot
    ax.set_ylabel('Execution Bandwidth (%)', fontsize=13, fontweight='bold')
    ax.set_xlabel('Time Window', fontsize=13, fontweight='bold')
    ax.set_title('Topdown Microarchitecture Analysis - 100% Stacked View', 
                 fontsize=15, fontweight='bold', pad=20)
    ax.set_ylim(0, 100)
    
    # Add legend
    ax.legend(loc='upper right', frameon=True, fontsize=11, 
              shadow=True, fancybox=True)
    
    # Grid
    ax.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.7)
    ax.set_axisbelow(True)
    
    # X-axis labels (show time in seconds)
    time_windows = df['time_ms'].values
    label_frequency = max(1, len(time_windows) // 20)
    
    x_labels = []
    for idx, tw in enumerate(time_windows):
        if idx % label_frequency == 0:
            x_labels.append(f'{tw/1000:.1f}s')
        else:
            x_labels.append('')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(x_labels, rotation=45, ha='right', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"\nChart saved to {output_file}")
    plt.show()
 
def main(trace_file, window_ms=1000, slots_per_cycle=4):
    """Main function to process trace and create visualization"""
    
    print(f"Processing Perfetto trace: {trace_file}")
    print(f"Time window: {window_ms}ms")
    print(f"CPU slots per cycle: {slots_per_cycle}\n")
    
    # Step 1: Query and sum counters per window
    df = query_counters_with_sum(trace_file, window_ms=window_ms)
    
    # Step 2: Calculate 4 topdown metrics for each window
    df = calculate_topdown_metrics(df, slots_per_cycle=slots_per_cycle)
    
    # Step 3: Display summary
    print(f"\nCalculated topdown metrics for {len(df)} windows")
    print("\nTopdown Metrics Summary:")
    print(df[['Retiring', 'Bad_Speculation', 'Frontend_Bound', 'Backend_Bound']].describe())
    
    print("\nFirst 10 windows:")
    print(df[['time_ms', 'cpu_cycles', 'inst_retired', 'Retiring', 'Bad_Speculation', 
              'Frontend_Bound', 'Backend_Bound']].head(10))
    
    # Step 4: Save to CSV
    df.to_csv('topdown_metrics_per_window.csv', index=False)
    print("\nDetailed metrics saved to topdown_metrics_per_window.csv")
    
    # Step 5: Create 100% stacked bar chart
    plot_topdown_100_stacked(df, output_file='topdown_stacked.png')
 
# Usage example
if __name__ == "__main__":
    TRACE_FILE = 'trace.perfetto'
    WINDOW_MS = 1000    # 1000ms windows
    SLOTS_PER_CYCLE = 4 
    
    main(TRACE_FILE, WINDOW_MS, SLOTS_PER_CYCLE)