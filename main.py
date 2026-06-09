import os
# Disable Streamlit CORS/XSRF protection
os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"
os.environ["STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION"] = "false"

import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

# --- DATABASE FUNCTIONS ---
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        return None
    return psycopg2.connect(db_url)

def init_db():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS render_errors_v3 (
                id SERIAL PRIMARY KEY,
                error_time TIMESTAMP,
                job_hash VARCHAR(50),
                gpu_model VARCHAR(100),
                gpu_count INT,
                driver_version VARCHAR(50),
                windows_version VARCHAR(50),
                node_id VARCHAR(100),
                file_name VARCHAR(255),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_logs_tracker (
                id SERIAL PRIMARY KEY,
                node_id VARCHAR(100),
                file_name VARCHAR(255),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(node_id, file_name)
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()

try:
    init_db()
except Exception as e:
    st.error(f"Database Initialization Error: {e}")

if "current_session_files" not in st.session_state:
    st.session_state["current_session_files"] = []

# --- MAIN INTERFACE ---
st.title("RENDER Network Node Analyzer v3 (Lite) 🚀")

tab1, tab2 = st.tabs(["📥 Upload Logs", "📊 Comparative Analytics"])

with tab1:
    st.subheader("🌐 Global System Statistics")
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT COUNT(*) as total_logs, COUNT(DISTINCT node_id) as total_nodes FROM uploaded_logs_tracker;")
        stats = cursor.fetchone()
        total_logs = stats['total_logs'] if stats else 0
        total_nodes = stats['total_nodes'] if stats else 0
        
        # Heavy query optimization - distinct configurations
        cursor.execute("SELECT DISTINCT gpu_model, gpu_count FROM render_errors_v3 LIMIT 20;")
        configs = cursor.fetchall()
        cursor.close()
        conn.close()
        
        st.info(f"System status: **{total_logs} log files** uploaded from **{total_nodes} unique nodes**.")
        
        if configs:
            config_list = [f"{c['gpu_count']}x {c['gpu_model']}" for c in configs]
            selected_config = st.selectbox(
                "🔍 Filter charts by hardware configuration:", 
                ["Show all configurations"] + config_list
            )
            st.session_state["selected_global_config"] = selected_config
    else:
        st.warning("Could not load global statistics.")

    st.markdown("---")

    st.subheader("1. Node Configuration")
    col1, col2, col3 = st.columns(3)
    with col1:
        node_id = st.text_input("Node ID", "Node_A").strip()
    with col2:
        driver_version = st.text_input("Nvidia Driver", "555.01").strip()
    with col3:
        win_version = st.text_input("Windows Version", "23H2").strip()
        
    st.subheader("2. Upload RNDR Log File")
    uploaded_file = st.file_uploader("Drag and drop your log file here (.txt, .log)", type=["txt", "log"])

    if uploaded_file is not None:
        file_name = uploaded_file.name
        file_size_mb = round(len(uploaded_file.getvalue()) / (1024 * 1024), 2)
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM uploaded_logs_tracker WHERE node_id = %s;", (node_id,))
            user_log_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT id FROM uploaded_logs_tracker WHERE node_id = %s AND file_name = %s;", (node_id, file_name))
            file_exists = cursor.fetchone()
            
            if user_log_count >= 4 and not file_exists:
                st.error(f"❌ Upload denied! Node '{node_id}' has reached the limit of 4 logs.")
                conn.close()
            else:
                # MEMORY FIX: Read file line by line without keeping full content in memory
                log_lines = uploaded_file.getvalue().decode("utf-8").splitlines()
                
                # Protect from giant files: analyze only last 30,000 lines
                if len(log_lines) > 30000:
                    log_lines = log_lines[-30000:]
                    st.warning("⚠️ Very large log file. Only the last 30,000 lines were processed to save server memory.")

                current_time = datetime(2026, 6, 9, 15, 30)
                two_weeks_ago = current_time - timedelta(days=14)

                failed_jobs = []
                detected_gpus = set()

                job_fail_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) WARNING: \[\d+\] job failed with config hash: (\w+)")
                gpu_pattern = re.compile(r"octane gpu device \d+ \"([^\"]+)\"")

                for line in log_lines:
                    match_gpu = gpu_pattern.search(line)
                    if match_gpu:
                        detected_gpus.add(match_gpu.group(1))

                    match_job = job_fail_pattern.search(line)
                    if match_job:
                        # Light date checking using string comparison (much faster than datetime parsing per line)
                        time_str = match_job.group(1)
                        if "2026-05-26" <= time_str <= "2026-06-09": # Strict 2 weeks string boundary
                            failed_jobs.append((time_str, match_job.group(2)))

                final_gpu_model = list(detected_gpus)[0] if detected_gpus else "Unknown GPU"
                final_gpu_count = len(detected_gpus) if detected_gpus else 1

                if failed_jobs:
                    if not file_exists:
                        cursor.execute("INSERT INTO uploaded_logs_tracker (node_id, file_name) VALUES (%s, %s);", (node_id, file_name))
                    
                    saved_count = 0
                    # Batch insert optimization
                    for t_str, j_hash in failed_jobs:
                        cursor.execute("""
                            SELECT id FROM render_errors_v3 
                            WHERE error_time = %s AND job_hash = %s AND node_id = %s;
                        """, (t_str, j_hash, node_id))
                        
                        if not cursor.fetchone():
                            cursor.execute("""
                                INSERT INTO render_errors_v3 (error_time, job_hash, gpu_model, gpu_count, driver_version, windows_version, node_id, file_name)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                            """, (t_str, j_hash, final_gpu_model, final_gpu_count, driver_version, win_version, node_id, file_name))
                            saved_count += 1
                    
                    conn.commit()
                    
                    session_item = {"name": file_name, "size": f"{file_size_mb} MB", "errors": len(failed_jobs)}
                    if session_item not in st.session_state["current_session_files"]:
                        st.session_state["current_session_files"].append(session_item)
                        
                    st.success(f"🤖 Detected: **{final_gpu_count}x {final_gpu_model}**")
                    st.success(f"Log processed! Added {saved_count} new entries to database.")
                    
                    # Memory optimization: show preview list instead of heavy pandas dataframe
                    st.write("📋 **Recent errors preview (Top 5):**")
                    for t_str, j_hash in failed_jobs[:5]:
                        st.text(f"[{t_str}] Hash: {j_hash}")
                else:
                    st.success("Perfect! No critical job failures found in this timeframe.")
                    
            if conn:
                cursor.close()
                conn.close()

    if st.session_state["current_session_files"]:
        st.write("### 📄 Your Uploaded Files in This Session:")
        for idx, file_info in enumerate(st.session_state["current_session_files"], 1):
            st.markdown(f"**{idx}. {file_info['name']}** ({file_info['size']}) — *Errors: {file_info['errors']}*")

with tab2:
    st.subheader("📊 Cross-Node Error Intersection & Comparison")
    
    conn = get_db_connection()
    if conn:
        # MEMORY FIX: Only pull necessary data and limit total records for visualization
        query = "SELECT error_time, job_hash, node_id, gpu_model, gpu_count FROM render_errors_v3 ORDER BY error_time DESC LIMIT 5000;"
        df_all = pd.read_sql(query, conn)
        conn.close()
        
        if not df_all.empty:
            df_all["error_time"] = pd.to_datetime(df_all["error_time"])
            
            selected_filter = st.session_state.get("selected_global_config", "Show all configurations")
            if selected_filter != "Show all configurations":
                df_all["config_string"] = df_all["gpu_count"].astype(str) + "x " + df_all["gpu_model"]
                df_all = df_all[df_all["config_string"] == selected_filter]

            if not df_all.empty:
                min_date = df_all["error_time"].min().date()
                max_date = df_all["error_time"].max().date()
                if min_date == max_date:
                    min_date = min_date - timedelta(days=1)
                    
                start_date, end_date = st.date_input("Filter Analytics by Date Range", [min_date, max_date])
                
                df_analysis = df_all[
                    (df_all["error_time"].dt.date >= start_date) & 
                    (df_all["error_time"].dt.date <= end_date)
                ]
                
                if not df_analysis.empty:
                    # Optimize chart preparation by limiting to top 30 most frequent error hashes
                    top_hashes = df_analysis["job_hash"].value_counts().head(30).index
                    df_analysis = df_analysis[df_analysis["job_hash"].isin(top_hashes)]
                    
                    hash_node_counts = df_analysis.groupby("job_hash")["node_id"].nunique()
                    
                    df_analysis["Failure Type"] = df_analysis["job_hash"].apply(
                        lambda x: "Shared across nodes (Systemic)" if hash_node_counts[x] > 1 else "Unique to this node (Hardware/Local)"
                    )
                    
                    chart_data = df_analysis.groupby(["job_hash", "Failure Type"]).size().reset_index(name="Count")
                    pivot_df = chart_data.pivot(index="job_hash", columns="Failure Type", values="Count").fillna(0)
                    
                    st.write("### Error Distribution Graph (Top 30 frequent errors)")
                    
                    available_colors = []
                    if "Shared across nodes (Systemic)" in pivot_df.columns:
                        available_colors.append("#1f77b4")
                    if "Unique to this node (Hardware/Local)" in pivot_df.columns:
                        available_colors.append("#d62728")
                        
                    st.bar_chart(pivot_df, color=available_colors)
                    
                    st.write("📋 **Filtered Data Details (Showing last 100 entries to prevent memory crash):**")
                    st.dataframe(df_analysis[["error_time", "job_hash", "node_id", "gpu_model", "Failure Type"]].head(100), use_container_width=True)
                else:
                    st.warning("No data found for the selected date range.")
            else:
                st.warning("No global data matches the selected hardware configuration filter.")
        else:
            st.info("The database is currently empty. Upload logs to generate analytics.")
