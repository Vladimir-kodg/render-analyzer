import os
# Disable Streamlit CORS/XSRF protection for Render.com stability
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
        # Table for storing errors
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
        # Table for tracking unique logs per node (to enforce the 4-logs limit)
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

# --- APP SESSION STATE FOR CURRENT UPLOADS ---
if "current_session_files" not in st.session_state:
    st.session_state["current_session_files"] = []

# --- MAIN INTERFACE (ENGLISH) ---
st.title("RENDER Network Node Analyzer v3 🚀")

tab1, tab2 = st.tabs(["📥 Upload Logs", "📊 Comparative Analytics"])

with tab1:
    # --- GLOBAL STATS SECTION ---
    st.subheader("🌐 Global System Statistics")
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get total logs and unique nodes
        cursor.execute("SELECT COUNT(*) as total_logs, COUNT(DISTINCT node_id) as total_nodes FROM uploaded_logs_tracker;")
        stats = cursor.fetchone()
        total_logs = stats['total_logs'] if stats else 0
        total_nodes = stats['total_nodes'] if stats else 0
        
        # Get available configurations for the dropdown
        cursor.execute("""
            SELECT DISTINCT gpu_model, gpu_count 
            FROM render_errors_v3 
            ORDER BY gpu_model;
        """)
        configs = cursor.fetchall()
        cursor.close()
        conn.close()
        
        st.info(f"Currently, the system has **{total_logs} log files** uploaded from **{total_nodes} unique nodes**.")
        
        if configs:
            config_list = [f"{c['gpu_count']}x {c['gpu_model']}" for c in configs]
            selected_config = st.selectbox(
                "🔍 Select a node configuration to compare with your own:", 
                ["Show all configurations"] + config_list
            )
            # Store selection in session state to filter in Tab 2
            st.session_state["selected_global_config"] = selected_config
    else:
        st.warning("Could not load global statistics (DB connection failed).")

    st.markdown("---")

    # --- INPUT ENVIRONMENT ---
    st.subheader("1. Node Configuration (Manual Input)")
    col1, col2, col3 = st.columns(3)
    with col1:
        node_id = st.text_input("Node ID (e.g., MyAwesomeNode)", "Node_A").strip()
    with col2:
        driver_version = st.text_input("Nvidia Driver Version", "555.01").strip()
    with col3:
        win_version = st.text_input("Windows Version", "23H2").strip()
        
    # --- LOG UPLOADER ---
    st.subheader("2. Upload RNDR Log File")
    uploaded_file = st.file_uploader("Drag and drop your log file here (.txt, .log)", type=["txt", "log"])

    if uploaded_file is not None:
        file_name = uploaded_file.name
        file_size_mb = round(len(uploaded_file.getvalue()) / (1024 * 1024), 2)
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            
            # Check how many logs this Node ID has already uploaded
            cursor.execute("SELECT COUNT(*) FROM uploaded_logs_tracker WHERE node_id = %s;", (node_id,))
            user_log_count = cursor.fetchone()[0]
            
            # Check if THIS specific file is already uploaded by this node
            cursor.execute("SELECT id FROM uploaded_logs_tracker WHERE node_id = %s AND file_name = %s;", (node_id, file_name))
            file_exists = cursor.fetchone()
            
            if user_log_count >= 4 and not file_exists:
                st.error(f"❌ Upload denied! Node '{node_id}' has reached the limit of **4 log files maximum**.")
                conn.close()
            else:
                # Process the file
                log_content = uploaded_file.getvalue().decode("utf-8")
                
                # Fixed time frame logic (2 weeks ago from June 2026)
                current_time = datetime(2026, 6, 9, 15, 30)
                two_weeks_ago = current_time - timedelta(days=14)

                failed_jobs = []
                detected_gpus = set()

                job_fail_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) WARNING: \[\d+\] job failed with config hash: (\w+)"
                gpu_pattern = r"octane gpu device \d+ \"([^\"]+)\""

                for line in log_content.split('\n'):
                    match_gpu = re.search(gpu_pattern, line)
                    if match_gpu:
                        detected_gpus.add(match_gpu.group(1))

                    match_job = re.search(job_fail_pattern, line)
                    if match_job:
                        failed_jobs.append({
                            "time_str": match_job.group(1),
                            "hash": match_job.group(2)
                        })

                final_gpu_model = list(detected_gpus)[0] if detected_gpus else "Unknown GPU"
                final_gpu_count = len(detected_gpus) if detected_gpus else 1

                if failed_jobs:
                    df_raw = pd.DataFrame(failed_jobs)
                    df_raw["time"] = pd.to_datetime(df_raw["time_str"])
                    
                    # Filter: Last 14 days
                    df_filtered = df_raw[(df_raw["time"] >= two_weeks_ago) & (df_raw["time"] <= current_time)]
                    
                    if not df_filtered.empty:
                        # Register log tracker if new
                        if not file_exists:
                            cursor.execute("""
                                INSERT INTO uploaded_logs_tracker (node_id, file_name) 
                                VALUES (%s, %s);
                            """, (node_id, file_name))
                        
                        # Insert errors
                        saved_count = 0
                        for _, row in df_filtered.iterrows():
                            cursor.execute("""
                                SELECT id FROM render_errors_v3 
                                WHERE error_time = %s AND job_hash = %s AND node_id = %s;
                            """, (row["time"], row["hash"], node_id))
                            
                            if not cursor.fetchone():
                                cursor.execute("""
                                    INSERT INTO render_errors_v3 (error_time, job_hash, gpu_model, gpu_count, driver_version, windows_version, node_id, file_name)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                                """, (row["time"], row["hash"], final_gpu_model, final_gpu_count, driver_version, win_version, node_id, file_name))
                                saved_count += 1
                        
                        conn.commit()
                        
                        # Add to current session list view if not already there
                        session_item = {"name": file_name, "size": f"{file_size_mb} MB", "errors": len(df_filtered)}
                        if session_item not in st.session_state["current_session_files"]:
                            st.session_state["current_session_files"].append(session_item)
                            
                        st.success(f"🤖 Hardware detected: **{final_gpu_count}x {final_gpu_model}**")
                        st.success(f"Successfully processed log! Saved {saved_count} new errors to global database.")
                    else:
                        st.warning("Log uploaded, but it contains no errors within the last 14 days.")
                else:
                    st.balloons()
                    st.success("Perfect! No critical job failures found in this log.")
                    
            if conn:
                cursor.close()
                conn.close()

    # --- CURRENT SESSION UPLOADED FILES LIST ---
    if st.session_state["current_session_files"]:
        st.write("### 📄 Your Uploaded Files in This Session:")
        for idx, file_info in enumerate(st.session_state["current_session_files"], 1):
            st.markdown(f"**{idx}. {file_info['name']}** ({file_info['size']}) — *Detected errors: {file_info['errors']}*")

with tab2:
    st.subheader("📊 Cross-Node Error Intersection & Comparison")
    
    conn = get_db_connection()
    if conn:
        query = "SELECT error_time, job_hash, node_id, gpu_model, gpu_count FROM render_errors_v3;"
        df_all = pd.read_sql(query, conn)
        conn.close()
        
        if not df_all.empty:
            df_all["error_time"] = pd.to_datetime(df_all["error_time"])
            
            # Apply global dropdown filter from Tab 1 if selected
            selected_filter = st.session_state.get("selected_global_config", "Show all configurations")
            if selected_filter != "Show all configurations":
                df_all["config_string"] = df_all["gpu_count"].astype(str) + "x " + df_all["gpu_model"]
                df_all = df_all[df_all["config_string"] == selected_filter]

            if not df_all.empty:
                # Date Range Filter
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
                    # Logic for Blue (Shared) / Red (Unique) failure types
                    hash_node_counts = df_analysis.groupby("job_hash")["node_id"].nunique()
                    
                    df_analysis["Failure Type"] = df_analysis["job_hash"].apply(
                        lambda x: "Shared across nodes (Systemic)" if hash_node_counts[x] > 1 else "Unique to this node (Hardware/Local)"
                    )
                    
                    chart_data = df_analysis.groupby(["job_hash", "Failure Type"]).size().reset_index(name="Count")
                    pivot_df = chart_data.pivot(index="job_hash", columns="Failure Type", values="Count").fillna(0)
                    
                    st.write("### Error Distribution Graph")
                    st.bar_chart(pivot_df, color=["#1f77b4", "#d62728"]) # Blue and Red colors
                    
                    st.write("📋 Filtered Data Details:")
                    st.dataframe(df_analysis[["error_time", "job_hash", "node_id", "gpu_model", "Failure Type"]], use_container_width=True)
                else:
                    st.warning("No data found for the selected date range.")
            else:
                st.warning("No global data matches the selected hardware configuration filter.")
        else:
            st.info("The database is currently empty. Upload logs to generate analytics.")
