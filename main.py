import os
# Отключаем защиту, которая вызывает ошибку 403 на Render.com
os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"
os.environ["STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION"] = "false"

import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta
import psycopg2

# --- ФУНКЦИИ БАЗЫ ДАННЫХ ---
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
            CREATE TABLE IF NOT EXISTS render_errors_v2 (
                id SERIAL PRIMARY KEY,
                error_time TIMESTAMP,
                job_hash VARCHAR(50),
                gpu_model VARCHAR(100),
                gpu_count INT,
                driver_version VARCHAR(50),
                windows_version VARCHAR(50),
                node_id VARCHAR(100),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()

try:
    init_db()
except Exception as e:
    st.error(f"Ошибка БД: {e}")

# --- ИНТЕРФЕЙС ---
st.title("RENDER Network Node Analyzer v2 🚀")

tab1, tab2 = st.tabs(["📥 Загрузка логов", "📊 Сравнительная Аналитика"])

with tab1:
    st.subheader("1. Окружение ноды (заполняется вручную)")
    col1, col2, col3 = st.columns(3)
    with col1:
        node_id = st.text_input("ID Ноды (например, Node_A)", "Node_A")
    with col2:
        driver_version = st.text_input("Версия драйвера Nvidia", "555.01")
    with col3:
        win_version = st.text_input("Версия Windows", "23H2")
        
    st.subheader("2. Загрузка лог-файла")
    uploaded_file = st.file_uploader("Перетащите файл лога (.txt, .log)", type=["txt", "log"])

    if uploaded_file is not None:
        log_content = uploaded_file.getvalue().decode("utf-8")
        st.info("Файл загружен. Анализируем...")

        # Временные рамки: 2 недели назад от текущего момента (июнь 2026)
        current_time = datetime(2026, 6, 8, 13, 0) # Фиксируем текущее время системы
        two_weeks_ago = current_time - timedelta(days=14)

        failed_jobs = []
        detected_gpus = set()

        # Регулярные выражения
        job_fail_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) WARNING: \[\d+\] job failed with config hash: (\w+)"
        gpu_pattern = r"octane gpu device \d+ \"([^\"]+)\""

        # Парсинг
        for line in log_content.split('\n'):
            # Ищем GPU
            match_gpu = re.search(gpu_pattern, line)
            if match_gpu:
                detected_gpus.add(match_gpu.group(1))

            # Ищем ошибки
            match_job = re.search(job_fail_pattern, line)
            if match_job:
                err_time = datetime.strptime(match_job.group(1), "%Y-%m-%d %H:%M:%S") # Ошибка парсинга исправлена в логике ниже
                # Для стабильности используем строку, но проверим дату встроенным методом pandas позже
                failed_jobs.append({
                    "time_str": match_job.group(1),
                    "hash": match_job.group(2)
                })

        # Определяем модель и количество GPU
        final_gpu_model = list(detected_gpus)[0] if detected_gpus else "Неизвестная GPU"
        final_gpu_count = len(detected_gpus) if detected_gpus else 1

        st.success(f"🤖 Авто-определение железа: Найдено GPU: **{final_gpu_model}** в количестве **{final_gpu_count} шт.**")

        if failed_jobs:
            # Создаем DataFrame и фильтруем по дате (в пределах 2 недель)
            df_raw = pd.DataFrame(failed_jobs)
            df_raw["time"] = pd.to_datetime(df_raw["time_str"])
            
            # Фильтр 14 дней
            df_filtered = df_raw[(df_raw["time"] >= two_weeks_ago) & (df_raw["time"] <= current_time)]
            
            st.write(f"Найдено ошибок за последние 2 недели: **{len(df_filtered)}** (пропущено старых: {len(df_raw) - len(df_filtered)})")

            if not df_filtered.empty:
                # Сохраняем в базу данных
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    saved_count = 0
                    for _, row in df_filtered.iterrows():
                        cursor.execute("""
                            SELECT id FROM render_errors_v2 
                            WHERE error_time = %s AND job_hash = %s AND node_id = %s;
                        """, (row["time"], row["hash"], node_id))
                        
                        if not cursor.fetchone():
                            cursor.execute("""
                                INSERT INTO render_errors_v2 (error_time, job_hash, gpu_model, gpu_count, driver_version, windows_version, node_id)
                                VALUES (%s, %s, %s, %s, %s, %s, %s);
                            """, (row["time"], row["hash"], final_gpu_model, final_gpu_count, driver_version, win_version, node_id))
                            saved_count += 1
                    conn.commit()
                    cursor.close()
                    conn.close()
                    st.success(f"Сохранено новых записей в базу: {saved_count}")
                
                st.dataframe(df_filtered[["time", "hash"]], use_container_width=True)

with tab2:
    st.subheader("📊 Анализ пересечения ошибок между нодами")
    
    conn = get_db_connection()
    if conn:
        query = "SELECT error_time, job_hash, node_id, gpu_model FROM render_errors_v2;"
        df_all = pd.read_sql(query, conn)
        conn.close()
        
        if not df_all.empty:
            df_all["error_time"] = pd.to_datetime(df_all["error_time"])
            
            # --- ИНТЕРАКТИВНЫЙ ФИЛЬТР ДАТ ---
            min_date = df_all["error_time"].min().date()
            max_date = df_all["error_time"].max().date()
            
            if min_date == max_date:
                min_date = min_date - timedelta(days=1)
                
            st.write("### Выберите диапазон анализа:")
            start_date, end_date = st.date_input("Диапазон дат", [min_date, max_date])
            
            # Применяем фильтр дат пользователя
            df_analysis = df_all[
                (df_all["error_time"].dt.date >= start_date) & 
                (df_all["error_time"].dt.date <= end_date)
            ]
            
            if not df_analysis.empty:
                # Считаем, сколько уникальных нод поймали каждую ошибку (хэш)
                # Если у ошибки > 1 уникальной ноды -> она повторяется на разных нодах
                hash_node_counts = df_analysis.groupby("job_hash")["node_id"].nunique()
                
                # Функция определения цвета/категории
                def выявить_тип_сбоя(job_hash):
                    return "Повторяется на нодах (Системная)" if hash_node_counts[job_hash] > 1 else "Уникальная для ноды (Локальная)"

                df_analysis["Тип сбоя"] = df_analysis["job_hash"].apply(выявить_тип_сбоя)
                
                # Группируем для графика
                chart_data = df_analysis.groupby(["job_hash", "Тип сбоя"]).size().reset_index(name="Количество")
                
                # Строим красивый график средствами Streamlit
                st.write("### Визуализация структуры ошибок")
                
                # Цветовая кодировка через сводную таблицу
                pivot_df = chart_data.pivot(index="job_hash", columns="Тип сбоя", values="Количество").fillna(0)
                
                # Выводим цветной график
                st.bar_chart(pivot_df, color=["#1f77b4", "#d62728"]) # Синий для системных, Красный для локальных
                
                st.write("📋 Детализация отфильтрованных данных:")
                st.dataframe(df_analysis[["error_time", "job_hash", "node_id", "gpu_model", "Тип сбоя"]], use_container_width=True)
            else:
                st.warning("В выбранном диапазоне дат нет данных.")
        else:
            st.info("База данных пока пуста. Загрузите логи во вкладке 'Загрузка логов'.")
