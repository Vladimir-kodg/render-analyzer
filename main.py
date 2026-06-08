import os
# Отключаем защиту, которая вызывает ошибку 403 на Render.com
os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"
os.environ["STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION"] = "false"

import streamlit as st
import re
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

# --- ФУНКЦИИ ДЛЯ РАБОТЫ С БАЗОЙ ДАННЫХ ---
def get_db_connection():
    """Подключение к PostgreSQL через переменную окружения"""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        return None
    return psycopg2.connect(db_url)

def init_db():
    """Создание таблицы в базе данных, если её нет"""
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS render_errors (
                id SERIAL PRIMARY KEY,
                error_time TIMESTAMP,
                job_hash VARCHAR(50),
                gpu_model VARCHAR(100),
                driver_version VARCHAR(50),
                windows_version VARCHAR(50),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()

# Инициализируем базу данных при запуске приложения
try:
    init_db()
except Exception as e:
    st.error(f"Ошибка инициализации базы данных: {e}")

# --- ИНТЕРФЕЙС STREAMLIT ---
st.title("RENDER Network Node Analyzer 🚀")

# Создаем вкладки: одна для загрузки, вторая для общей аналитики
tab1, tab2 = st.tabs(["📥 Загрузка логов", "📊 Общая Аналитика"])

with tab1:
    st.subheader("1. Данные конфигурации ноды")
    col1, col2 = st.columns(2)
    with col1:
        gpu_model = st.selectbox("Модель GPU (основная)", ["RTX 5090", "RTX 4090", "RTX 3090", "RTX 4080", "RTX 3080", "Другая"])
        win_version = st.text_input("Версия Windows", "23H2")
    with col2:
        driver_version = st.text_input("Версия драйвера Nvidia", "555.xx")
        
    st.subheader("2. Загрузка лог-файла")
    uploaded_file = st.file_uploader("Перетащите файл лога (.txt, .log)", type=["txt", "log"])

    if uploaded_file is not None:
        log_content = uploaded_file.getvalue().decode("utf-8")
        st.info("Файл загружен. Анализируем...")

        failed_jobs = []
        job_fail_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) WARNING: \[\d+\] job failed with config hash: (\w+)"

        # Парсим лог построчно
        for line in log_content.split('\n'):
            match_job = re.search(job_fail_pattern, line)
            if match_job:
                failed_jobs.append({
                    "time": match_job.group(1),
                    "hash": match_job.group(2)
                })

        if failed_jobs:
            st.error(f"Внимание! Найдено сбоев джобов в этом логе: {len(failed_jobs)}")
            
            # Сохраняем найденные ошибки в базу данных
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                saved_count = 0
                for job in failed_jobs:
                    # Проверяем, нет ли уже этой ошибки в базе (чтобы не дублировать при повторной загрузке)
                    cursor.execute("""
                        SELECT id FROM render_errors 
                        WHERE error_time = %s AND job_hash = %s AND gpu_model = %s;
                    """, (job["time"], job["hash"], gpu_model))
                    
                    if not cursor.fetchone():
                        cursor.execute("""
                            INSERT INTO render_errors (error_time, job_hash, gpu_model, driver_version, windows_version)
                            VALUES (%s, %s, %s, %s, %s);
                        """, (job["time"], job["hash"], gpu_model, driver_version, win_version))
                        saved_count += 1
                
                conn.commit()
                cursor.close()
                conn.close()
                if saved_count > 0:
                    st.success(f"Успешно сохранено новых записей в базу данных: {saved_count}")
                else:
                    st.warning("Все эти ошибки уже были загружены ранее.")
            
            # Выводим таблицу текущего лога
            df_current = pd.DataFrame(failed_jobs)
            df_current.columns = ["Время ошибки", "Хэш Джоба"]
            st.dataframe(df_current, use_container_width=True)
        else:
            st.balloons()
            st.success("Критических падений джобов в данном логе не обнаружено!")

with tab2:
    st.subheader("Зависимости и закономерности (Все загруженные логи)")
    
    conn = get_db_connection()
    if conn:
        # Читаем ВСЕ данные из базы для построения графиков
        query = "SELECT error_time, job_hash, gpu_model, driver_version, windows_version FROM render_errors;"
        df_all = pd.read_sql(query, conn)
        conn.close()
        
        if not df_all.empty:
            st.write(f"Всего собранных записей об ошибках в базе: **{len(df_all)}**")
            
            # Таблица со всеми данными
            st.dataframe(df_all, use_container_width=True)
            
            # Простая визуализация средствами Streamlit
            st.write("### Количество ошибок по моделям GPU")
            gpu_counts = df_all["gpu_model"].value_counts()
            st.bar_chart(gpu_counts)
            
            st.write("### Количество ошибок по версиям Драйверов")
            driver_counts = df_all["driver_version"].value_counts()
            st.bar_chart(driver_counts)
            
        else:
            st.info("База данных пока пуста. Загрузите хотя бы один лог с ошибками во вкладке 'Загрузка логов'.")
    else:
        st.error("Не удалось подключиться к базе данных.")
