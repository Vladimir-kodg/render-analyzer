import streamlit as st
import re
import pandas as pd

st.title("RENDER Network Node Analyzer 🚀")

# --- БЛОК 1: Ручной ввод данных ---
st.subheader("1. Данные конфигурации ноды")
col1, col2 = st.columns(2)
with col1:
    gpu_model = st.selectbox("Модель GPU (основная)", ["RTX 5090", "RTX 4090", "RTX 3090", "Другая"])
    win_version = st.text_input("Версия Windows", "23H2")
with col2:
    driver_version = st.text_input("Версия драйвера Nvidia", "555.xx")
    node_id = st.text_input("ID Ноды (опционально)", "Node-1")

# --- БЛОК 2: Загрузка и парсинг лога ---
st.subheader("2. Загрузка лог-файла")
uploaded_file = st.file_uploader("Перетащите файл лога (.txt, .log)")

if uploaded_file is not None:
    # Читаем содержимое файла как текст
    log_content = uploaded_file.getvalue().decode("utf-8")
    
    st.info("Файл загружен. Анализируем...")

    # Списки для сбора найденных данных
    failed_jobs = []
    detected_gpus = set() # Используем set, чтобы не дублировать названия карт

    # Регулярные выражения для поиска паттернов
    job_fail_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) WARNING: \[\d+\] job failed with config hash: (\w+)"
    gpu_pattern = r"octane gpu device \d+ \"([^\"]+)\""

    # Проходим по логу построчно
    for line in log_content.split('\n'):
        # 1. Ищем упавшие джобы
        match_job = re.search(job_fail_pattern, line)
        if match_job:
            timestamp = match_job.group(1)
            job_hash = match_job.group(2)
            failed_jobs.append({"Время": timestamp, "Хэш Джоба": job_hash, "Статус": "Ошибка"})
        
        # 2. Ищем модель GPU (если она есть в логе)
        match_gpu = re.search(gpu_pattern, line)
        if match_gpu:
            detected_gpus.add(match_gpu.group(1))

    # --- БЛОК 3: Вывод результатов анализа ---
    st.success("Анализ завершен!")

    # Показываем, что нашли по железу в логе
    if detected_gpus:
        st.write(f"**Обнаружено в логе GPU:** {', '.join(detected_gpus)}")
    else:
        st.write(f"**В логе не найдено строк инициализации GPU** (используем ручной ввод: {gpu_model})")

    # Показываем таблицу падений
    if failed_jobs:
        st.error(f"Внимание! Найдено сбоев джобов: {len(failed_jobs)}")
        df = pd.DataFrame(failed_jobs)
        st.dataframe(df, use_container_width=True)
    else:
        st.balloons()
        st.success("Критических падений джобов в данном логе не обнаружено!")
