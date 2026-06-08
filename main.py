import streamlit as st

st.title("RENDER Network Node Analyzer 🚀")
st.write("Привет! Это будущая платформа для анализа логов.")

# Тестовые поля для ручного ввода
st.subheader("Параметры ноды")
gpu_model = st.selectbox("Модель GPU", ["RTX 4090", "RTX 3080", "RTX 4080", "Другая"])
win_version = st.text_input("Версия Windows (например, 22H2)", "23H2")
driver_version = st.text_input("Версия драйвера Nvidia", "555.xx")

# Кнопка загрузки файла
st.subheader("Загрузка лога")
uploaded_file = st.file_uploader("Перетащите лог-файл ноды (.txt, .log)")

if uploaded_file is not None:
    st.success("Файл успешно загружен! Скоро здесь будет парсер.")
