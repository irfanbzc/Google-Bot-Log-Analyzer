import streamlit as st
import gzip
import re
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt

# Bilinen botlar
KNOWN_BOTS = {
    'Googlebot': re.compile(r'Googlebot', re.I),
    'Bingbot': re.compile(r'Bingbot', re.I),
    'YandexBot': re.compile(r'YandexBot', re.I),
    'AhrefsBot': re.compile(r'AhrefsBot', re.I),
    'SemrushBot': re.compile(r'SemrushBot', re.I),
    'Baiduspider': re.compile(r'Baiduspider', re.I),
    'MJ12bot': re.compile(r'MJ12bot', re.I),
}

def detect_bot(user_agent):
    for bot_name, pattern in KNOWN_BOTS.items():
        if pattern.search(user_agent):
            return bot_name
    return 'Other'

# Nginx/Apache combined log format regex parser
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d{3}) \d+ "-" "(?P<user_agent>[^"]+)"'
)

def parse_log_line(line):
    m = log_pattern.match(line)
    if not m:
        return None
    ip = m.group('ip')
    dt_str = m.group('datetime')
    url = m.group('url')
    status = int(m.group('status'))
    user_agent = m.group('user_agent')

    # Tarihi datetime objesine çevir
    try:
        dt = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S %z")
    except:
        return None

    bot = detect_bot(user_agent)

    return {
        'IP': ip,
        'URL': url,
        'Status': status,
        'Datetime': dt,
        'User-Agent': user_agent,
        'Bot': bot
    }

def load_log_file(file) -> pd.DataFrame:
    """
    .gz veya düz metin dosya olabilir
    """
    if file.name.endswith('.gz'):
        with gzip.open(file, 'rt', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    else:
        # .txt dosyası ise
        # streamlit file_uploader'dan gelen dosya bytes olabilir,
        # önce decode etmeliyiz
        content = file.getvalue()
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        lines = content.splitlines()

    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parsed = parse_log_line(line)
        if parsed:
            records.append(parsed)

    df = pd.DataFrame(records)
    return df

def main():
    st.title("🚀 Gelişmiş Bot & SEO Log Analizörü")
    st.markdown("""
    **Nginx/Apache erişim log dosyanızı yükleyin (txt veya gz).**  
    Bot ziyaretlerini, HTTP durum kodlarını ve SEO hatalarını analiz edin.
    """)

    uploaded_file = st.file_uploader("Log dosyanızı seçin (txt, gz)", type=['txt', 'gz'])
    if uploaded_file:
        try:
            df = load_log_file(uploaded_file)
        except Exception as e:
            st.error(f"Dosya okunurken hata oluştu: {e}")
            return

        if df.empty:
            st.warning("Yüklenen dosyada geçerli log verisi bulunamadı veya format uyumsuz.")
            return

        st.success(f"Log dosyası başarıyla yüklendi! Toplam {len(df)} kayıt.")

        # Genel özet
        st.subheader("📋 Genel Özet")
        st.write(f"Toplam Kayıt: {len(df)}")
        st.write(f"Tarayan Bot Türü Sayısı: {df['Bot'].nunique()}")
        st.write("En Çok Tarayan Botlar:")
        st.bar_chart(df['Bot'].value_counts())

        # Bot seçimi
        st.subheader("🔎 Botlara Göre Filtreleme")
        bots = ['All'] + sorted(df['Bot'].unique().tolist())
        selected_bot = st.selectbox("Bot Seçin:", bots)
        if selected_bot != 'All':
            df = df[df['Bot'] == selected_bot]

        # Durum kodu filtreleme
        st.subheader("🛑 HTTP Durum Kodlarına Göre Filtreleme")
        status_codes = sorted(df['Status'].unique().tolist())
        selected_status = st.multiselect("Durum Kodlarını Seçin:", options=status_codes, default=status_codes)
        df = df[df['Status'].isin(selected_status)]

        # Tarih aralığı
        st.subheader("📅 Tarih Aralığı Seçimi")
        min_date = df['Datetime'].min().date()
        max_date = df['Datetime'].max().date()
        selected_date = st.date_input("Tarih Aralığı:", value=(min_date, max_date))
        if isinstance(selected_date, tuple) and len(selected_date) == 2:
            start, end = selected_date
            df = df[(df['Datetime'].dt.date >= start) & (df['Datetime'].dt.date <= end)]

        # Filtrelenmiş tablo
        st.subheader(f"📊 Filtrelenmiş Kayıtlar ({len(df)})")
        st.dataframe(df[['Datetime', 'IP', 'URL', 'Status', 'Bot']].sort_values(by='Datetime', ascending=False))

        # SEO hata raporu
        st.subheader("🚨 SEO Hata Raporu")
        st.markdown("**En çok 404 (Sayfa Bulunamadı) hatası olan URL'ler:**")
        errors_404 = df[df['Status'] == 404]
        top_404 = errors_404['URL'].value_counts().head(10)
        if not top_404.empty:
            st.table(top_404)
        else:
            st.write("404 hatası bulunamadı.")

        st.markdown("**En çok 301 (Yönlendirme) durumu olan URL'ler:**")
        redirects_301 = df[df['Status'] == 301]
        top_301 = redirects_301['URL'].value_counts().head(10)
        if not top_301.empty:
            st.table(top_301)
        else:
            st.write("301 yönlendirme durumu bulunamadı.")

        # Günlük yoğunluk grafiği
        st.subheader("📈 Günlük Tarama Yoğunluğu (Seçilen Filtreye Göre)")
        daily_counts = df.groupby(df['Datetime'].dt.date).size()
        fig, ax = plt.subplots()
        daily_counts.plot(kind='bar', ax=ax, figsize=(10,4))
        ax.set_xlabel("Tarih")
        ax.set_ylabel("Ziyaret Sayısı")
        ax.set_title("Günlük Bot Ziyaretleri")
        st.pyplot(fig)

if __name__ == "__main__":
    main()
