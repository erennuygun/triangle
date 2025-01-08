# Triangle Code Analyzer

<div align="center">
    <img src="static/logo.png" alt="Triangle Code Analyzer Logo" width="200"/>
    <h3>Güvenli Kod Analizi ve Zafiyet Tarama Aracı</h3>
</div>

## 🔍 Özellikler

- **Statik Kod Analizi**: Önceden tanımlanmış güvenlik kurallarına göre kod analizi
- **AI Destekli Analiz**: Google AI ile güvenlik açıklarının tespiti
- **Çoklu Dosya Desteği**: .py, .js, .php, .java, .cpp, .cs ve .zip dosya analizi
- **Detaylı Raporlama**: Zafiyet türü, önem derecesi ve çözüm önerileri
- **Dashboard**: Analiz istatistikleri ve trend takibi
- **Tarama Geçmişi**: Geçmiş analizlerin detaylı görüntülenmesi

## 🚀 Kurulum

1. Repoyu klonlayın:
```bash
git clone https://github.com/yourusername/triangle-code-analyzer.git
cd triangle-code-analyzer
```

2. Sanal ortam oluşturun ve aktif edin:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Gereksinimleri yükleyin:
```bash
pip install -r requirements.txt
```

4. .env dosyasını oluşturun:
```env
GOOGLE_API_KEY=your_api_key_here
```

5. Veritabanını oluşturun:
```bash
python init_database.py
```

6. Uygulamayı başlatın:
```bash
python app.py
```

## 💻 Kullanım

1. `http://localhost:5000` adresine gidin
2. Varsayılan kullanıcı bilgileri:
   - Kullanıcı adı: `admin`
   - Şifre: `Test.12345!`
3. Analiz etmek istediğiniz dosyayı yükleyin
4. Sonuçları inceleyin ve raporları görüntüleyin

## 🛡️ Güvenlik Seviyeleri

- **Critical**: Uzaktan kod çalıştırma, SQL enjeksiyonu gibi kritik güvenlik açıkları
- **High**: XSS, CSRF gibi ciddi güvenlik açıkları
- **Medium**: Güvenlik açığı potansiyeli olan durumlar
- **Low**: En iyi pratiklere uymayan düşük riskli durumlar

## 🔧 Teknolojiler

- Python 3.x
- Flask
- Google AI (Gemini Pro)
- SQLite
- HTML5/CSS3
- JavaScript
- Chart.js

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🤝 Katkıda Bulunma

1. Bu repoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Bir Pull Request oluşturun