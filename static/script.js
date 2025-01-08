// Dosya seçme işlemini dinle
document.getElementById('codeFile').addEventListener('change', function(e) {
    const fileName = e.target.files[0]?.name;
    const fileLabel = document.getElementById('fileLabel');
    const fileNameSpan = document.getElementById('fileName');
    const fileInfo = document.getElementById('fileInfo');
    
    if (fileName) {
        fileLabel.innerHTML = '<i class="fas fa-check"></i> Dosya Yüklendi';
        fileLabel.classList.add('file-selected');
        fileNameSpan.textContent = fileName;
        fileInfo.textContent = `Dosya: ${fileName}`;
    } else {
        fileLabel.innerHTML = '<i class="fas fa-cloud-upload-alt"></i> Dosya Seç';
        fileLabel.classList.remove('file-selected');
        fileNameSpan.textContent = '';
        fileInfo.textContent = '';
    }
});

document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fileInput = document.getElementById('codeFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Lütfen bir dosya seçin');
        return;
    }

    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');
    const scanTime = document.getElementById('scanTime');

    // Yükleme başladığında göster
    loading.classList.remove('hidden');
    results.classList.add('hidden');

    const startTime = new Date();
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        const endTime = new Date();
        const duration = (endTime - startTime) / 1000;

        if (response.ok && data.success) {
            displayResults(data);
            
            scanTime.textContent = `Analiz Süresi: ${duration.toFixed(2)} saniye`;
            
            results.classList.remove('hidden');
        } else {
            throw new Error(data.error || 'Bir hata oluştu');
        }
    } catch (error) {
        alert('Hata: ' + error.message);
        resultsContent.innerHTML = `
            <div class="error-message">
                <h3><i class="fas fa-exclamation-circle"></i> Hata Oluştu</h3>
                <p>${error.message}</p>
            </div>
        `;
    } finally {
        // Yükleme tamamlandığında gizle
        loading.classList.add('hidden');
        results.classList.remove('hidden');
    }
});

// Sayfa yüklendiğinde loading ve results divlerini gizle
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
});

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');
    resultsContent.innerHTML = '';

    // API'den gelen vulnerabilities array'ini önem derecesine göre grupla
    const groupedVulns = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    };

    // Zafiyetleri grupla
    data.vulnerabilities.forEach(vuln => {
        if (groupedVulns.hasOwnProperty(vuln.severity)) {
            groupedVulns[vuln.severity].push(vuln);
        }
    });

    // İstatistik kartlarını ekle
    const stats = {
        critical: groupedVulns.CRITICAL.length,
        high: groupedVulns.HIGH.length,
        medium: groupedVulns.MEDIUM.length,
        low: groupedVulns.LOW.length
    };

    resultsContent.innerHTML = `
    <div class="stats-overview">
        <div class="stat-card critical">
            <div class="stat-circle">
                <span class="stat-number">${stats.critical}</span>
            </div>
            <h3>Critical Vulnerability</h3>
        </div>
        <div class="stat-card high">
            <div class="stat-circle">
                <span class="stat-number">${stats.high}</span>
            </div>
            <h3>High Vulnerability</h3>
        </div>
        <div class="stat-card medium">
            <div class="stat-circle">
                <span class="stat-number">${stats.medium}</span>
            </div>
            <h3>Medium Vulnerability</h3>
        </div>
        <div class="stat-card low">
            <div class="stat-circle">
                <span class="stat-number">${stats.low}</span>
            </div>
            <h3>Low Vulnerability</h3>
        </div>
    </div>`;

    // Zafiyet gruplarını oluştur
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    severityOrder.forEach(severity => {
        const vulns = groupedVulns[severity];
        if (vulns && vulns.length > 0) {
            const severityGroup = document.createElement('div');
            severityGroup.className = 'severity-group';
            
            // Başlık
            const title = document.createElement('h2');
            title.className = `severity-title ${severity.toLowerCase()}`;
            title.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                ${getSeverityText(severity)} Zafiyetler (${vulns.length})
            `;
            severityGroup.appendChild(title);

            // Zafiyetler
            vulns.forEach(vuln => {
                const vulnItem = document.createElement('div');
                vulnItem.className = 'vulnerability-item';
                
                vulnItem.innerHTML = `
                    <div class="vuln-header" onclick="toggleVuln(this)">
                        <div class="vuln-title">
                            <h3>
                                <i class="fas fa-bug"></i>
                                ${escapeHtml(vuln.name)}
                                ${vuln.source === 'ai_analysis' ? '<span class="source-badge ai">AI</span>' : ''}
                            </h3>
                            <span class="file-info">
                                ${escapeHtml(vuln.file_name)}
                                ${vuln.line_number ? ` - Satır: ${vuln.line_number}` : ''}
                            </span>
                        </div>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="vuln-details hidden">
                        <div class="detail-tabs">
                            <button class="tab-btn active" onclick="switchTab(this, 'details')">Detaylar</button>
                            ${vuln.code_context ? '<button class="tab-btn" onclick="switchTab(this, \'code\')">Kod</button>' : ''}
                        </div>
                        
                        <div class="tab-content details-tab active">
                            <div class="detail-section">
                                <h4>Açıklama</h4>
                                <p>${escapeHtml(vuln.description)}</p>
                            </div>
                            <div class="detail-section">
                                <h4>Çözüm Önerisi</h4>
                                <p>${escapeHtml(vuln.solution)}</p>
                            </div>
                        </div>
                        
                        ${vuln.code_context ? `
                        <div class="tab-content code-tab">
                            <div class="code-block">
                                <pre><code>${vuln.code_context.map(line => `
<span class="line-number">${line.line_number}</span>${line.is_vulnerable ? '<span class="vulnerable-line">' : ''}${escapeHtml(line.content)}${line.is_vulnerable ? '</span>' : ''}`).join('\n')}</code></pre>
                            </div>
                        </div>
                        ` : ''}
                    </div>
                `;
                
                severityGroup.appendChild(vulnItem);
            });

            resultsContent.appendChild(severityGroup);
        }
    });

    // Sonuçları göster
    resultsDiv.classList.remove('hidden');
    document.getElementById('loading').classList.add('hidden');
}

// Yardımcı fonksiyonlar
function getSeverityText(severity) {
    const texts = {
        'CRITICAL': 'Kritik',
        'HIGH': 'Yüksek',
        'MEDIUM': 'Orta',
        'LOW': 'Düşük'
    };
    return texts[severity];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function toggleVuln(element) {
    const details = element.nextElementSibling;
    const icon = element.querySelector('.fa-chevron-down');
    details.classList.toggle('hidden');
    icon.style.transform = details.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(180deg)';
}

function switchTab(btn, tabName) {
    // Aktif sekme butonunu güncelle
    const tabBtns = btn.parentElement.querySelectorAll('.tab-btn');
    tabBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Aktif içeriği güncelle
    const tabContents = btn.closest('.vuln-details').querySelectorAll('.tab-content');
    tabContents.forEach(c => c.classList.remove('active'));
    btn.closest('.vuln-details').querySelector(`.${tabName}-tab`).classList.add('active');
} 