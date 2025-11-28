{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-10">
        <div class="card">
            <div class="card-header text-center">
                <h4>{{ 'Generate QR Code' if is_admin else 'Absensi Event' }}</h4>
            </div>
            <div class="card-body text-center">
                <h5>{{ event.nama_event }}</h5>
                <p class="text-muted">
                    📅 {{ event.tanggal_event }} | ⏰ {{ event.waktu_event }}<br>
                    📍 {{ event.lokasi }}
                </p>
                
                {% if is_admin %}
                <div class="mb-4">
                    <p class="text-info">QR Code akan berubah otomatis setiap 2 menit</p>
                    {% if qr_code %}
                    <img src="data:image/png;base64,{{ qr_code }}" alt="QR Code" class="img-fluid mb-3" style="max-width: 300px;">
                    {% endif %}
                    {% if seconds_remaining is defined %}
                    <div class="alert alert-info">
                        <i class="fas fa-clock"></i> QR Code berlaku selama: 
                        <strong id="countdown">{{ seconds_remaining }}</strong> detik
                    </div>
                    {% endif %}
                </div>
                
                <div class="alert alert-warning">
                    <strong>Instruksi:</strong> Tampilkan QR code ini kepada anggota untuk melakukan absensi
                </div>
                
                {% else %}
                <div class="mb-4">
                    <ul class="nav nav-tabs" id="absenTab" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="scan-tab" data-bs-toggle="tab" data-bs-target="#scan" type="button" role="tab">
                                📷 Scan QR Code
                            </button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="manual-tab" data-bs-toggle="tab" data-bs-target="#manual" type="button" role="tab">
                                ⌨️ Input Manual
                            </button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="token-tab" data-bs-toggle="tab" data-bs-target="#token" type="button" role="tab">
                                🔑 Token
                            </button>
                        </li>
                    </ul>
                    
                    <div class="tab-content mt-3" id="absenTabContent">
                        <!-- Tab Scan QR Code -->
                        <div class="tab-pane fade show active" id="scan" role="tabpanel">
                            <div class="mb-3">
                                <p>Gunakan kamera untuk scan QR Code yang ditampilkan admin</p>
                                
                                <div class="camera-container mb-3">
                                    <div id="camera-preview" class="border rounded p-2 text-center" style="min-height: 300px; background: #f8f9fa;">
                                        <div id="camera-placeholder" class="py-5">
                                            <i class="fas fa-camera fa-3x text-muted mb-3"></i>
                                            <p class="text-muted">Kamera siap untuk scanning</p>
                                            <button id="start-camera" class="btn btn-primary btn-sm">Aktifkan Kamera</button>
                                        </div>
                                        <video id="video" width="100%" style="display: none;"></video>
                                        <canvas id="canvas" style="display: none;"></canvas>
                                    </div>
                                </div>
                                
                                <div class="camera-controls mb-3">
                                    <button id="capture-btn" class="btn btn-success" style="display: none;">
                                        <i class="fas fa-camera"></i> Capture QR Code
                                    </button>
                                    <button id="switch-camera" class="btn btn-outline-secondary btn-sm" style="display: none;">
                                        <i class="fas fa-sync-alt"></i> Switch Camera
                                    </button>
                                </div>
                                
                                <div id="scan-result" class="alert alert-info" style="display: none;">
                                    <strong>QR Code Terdeteksi:</strong>
                                    <span id="qr-result-text"></span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Tab Input Manual -->
                        <div class="tab-pane fade" id="manual" role="tabpanel">
                            <p>Masukkan kode QR secara manual</p>
                            <form method="POST" class="mt-4">
                                <input type="hidden" name="absen_type" value="qr_code">
                                <div class="mb-3">
                                    <label for="qr_code" class="form-label">Masukkan Kode QR</label>
                                    <input type="text" class="form-control" id="qr_code" name="qr_code" 
                                           placeholder="Masukkan kode QR yang ditampilkan" required>
                                    <div class="form-text">Mintalah kode QR terbaru kepada admin</div>
                                </div>
                                <button type="submit" class="btn btn-primary btn-lg">Submit Absensi QR Code</button>
                            </form>
                        </div>
                        
                        <!-- Tab Token -->
                        <div class="tab-pane fade" id="token" role="tabpanel">
                            <p>Masukkan token yang diberikan admin untuk melakukan absensi</p>
                            <form method="POST" class="mt-4">
                                <input type="hidden" name="absen_type" value="token">
                                <div class="mb-3">
                                    <label for="token" class="form-label">Masukkan Token</label>
                                    <input type="text" class="form-control" id="token" name="token" 
                                           placeholder="Masukkan token (contoh: A1B2C3)" required>
                                    <div class="form-text">Mintalah token terbaru kepada admin</div>
                                </div>
                                <button type="submit" class="btn btn-warning btn-lg">Submit Absensi Token</button>
                            </form>
                        </div>
                    </div>
                </div>
                {% endif %}
                
                <div class="mt-4">
                    <a href="{{ url_for('admin_events' if is_admin else 'user_events') }}" 
                       class="btn btn-outline-secondary">Kembali</a>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- QR Code Scanner Library -->
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
{% endblock %}

{% block scripts %}
{% if is_admin and refresh_interval %}
<script>
    // Auto refresh QR code untuk admin (2 menit)
    setTimeout(function() {
        window.location.reload();
    }, {{ refresh_interval }});
    
    // Countdown timer untuk admin
    {% if seconds_remaining is defined %}
    let timeLeft = {{ seconds_remaining }};
    const countdownElement = document.getElementById('countdown');
    
    const countdown = setInterval(function() {
        timeLeft--;
        countdownElement.textContent = timeLeft;
        
        if (timeLeft <= 0) {
            clearInterval(countdown);
            window.location.reload();
        }
    }, 1000);
    {% endif %}
</script>
{% else %}
<script>
    // QR Code Scanner untuk user
    let video = document.getElementById('video');
    let canvas = document.getElementById('canvas');
    let context = canvas.getContext('2d');
    let currentStream = null;
    let currentFacingMode = 'environment'; // environment = back camera, user = front camera
    
    document.getElementById('start-camera').addEventListener('click', function() {
        startCamera();
    });
    
    document.getElementById('switch-camera').addEventListener('click', function() {
        switchCamera();
    });
    
    document.getElementById('capture-btn').addEventListener('click', function() {
        captureQRCode();
    });
    
    function startCamera() {
        if (currentStream) {
            stopCamera();
        }
        
        const constraints = {
            video: { 
                facingMode: currentFacingMode,
                width: { ideal: 640 },
                height: { ideal: 480 }
            },
            audio: false
        };
        
        navigator.mediaDevices.getUserMedia(constraints)
            .then(function(stream) {
                currentStream = stream;
                video.srcObject = stream;
                video.play();
                
                document.getElementById('camera-placeholder').style.display = 'none';
                video.style.display = 'block';
                document.getElementById('capture-btn').style.display = 'inline-block';
                document.getElementById('switch-camera').style.display = 'inline-block';
                document.getElementById('start-camera').style.display = 'none';
                
                // Start scanning automatically
                requestAnimationFrame(scanQRCode);
            })
            .catch(function(err) {
                console.error("Error accessing camera: ", err);
                alert('Tidak dapat mengakses kamera. Pastikan Anda memberikan izin akses kamera.');
            });
    }
    
    function stopCamera() {
        if (currentStream) {
            currentStream.getTracks().forEach(track => track.stop());
            currentStream = null;
        }
    }
    
    function switchCamera() {
        currentFacingMode = currentFacingMode === 'environment' ? 'user' : 'environment';
        startCamera();
    }
    
    function captureQRCode() {
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            
            if (code) {
                document.getElementById('qr-result-text').textContent = code.data;
                document.getElementById('scan-result').style.display = 'block';
                
                // Auto-submit the form
                document.getElementById('qr_code').value = code.data;
                
                // Stop camera after successful scan
                setTimeout(() => {
                    stopCamera();
                    document.querySelector('button[type="submit"]').click();
                }, 1000);
            } else {
                alert('QR Code tidak terdeteksi. Coba lagi dengan pencahayaan yang lebih baik.');
            }
        }
    }
    
    function scanQRCode() {
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            
            if (code) {
                document.getElementById('qr-result-text').textContent = code.data;
                document.getElementById('scan-result').style.display = 'block';
                
                // Auto-fill and submit
                document.getElementById('qr_code').value = code.data;
                
                // Stop camera and submit
                setTimeout(() => {
                    stopCamera();
                    document.querySelector('button[type="submit"]').click();
                }, 1000);
                
                return; // Stop scanning after success
            }
        }
        
        // Continue scanning
        requestAnimationFrame(scanQRCode);
    }
    
    // Clean up when leaving page
    window.addEventListener('beforeunload', function() {
        stopCamera();
    });
    
    // Switch to manual tab when camera is not available
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        document.getElementById('scan-tab').style.display = 'none';
        document.getElementById('manual-tab').click();
    }
</script>
{% endif %}
{% endblock %}
