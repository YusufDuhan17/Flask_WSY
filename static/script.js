document.addEventListener('DOMContentLoaded', function() {

    // --- Sidebar Aktif Navigasyon Öğesi ve Görsel Efektler ---
    const menuItems = document.querySelectorAll('.menu li');
    const currentPath = window.location.pathname;

    menuItems.forEach(item => {
        const itemLink = item.querySelector('a');
        if (itemLink) {
            const itemHref = new URL(itemLink.href).pathname;

            // Tam eşleşme veya belirli alt yollar için aktif sınıfı ekle
            if (currentPath === itemHref || 
                (currentPath.startsWith('/add_password') && itemHref === '/add_password') ||
                (currentPath.startsWith('/update_password/') && itemHref === '/dashboard')) { 
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }

            // Menü öğelerine tıklama ve fare etkileşimleri (yeni tasarımdan)
            item.addEventListener('click', () => {
                menuItems.forEach(i => i.classList.remove('active'));
                item.classList.add('active');
                
                const icon = item.querySelector('i');
                if (icon) {
                    icon.style.transform = 'scale(1.2)';
                    setTimeout(() => {
                        icon.style.transform = 'scale(1)';
                    }, 200);
                }
            });
            
            item.addEventListener('mouseenter', (e) => {
                const highlight = document.createElement('div');
                highlight.classList.add('highlight');
                highlight.style.position = 'absolute';
                highlight.style.top = '0';
                highlight.style.left = '0';
                highlight.style.width = '100%';
                highlight.style.height = '100%';
                highlight.style.borderRadius = '16px';
                highlight.style.background = `radial-gradient(circle at ${e.offsetX}px ${e.offsetY}px, rgba(255,255,255,0.2) 0%, rgba(255,255,255,0) 70%)`;
                highlight.style.pointerEvents = 'none';
                
                item.appendChild(highlight);
                
                setTimeout(() => {
                    highlight.style.opacity = '0';
                    setTimeout(() => {
                        if (item.contains(highlight)) { 
                            item.removeChild(highlight);
                        }
                    }, 300);
                }, 500);
            });
        }
    });

    // --- Kart Animasyonları (Dashboard'daki Şifre Kartları için) ---
    const cards = document.querySelectorAll('.password-card');
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const rotateY = (x / rect.width - 0.5) * 10; 
            const rotateX = (y / rect.height - 0.5) * -10; 
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(1.02)`; 
            card.style.transition = 'none'; 
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0) scale(1)';
            card.style.transition = 'transform 0.5s ease'; 
        });
    });


    // --- Flash Mesajlarını Pop-up Modalı Olarak Göster ---
    const flashModal = document.getElementById('flash-modal');
    const flashModalContentArea = document.getElementById('flash-modal-message-area');
    const flashModalCloseButton = document.querySelector('.flash-modal-close-button');

    // flaskFlashMessages global değişkeni base.html tarafından tanımlanır
    if (typeof flaskFlashMessages !== 'undefined' && flaskFlashMessages.length > 0) {
        flaskFlashMessages.forEach(msg => {
            const [category, message] = msg;
            const msgDiv = document.createElement('div');
            msgDiv.classList.add('flash-message', category);
            msgDiv.textContent = message;
            flashModalContentArea.appendChild(msgDiv);
        });
        flashModal.classList.add('show'); // Modalı görünür yap

        // Otomatik kapanma (sadece bilgi ve başarı mesajları için)
        if (flaskFlashMessages.some(msg => msg[0] === 'info' || msg[0] === 'success')) {
            setTimeout(() => {
                flashModal.classList.remove('show');
                // CSS geçişi tamamlandıktan sonra içeriği temizle
                flashModal.addEventListener('transitionend', () => {
                    if (!flashModal.classList.contains('show')) {
                        flashModalContentArea.innerHTML = '';
                    }
                }, { once: true });
            }, 5000); // 5 saniye sonra otomatik kapan
        }
    }

    // Kapatma butonu işlevi
    if (flashModalCloseButton) {
        flashModalCloseButton.addEventListener('click', () => {
            flashModal.classList.remove('show');
            flashModal.addEventListener('transitionend', () => {
                if (!flashModal.classList.contains('show')) {
                    flashModalContentArea.innerHTML = '';
                }
            }, { once: true });
        });
    }

    // Modal dışına tıklayınca kapatma
    if (flashModal) {
        flashModal.addEventListener('click', (event) => {
            if (event.target === flashModal) {
                flashModal.classList.remove('show');
                flashModal.addEventListener('transitionend', () => {
                    if (!flashModal.classList.contains('show')) {
                        flashModalContentArea.innerHTML = '';
                    }
                }, { once: true });
            }
        });
    }


    // --- Şifre Göster/Gizle Fonksiyonu (Dashboard) ---
    window.togglePasswordVisibility = function(button, passwordId) {
        const passwordSpan = document.getElementById('password_display_' + passwordId);
        const originalPassword = passwordSpan.dataset.originalPassword;

        if (button.textContent === "Göster") {
            passwordSpan.textContent = originalPassword;
            button.textContent = "Gizle";
        } else {
            passwordSpan.textContent = "*******";
            button.textContent = "Göster";
        }
    };

    // Sayfa yüklendiğinde şifre alanlarını gizle (Dashboard)
    const passwordSpansInitial = document.querySelectorAll('[id^="password_display_"]');
    passwordSpansInitial.forEach(span => {
        if (span.dataset.originalPassword) { 
            span.textContent = "*******";
        }
    });


    // --- Şifre Gücü Göstergesi Fonksiyonları (add_password.html ve update_password.html için) ---
    window.checkPasswordStrengthFrontend = function(password) {
        let score = 0;
        let feedback = [];

        if (password.length >= 14) { score += 4; feedback.push("Şifre uzunluğu mükemmel! (14+ karakter)"); }
        else if (password.length >= 10) { score += 3; feedback.push("Şifre yeterince uzun. Daha uzun olması daha iyi olur (min 10)."); }
        else if (password.length >= 8) { score += 2; feedback.push("Şifre kısa. En az 8, tercihen 14+ karakter olmalı."); }
        else { feedback.push("Şifre çok kısa. En az 8 karakter olmalı, 14+ önerilir."); }

        if (/[A-Z]/.test(password)) { score += 1; } else { feedback.push("Büyük harf (A-Z) ekleyin."); }
        if (/[a-z]/.test(password)) { score += 1; } else { feedback.push("Küçük harf (a-z) ekleyin."); }
        if (/\d/.test(password)) { score += 1; } else { feedback.push("Sayı (0-9) ekleyin."); }
        if (/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password)) { score += 1; } else { feedback.push("Özel karakter (!@#$ vb.) ekleyin."); }

        if (password.length > 5 && new Set(password.split('')).size < password.length * 0.7) { feedback.push("Çok fazla tekrar eden karakter veya basit desenler içeriyor. Daha çeşitli yapın."); }

        const common_words = ["password", "123456", "qwerty", "admin", "yusuf", "sifre", "parola", "12345678", "abcde"];
        if (common_words.some(word => password.toLowerCase().includes(word))) { score -= 2; feedback.push("Ortak veya tahmin edilebilir kelimeler kullanmaktan kaçının."); }
        
        const sequential_chars = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789|012|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)/;
        if (sequential_chars.test(password.toLowerCase())) { score -= 1; feedback.push("Ardışık karakterler veya klavye dizilimi kullanmaktan kaçının."); }
        
        const reverse_sequential_chars = /(cba|edc|fed|gfe|ihg|kji|lkj|pon|rqp|tsr|vut|xwv|zyx|321|432|543|654|765|876|987|ewq|tre|yrt|iuy|poi|dsa|gfd|jhg|lkj|vbn|mno|xcz)/;
        if (reverse_sequential_chars.test(password.toLowerCase())) { score -= 1; feedback.push("Tersten ardışık karakterler veya klavye dizilimi kullanmaktan kaçının."); }

        let strengthText, color;
        if (score >= 7) { strengthText = "Çok Güçlü"; color = "#4CAF50"; }
        else if (score >= 5) { strengthText = "Güçlü"; color = "#8BC34A"; }
        else if (score >= 3) { strengthText = "Orta"; color = "#FFC107"; }
        else { strengthText = "Zayıf"; color = "#F44336"; }
        
        return { strengthText, color, feedback };
    };

    window.updateStrengthDisplayCommon = function(passwordInputId, labelId, progressId, feedbackListId, hiddenStrengthInputId) {
        const passwordInput = document.getElementById(passwordInputId);
        if (!passwordInput) return;

        const strengthLabel = document.getElementById(labelId);
        const strengthProgressBar = document.getElementById(progressId);
        const hiddenStrengthInput = document.getElementById(hiddenStrengthInputId); 
        
        const password = passwordInput.value;
        const { strengthText, color, feedback } = window.checkPasswordStrengthFrontend(password);

        strengthLabel.textContent = `Şifre Gücü: ${strengthText}`;
        strengthLabel.style.color = color;
        if (hiddenStrengthInput) {
            hiddenStrengthInput.value = strengthText; 
        }

        let progressValue;
        switch (strengthText) {
            case "Zayıf": progressValue = 25; break;
            case "Orta": progressValue = 50; break;
            case "Güçlü": progressValue = 75; break;
            case "Çok Güçlü": progressValue = 100; break;
            default: progressValue = 0; break;
        }
        strengthProgressBar.value = progressValue;
        strengthProgressBar.style.setProperty('--progress-color', color); 

        const feedbackList = document.getElementById(feedbackListId);
        if (feedbackList) {
            feedbackList.innerHTML = ''; 
            if (feedback.length > 0) {
                feedback.forEach(item => {
                    const li = document.createElement('li');
                    li.textContent = `• ${item}`;
                    feedbackList.appendChild(li);
                });
                strengthLabel.classList.add('has-feedback'); 
            } else {
                strengthLabel.classList.remove('has-feedback');
            }
        }
    };

    // add_password.html için özel bağlama
    const addPagePasswordInput = document.getElementById('password');
    if (addPagePasswordInput && document.getElementById('strength-label-add')) {
        addPagePasswordInput.addEventListener('input', () => window.updateStrengthDisplayCommon('password', 'strength-label-add', 'strength-progressbar-add', 'strength-feedback-list', 'strength-text-add'));
        window.updateStrengthDisplayCommon('password', 'strength-label-add', 'strength-progressbar-add', 'strength-feedback-list', 'strength-text-add'); 
    }

    // update_password.html için özel bağlama
    const updatePagePasswordInput = document.getElementById('password');
    if (updatePagePasswordInput && document.getElementById('strength-label-update')) {
        updatePagePasswordInput.addEventListener('input', () => window.updateStrengthDisplayCommon('password', 'strength-label-update', 'strength-progressbar-update', 'strength-feedback-list-update', 'strength-text-update'));
        window.updateStrengthDisplayCommon('password', 'strength-label-update', 'strength-progressbar-update', 'strength-feedback-list-update', 'strength-text-update'); 
    }

    // --- Yeni Kategori Ekleme İşlevselliği (Pop-up yerine Form İçi) ---
    const addNewCategoryBtn = document.getElementById('add-new-category-btn');
    const newCategoryInputArea = document.getElementById('new-category-input-area');
    const newCategoryNameInput = document.getElementById('new-category-name');
    const saveNewCategoryBtn = document.getElementById('save-new-category-btn');
    const cancelNewCategoryBtn = document.getElementById('cancel-new-category-btn');
    const categorySelect = document.getElementById('category'); 

    if (addNewCategoryBtn && newCategoryInputArea && newCategoryNameInput && saveNewCategoryBtn && cancelNewCategoryBtn && categorySelect) {
        addNewCategoryBtn.addEventListener('click', function(event) {
            event.preventDefault(); 
            newCategoryInputArea.style.display = 'flex'; 
            newCategoryNameInput.focus(); 
        });

        cancelNewCategoryBtn.addEventListener('click', function() {
            newCategoryInputArea.style.display = 'none'; 
            newCategoryNameInput.value = ''; 
        });

        saveNewCategoryBtn.addEventListener('click', function() {
            const newCat = newCategoryNameInput.value.trim();
            if (newCat) {
                let options = Array.from(categorySelect.options).map(opt => opt.value);
                if (!options.includes(newCat)) {
                    const newOption = document.createElement('option');
                    newOption.value = newCat;
                    newOption.textContent = newCat;
                    categorySelect.appendChild(newOption);
                    
                    let sortedOptions = Array.from(categorySelect.options)
                        .map(opt => opt.value)
                        .sort((a, b) => {
                            if (a === "Genel") return -1; 
                            if (b === "Genel") return 1;
                            return a.localeCompare(b);
                        });
                    
                    categorySelect.innerHTML = '';
                    sortedOptions.forEach(val => {
                        const opt = document.createElement('option');
                        opt.value = val;
                        opt.textContent = val;
                        categorySelect.appendChild(opt);
                    });

                    categorySelect.value = newCat; 
                    newCategoryInputArea.style.display = 'none'; 
                    newCategoryNameInput.value = ''; 
                    alert(`'${newCat}' kategorisi başarıyla eklendi!`); 
                } else {
                    alert(`'${newCat}' kategorisi zaten mevcut.`);
                }
            } else {
                alert("Lütfen yeni kategori adını girin.");
            }
        });
    }

    // --- Şifreyi Panoya Kopyalama Fonksiyonu ---
    window.copyToClipboard = function(button) {
        const passwordSpan = button.closest('.card-actions').previousElementSibling.querySelector('[id^="password_display_"]'); 
        if (passwordSpan && passwordSpan.dataset.originalPassword) {
            navigator.clipboard.writeText(passwordSpan.dataset.originalPassword).then(() => {
                const originalText = button.textContent;
                button.textContent = "Kopyalandı!";
                setTimeout(() => {
                    button.textContent = originalText;
                }, 1500);
            }).catch(err => {
                console.error('Kopyalama başarısız:', err);
                alert('Şifre kopyalanamadı.');
            });
        } else {
            alert('Kopyalanacak şifre bulunamadı.');
        }
    };
});