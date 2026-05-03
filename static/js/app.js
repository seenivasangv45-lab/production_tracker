// ─── ProTrack App JS ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {

    // Auto-dismiss flash messages after 5s
    document.querySelectorAll('.flash').forEach(el => {
        setTimeout(() => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(-8px)';
            setTimeout(() => el.remove(), 300);
        }, 5000);
    });

    // Select all checkbox
    const selectAll = document.getElementById('selectAll');
    if (selectAll) {
        selectAll.addEventListener('change', function() {
            document.querySelectorAll('.row-check').forEach(cb => {
                cb.checked = this.checked;
            });
            updateAssignBar();
        });
    }

    // Row checkboxes - show assign bar
    document.querySelectorAll('.row-check').forEach(cb => {
        cb.addEventListener('change', updateAssignBar);
    });

    // Upload drag and drop
    const uploadArea = document.querySelector('.upload-area');
    if (uploadArea) {
        const fileInput = uploadArea.querySelector('input[type="file"]');
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            fileInput.files = e.dataTransfer.files;
            if (fileInput.files.length) {
                uploadArea.querySelector('p').textContent = fileInput.files[0].name;
            }
        });
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                uploadArea.querySelector('p').textContent = fileInput.files[0].name;
            }
        });
    }

    // Mobile sidebar toggle
    const hamburger = document.querySelector('.hamburger');
    if (hamburger) {
        hamburger.addEventListener('click', () => {
            document.querySelector('.sidebar').classList.toggle('open');
        });
    }
});

function updateAssignBar() {
    const checked = document.querySelectorAll('.row-check:checked');
    const bar = document.getElementById('assignBar');
    if (bar) {
        if (checked.length > 0) {
            bar.classList.add('visible');
            const countEl = bar.querySelector('.count');
            if (countEl) countEl.textContent = checked.length + ' selected';
        } else {
            bar.classList.remove('visible');
        }
    }
}

function getSelectedIds() {
    return Array.from(document.querySelectorAll('.row-check:checked')).map(cb => cb.value);
}

function submitAssign(action) {
    const form = document.getElementById('assignForm');
    if (!form) return;
    const ids = getSelectedIds();
    if (ids.length === 0) { alert('Select at least one account.'); return; }

    // Clear old hidden inputs
    form.querySelectorAll('.dynamic-id').forEach(el => el.remove());

    ids.forEach(id => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'account_ids';
        input.value = id;
        input.className = 'dynamic-id';
        form.appendChild(input);
    });

    form.querySelector('[name="action"]').value = action;
    form.submit();
}
