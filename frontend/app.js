
function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(pageId).classList.add('active');
}
function goToStart() { showPage('page-start'); }


function updateCount(textareaId, counterId) {
  const len = document.getElementById(textareaId).value.length;
  const el = document.getElementById(counterId);
  el.textContent = len + ' / 10000';
  el.style.color = len >= 9500 ? '#ff4d4d' : len >= 8000 ? '#ffaa00' : '';
}

async function processEncryption() {
  let text = document.getElementById('e-plaintext').value.trim();
  let key = document.getElementById('e-key').value.trim();
  if (!text || !key) { alert("Please fill all fields!"); return; }


  try {
    const res = await fetch('http://127.0.0.1:5000/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: key, text: text })
    });

    const json = await res.json();
    if (!res.ok) {
      alert("Server error: " + (json.error || JSON.stringify(json)));
      return;
    }


    document.getElementById('e-res-key').value = key;
    document.getElementById('e-res-iv').value = json.iv || '';
    document.getElementById('e-res-text').value = json.cipher || '';

    showPage('page-encrypt-2');
  } catch (err) {
    alert("Network or server error: " + err);
  }
}

async function processDecryption() {
  let cipher = document.getElementById('d-ciphertext').value.trim();
  let key = document.getElementById('d-key').value.trim();
  let iv = document.getElementById('d-iv').value.trim();
  if (!cipher || !key || !iv) { alert("Please fill all fields!"); return; }

  try {
    const res = await fetch('http://127.0.0.1:5000/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: key, iv: iv, cipher: cipher })
    });

    const json = await res.json();
    if (!res.ok) {
      alert("Server error: " + (json.error || JSON.stringify(json)));
      return;
    }

    document.getElementById('d-res-text').value = json.plaintext || '';
    showPage('page-decrypt-2');
  } catch (err) {
    alert("Network or server error: " + err);
  }
}
