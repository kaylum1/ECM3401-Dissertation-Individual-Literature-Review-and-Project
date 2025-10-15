// extension/metrics.js

// When the metrics page loads, set the radio button to the stored weight system.
document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.local.get('weightSystem', function(data) {
    const storedSystem = data.weightSystem || 'normal';
    const radioToCheck = document.querySelector(`input[name="weightSystem"][value="${storedSystem}"]`);
    if (radioToCheck) {
      radioToCheck.checked = true;
    }
  });
});

// Listen for form submission to update the weight system.
document.getElementById('weightForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const selectedSystem = document.querySelector('input[name="weightSystem"]:checked').value;

  // Send the selected weight system to the server.
  fetch('http://localhost:8000/set_weights', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ system: selectedSystem })
  })
  .then(response => response.json())
  .then(data => {
    // Save the selected weight system in chrome.storage.local.
    // This will trigger chrome.storage.onChanged in the popup, causing it to update.
    chrome.storage.local.set({ weightSystem: selectedSystem }, function() {
      alert('Weight system updated to ' + data.system);
    });
  })
  .catch(error => {
    console.error('Error updating weight system:', error);
    alert('Error updating weight system.');
  });
});

// Navigate back to the popup page when the "Back" button is clicked.
document.getElementById('backBtn').addEventListener('click', function() {
  window.location.href = 'popup.html';
});
