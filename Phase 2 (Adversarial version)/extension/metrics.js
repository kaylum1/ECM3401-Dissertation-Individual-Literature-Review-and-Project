// extension/metrics.js


//-------------------------------------------------------
//The metrics page is where users will be able to access 
// the diffferent setting if they wish to do so weather they go for normal, 
// privacy focused, or secuirty focused 
//-------------------------------------------------------




// When the metrics page loads, set the radio button to the stored weight system so it automatcally starts on normal when starting the extension


document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.local.get('weightSystem', function(data) {
    const storedSystem = data.weightSystem || 'normal';
    const radioToCheck = document.querySelector(`input[name="weightSystem"][value="${storedSystem}"]`);  
    if (radioToCheck) {
      radioToCheck.checked = true;
    }
  });
});

//-------------------------------------------------
// This section deals with the error handling and
// setting the value of the weight them selves
//-----------------------------------------------


// Active listner to Listens for form submission to update the weight system
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
  


    // allows you to switch between different scoring weights 
    //THIS HAS BEEN CHANGED FOR PHASE TWO TO MAKE SURE THE 
    const labelMap = { //-----------------------------------------phase 2 change, and matches the ordering of metric.html 
      normal: 'undefined',
      privacy: 'undefined',
      security: 'undefined',
      adversarial: 'undefined'
    };
    const userLabel = labelMap[data.system] || data.system;
    alert('Weight system updated to ' + userLabel);
  })
  .catch(error => {
    console.error('Error updating weight system:', error);
    alert('Error updating weight system.');
  });
});





//BACK BUTTON BACK TO THE POPUP.JS
document.getElementById('backBtn').addEventListener('click', function() {
  window.location.href = 'popup.html';
});
