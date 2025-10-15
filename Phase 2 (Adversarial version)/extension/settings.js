
//---------------------------------------------------
//this is the pages that deals with the toggles that allow add blocker and cookie declines
// this section works with the implmention part in background.js 
//---------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
  const adBlockerToggle = document.getElementById('adBlockerToggle');
  const cookieDeclinerToggle = document.getElementById('cookieDeclinerToggle');
  // const vpnToggle = document.getElementById('vpnToggle'); // VPN toggle commented out

  // Retrieve and set saved settings; default to false if not set.
  chrome.storage.local.get(
    ['adBlockerEnabled', 'cookieDeclinerEnabled' /*, 'vpnEnabled'*/],
    function(result) {
      adBlockerToggle.checked = result.adBlockerEnabled === true;
      cookieDeclinerToggle.checked = result.cookieDeclinerEnabled === true;
      // vpnToggle.checked = result.vpnEnabled === true; // VPN setting commented out
    }
  );

  // Save changes when the user toggles the switches.
  adBlockerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'adBlockerEnabled': adBlockerToggle.checked }, function() {
      console.log('Ad Blocker setting saved:', adBlockerToggle.checked);
    });
  });

  cookieDeclinerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'cookieDeclinerEnabled': cookieDeclinerToggle.checked }, function() {
      console.log('Automatic Cookie Decliner setting saved:', cookieDeclinerToggle.checked);
    });
  });

  /* 
  // VPN toggle functionality commented out.
  vpnToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'vpnEnabled': vpnToggle.checked }, function() {
      console.log('VPN setting saved:', vpnToggle.checked);
    });
  });
  */

  // Back button returns to the main popup page.
  document.getElementById('backBtn').addEventListener('click', function() {
    window.location.href = 'popup.html';
  });
});
