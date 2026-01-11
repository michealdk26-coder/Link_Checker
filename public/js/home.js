// Home page scanning script
(function(){
  const API_URL = window.location.origin;
  const input = document.getElementById('homeUrlInput');
  const btn = document.getElementById('homeScanBtn');
  const alertBox = document.getElementById('homeAlert');
  const results = document.getElementById('homeResults');
  const riskText = document.getElementById('homeRiskText');
  const riskScore = document.getElementById('homeRiskScore');
  const recList = document.getElementById('homeRecommendations');

  function showAlert(message, type){
    alertBox.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show" role="alert">${message}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
  }

  function clearAlert(){
    alertBox.innerHTML = '';
  }

  if(btn){
    btn.addEventListener('click', async function(){
      clearAlert();
      const url = (input.value || '').trim();
      if(!url){
        showAlert('Please enter a URL to scan.', 'warning');
        return;
      }
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Scanning...';
      results.style.display = 'none';
      try{
        const res = await fetch(`${API_URL}/api/scan/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        const data = await res.json();
        if(res.ok && data.success){
          const report = data.report;
          riskText.textContent = report.overallRisk;
          riskScore.textContent = report.riskPercentage;
          recList.innerHTML = '';
          (report.recommendations || []).forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            recList.appendChild(li);
          });
          results.style.display = 'block';
        } else {
          showAlert(data.message || 'Failed to scan URL.', 'danger');
        }
      } catch(err){
        showAlert('Network error. Please try again.', 'danger');
      }
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-search me-2"></i>Check Security';
    });
  }
})();