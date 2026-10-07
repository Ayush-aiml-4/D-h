function paint(sensor) {
  const st = document.getElementById('status');
  if (sensor.connecting) {
    st.textContent = 'CONNECTING';
    st.className = 'warn';
  } else if (sensor.connected && !sensor.paused) {
    st.textContent = 'CONNECTED';
    st.className = 'ok';
  } else if (sensor.connected && sensor.paused) {
    st.textContent = 'PAUSED';
    st.className = 'warn';
  } else if (sensor.lastError && !sensor.connected) {
    st.textContent = 'ERROR';
    st.className = 'bad';
  } else {
    st.textContent = 'DISCONNECTED';
    st.className = 'bad';
  }
  document.getElementById('target').textContent = sensor.target || '—';
  document.getElementById('events').textContent = String(sensor.eventsSent || 0);
  document.getElementById('last').textContent = sensor.lastEvent
    ? String(sensor.lastEvent).slice(11, 19)
    : '—';
  document.getElementById('paused').textContent = sensor.paused ? 'yes' : 'no';
  document.getElementById('err').textContent = sensor.lastError || '';
}

function send(type) {
  chrome.runtime.sendMessage({ type }, (res) => {
    if (chrome.runtime.lastError) {
      document.getElementById('err').textContent = chrome.runtime.lastError.message;
      return;
    }
    if (res && res.sensor) paint(res.sensor);
  });
}

document.getElementById('connect').onclick = () => send('CONNECT');
document.getElementById('disconnect').onclick = () => send('DISCONNECT');
document.getElementById('pause').onclick = () => send('PAUSE');
document.getElementById('resume').onclick = () => send('RESUME');

chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (res) => {
  if (res && res.sensor) paint(res.sensor);
});

setInterval(() => {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (res) => {
    if (res && res.sensor) paint(res.sensor);
  });
}, 1500);
