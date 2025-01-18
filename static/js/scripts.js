// static/js/scripts.js

function checkTaskStatus(taskId) {
    fetch(`http://localhost:5000/result/${taskId}`)
        .then(response => response.json())
        .then(data => {
            if (data.state === 'PENDING' || data.state === 'PROGRESS') {
                document.getElementById('scanResult').innerText = `Scan in progress... (${data.progress}%)`;
                setTimeout(() => checkTaskStatus(taskId), 2000); // Poll every 2 seconds
            } else if (data.state === 'SUCCESS') {
                document.getElementById('scanResult').innerText = `Scan completed. Results: ${JSON.stringify(data.result, null, 2)}`;
            } else if (data.state === 'FAILURE') {
                document.getElementById('scanResult').innerText = `Scan failed. Error: ${data.error}`;
            }
        })
        .catch((error) => {
            console.error('Error:', error);
            document.getElementById('scanResult').innerText = `An error occurred: ${error}`;
        });
}

document.getElementById('scanForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the default form submission

    const urlInput = document.getElementById('urlInput').value;

    fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json' // Ensure the Content-Type is set to application/json
        },
        body: JSON.stringify({ url: urlInput }) // Send JSON payload
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw err; });
        }
        return response.json();
    })
    .then(data => {
        console.log('Task ID:', data.task_id);
        document.getElementById('scanResult').innerText = 'Scan started. Waiting for results...';
        checkTaskStatus(data.task_id); // Start polling for task status
    })
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('scanResult').innerText = `Error: ${error.error || 'Unknown error'}`;
    });
});
