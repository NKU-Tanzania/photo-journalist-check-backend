function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function verifyImage(imageId) {
    // Get CSRF token
    const csrftoken = getCookie('csrftoken');

    // Show loading indicator
    const button = event.target;
    const originalText = button.innerText;
    button.innerText = 'Verifying...';
    button.disabled = true;

    // Make API request to verify the image
    fetch(`/api/verify/${imageId}/`, {
        method: 'GET',
        headers: {
            'X-CSRFToken': csrftoken,
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        // Show result and refresh the page
        alert(data.message);
        location.reload();
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Verification failed. Check console for details.');
        button.innerText = originalText;
        button.disabled = false;
    });
}