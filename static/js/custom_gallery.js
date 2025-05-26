document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM fully loaded');

  // Select all toggle buttons
  const toggleBtns = document.querySelectorAll('.toggle-hash-btn');
  console.log('Found toggle buttons:', toggleBtns.length);

  // Add click event listener to each button
  toggleBtns.forEach(btn => {
    btn.addEventListener('click', function(e) {
      // Prevent default behavior
      e.preventDefault();

      console.log('Toggle button clicked');

      // Find the hash details container (parent -> parent -> sibling)
      const hashDetails = this.closest('.hash-toggle-btn').nextElementSibling;
      console.log('Hash details element:', hashDetails);

      // Toggle the active class
      if (hashDetails.classList.contains('active')) {
        hashDetails.classList.remove('active');
        this.textContent = 'Show Hash Values';
      } else {
        hashDetails.classList.add('active');
        this.textContent = 'Hide Hash Values';
      }
    });
  });
});


document.addEventListener('DOMContentLoaded', function() {
    // Filter functionality
       const filterSelect = document.getElementById('verification-filter');
    const searchInput = document.getElementById('image-search');
    const searchButton = document.getElementById('search-button');

    console.log('Filter select:', filterSelect);
    console.log('Search input:', searchInput);
    console.log('Search button:', searchButton);

    // Make sure we have gallery items to work with
    const galleryItems = document.querySelectorAll('.gallery-item');
    console.log('Gallery items found:', galleryItems.length);

    if (filterSelect) {
        // Ensure the dropdown has proper styling
        filterSelect.style.display = 'inline-block';
        filterSelect.style.width = '150px';
        filterSelect.style.height = '31px';
        filterSelect.style.padding = '5px';
        filterSelect.style.border = '1px solid #ccc';
        filterSelect.style.borderRadius = '4px';
        filterSelect.style.backgroundColor = '#fff';
        filterSelect.style.cursor = 'pointer';

        filterSelect.addEventListener('change', function() {
            console.log('Filter changed to:', this.value);
            const filterValue = this.value;

            if (galleryItems.length === 0) {
                console.error('No gallery items found to filter');
                return;
            }

            galleryItems.forEach(item => {
                console.log('Processing item:', item);
                if (filterValue === 'all') {
                    item.style.display = 'block';
                } else if (filterValue === 'verified' && item.classList.contains('verified')) {
                    item.style.display = 'block';
                } else if (filterValue === 'unverified' && !item.classList.contains('verified')) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    } else {
        console.error('Filter select element not found');
    }

    // Search functionality
    if (searchInput && searchButton) {
        // Ensure the search input has proper styling
        searchInput.style.display = 'inline-block';
        searchInput.style.width = '200px';
        searchInput.style.height = '31px';
        searchInput.style.padding = '5px';
        searchInput.style.border = '1px solid #ccc';
        searchInput.style.borderRadius = '4px';
        searchInput.style.marginRight = '5px';

        // Ensure the search button has proper styling
        searchButton.style.display = 'inline-block';
        searchButton.style.height = '31px';
        searchButton.style.padding = '5px 10px';
        searchButton.style.border = '1px solid #ccc';
        searchButton.style.borderRadius = '4px';
        searchButton.style.backgroundColor = '#f8f8f8';
        searchButton.style.cursor = 'pointer';

        function performSearch() {
            const searchTerm = searchInput.value.toLowerCase();
            console.log('Performing search for:', searchTerm);

            if (galleryItems.length === 0) {
                console.error('No gallery items found to search');
                return;
            }

            galleryItems.forEach(item => {
                // Check if data-user attribute exists
                const username = item.getAttribute('data-user');
                if (!username) {
                    console.error('Item is missing data-user attribute:', item);
                    return;
                }

                if (username.toLowerCase().includes(searchTerm)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        }

        searchButton.addEventListener('click', performSearch);
        searchInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
    } else {
        console.error('Search input or button not found');
    }

    // Modal functionality
    const modal = document.getElementById('image-modal');
    const modalImage = document.getElementById('modal-image');
    const modalTitle = document.getElementById('modal-title');
    const modalMetadata = document.getElementById('modal-metadata');
    const modalActions = document.getElementById('modal-actions');
    const closeModal = document.querySelector('.close-modal');

    // Open modal when clicking on an image or placeholder
    document.querySelectorAll('.image-container img, .no-image-placeholder').forEach(element => {
        element.addEventListener('click', function() {
            const galleryItem = this.closest('.gallery-item');
            const isVerified = galleryItem.classList.contains('verified');
            const imageElement = galleryItem.querySelector('.image-container img');
            const username = galleryItem.querySelector('h3').textContent;
            const imageId = galleryItem.querySelector('.action-button').getAttribute('data-id');
            const uploadedAt = galleryItem.querySelector('p').textContent;

            // Set the modal image if it exists, otherwise show placeholder
            if (imageElement) {
                modalImage.src = imageElement.src;
                modalImage.style.display = 'block';
            } else {
                modalImage.style.display = 'none';
                modalImage.after = 'No image available';
            }

            modalTitle.textContent = `Uploaded by ${username}`;

            // Create metadata display
            modalMetadata.innerHTML = `
                <table>
                    <tr>
                        <th>Status</th>
                        <td>${isVerified ? '✓ Verified' : '✗ Not Verified'}</td>
                    </tr>
                    <tr>
                        <th>Uploaded</th>
                        <td>${uploadedAt.replace('Uploaded: ', '')}</td>
                    </tr>
                </table>
            `;

            // Create action buttons
            if (isVerified) {
                modalActions.innerHTML = `
                    <a href="/admin/image/${imageId}/download/" class="action-button download">Download</a>
                    <a href="/admin/image/${imageId}/metadata/" class="action-button info">View Full Info</a>
                `;
            } else {
                modalActions.innerHTML = `
                    <button class="action-button verify" data-id="${imageId}">Verify Now</button>
                    <a href="/admin/image/${imageId}/metadata/" class="action-button info">View Full Info</a>
                `;
            }

            modal.style.display = 'block';
        });
    });

    // Close modal functionality
    closeModal.addEventListener('click', function() {
        modal.style.display = 'none';
    });

    window.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });

    // Verification functionality
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('verify') || e.target.parentElement.classList.contains('verify')) {
            const button = e.target.classList.contains('verify') ? e.target : e.target.parentElement;
            const imageId = button.getAttribute('data-id');

            // Show loading state
            button.textContent = 'Verifying...';
            button.disabled = true;

            // Send verification request
            fetch(`/admin/verify-image/${imageId}/`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCookie('csrftoken'),
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update UI to show verified status
                    const galleryItem = button.closest('.gallery-item');
                    galleryItem.classList.remove('unverified');
                    galleryItem.classList.add('verified');

                    const badge = galleryItem.querySelector('.verification-badge');
                    badge.classList.remove('unverified');
                    badge.classList.add('verified');
                    badge.innerHTML = '<span>✓ Verified</span>';

                    // Replace verify button with download button
                    const actionDiv = button.parentElement;
                    actionDiv.innerHTML = `<a href="/admin/image/${imageId}/download/" class="action-button download">Download</a>
                                          <a href="/admin/image/${imageId}/metadata/" class="action-button info">View Info</a>`;

                    // If modal is open, update that too
                    if (modal.style.display === 'block') {
                        modalMetadata.querySelector('td').textContent = '✓ Verified';
                        modalActions.innerHTML = `
                            <a href="/admin/image/${imageId}/download/" class="action-button download">Download</a>
                            <a href="/admin/image/${imageId}/metadata/" class="action-button info">View Full Info</a>
                        `;
                    }
                } else {
                    // Show error
                    button.textContent = 'Verification Failed';
                    button.style.backgroundColor = '#e74c3c';
                    setTimeout(() => {
                        button.textContent = 'Verify Now';
                        button.disabled = false;
                    }, 2000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                button.textContent = 'Error';
                button.style.backgroundColor = '#e74c3c';
                setTimeout(() => {
                    button.textContent = 'Verify Now';
                    button.disabled = false;
                }, 2000);
            });
        }
    });

    // Helper function to get CSRF token
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
});