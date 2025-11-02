// Modal functionality for customer history page

// Transaction Details Modal Functions
function openTransactionDetailsModal(element) {
    const modal = document.getElementById('transactionDetailsModal');
    const transactionId = element.getAttribute('data-transaction-id');
    const transactionType = element.getAttribute('data-transaction-type');
    const transactionDate = element.getAttribute('data-transaction-date');
    const transactionAmount = element.getAttribute('data-transaction-amount');
    const transactionDescription = element.getAttribute('data-transaction-description');
    const transactionBillNo = element.getAttribute('data-transaction-bill-no');
    const transactionStatus = element.getAttribute('data-transaction-status');
    const transactionSource = element.getAttribute('data-transaction-source');
    const modificationReason = element.getAttribute('data-modification-reason');

    // Populate modal with transaction data
    document.getElementById('detail-date').textContent = transactionDate;
    document.getElementById('detail-amount').textContent = '₹' + transactionAmount;
    document.getElementById('detail-type').textContent = transactionType.charAt(0).toUpperCase() + transactionType.slice(1);
    document.getElementById('detail-description').textContent = transactionDescription;

    // Handle bill number
    const billRow = document.getElementById('detail-bill-row');
    if (transactionBillNo) {
        document.getElementById('detail-bill-no').textContent = transactionBillNo;
        billRow.style.display = 'flex';
    } else {
        billRow.style.display = 'none';
    }

    // Handle status/method
    const statusRow = document.getElementById('detail-status-row');
    const statusLabel = document.getElementById('detail-status-label');
    if (transactionType === 'debit') {
        statusLabel.textContent = 'Status:';
    } else {
        statusLabel.textContent = 'Method:';
    }
    document.getElementById('detail-status').textContent = transactionStatus;
    statusRow.style.display = 'flex';

    // Handle modification reason
    const modificationRow = document.getElementById('detail-modification-row');
    if (modificationReason) {
        document.getElementById('detail-modification-reason').textContent = modificationReason;
        modificationRow.style.display = 'flex';
    } else {
        modificationRow.style.display = 'none';
    }

    // Set up action buttons
    const viewBtn = document.getElementById('viewTransactionBtn');
    const editBtn = document.getElementById('editTransactionBtn');
    const deleteBtn = document.getElementById('deleteTransactionBtn');

    // Store transaction data for edit/delete operations
    modal.setAttribute('data-current-transaction-id', transactionId);
    modal.setAttribute('data-current-transaction-type', transactionType);

    viewBtn.href = `{{ url_for('view_customer_transaction', customer_id=customer.id, transaction_id='PLACEHOLDER') }}`.replace('PLACEHOLDER', transactionId);

    if (transactionSource === 'customer_transactions') {
        editBtn.style.display = 'inline-block';
        deleteBtn.style.display = 'inline-block';
        editBtn.onclick = function() {
            editTransaction(transactionId, transactionType);
        };
        deleteBtn.onclick = function() {
            deleteTransaction(transactionId, transactionType);
        };
    } else {
        editBtn.style.display = 'none';
        deleteBtn.style.display = 'none';
    }

    // Show modal
    modal.style.display = 'block';
    modal.focus();

    // Color code the modal based on transaction type
    const modalContent = modal.querySelector('.modal-content');
    if (transactionType === 'debit') {
        modalContent.style.borderLeft = '4px solid #28a745';
    } else {
        modalContent.style.borderLeft = '4px solid #dc3545';
    }
}

// Edit transaction function
function editTransaction(transactionId, transactionType) {
    // Redirect to edit page
    window.location.href = `{{ url_for('edit_customer_transaction', customer_id=customer.id, transaction_id='PLACEHOLDER') }}`.replace('PLACEHOLDER', transactionId);
}

// Delete transaction function
async function deleteTransaction(transactionId, transactionType) {
    if (!confirm(`Are you sure you want to delete this ${transactionType} transaction? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`{{ url_for('delete_customer_transaction', customer_id=customer.id, transaction_id='PLACEHOLDER') }}`.replace('PLACEHOLDER', transactionId), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'csrf_token': '{{ csrf_token() }}'
            })
        });

        if (response.ok) {
            // Close modal and refresh page
            closeTransactionDetailsModal();
            window.location.reload();
        } else {
            const result = await response.json();
            alert(result.message || 'Failed to delete transaction. Please try again.');
        }
    } catch (error) {
        console.error('Error deleting transaction:', error);
        alert('An error occurred while deleting the transaction. Please try again.');
    }
}

function closeTransactionDetailsModal() {
    document.getElementById('transactionDetailsModal').style.display = 'none';
}

function viewFullDetails() {
    // Expand modal to show additional details
    const modalContent = document.querySelector('#transactionDetailsModal .modal-content');
    const detailSection = document.querySelector('.transaction-detail-section');

    // Toggle expanded view
    if (modalContent.classList.contains('expanded')) {
        modalContent.classList.remove('expanded');
        detailSection.style.maxHeight = '';
        document.getElementById('viewFullDetailsBtn').textContent = '📄';
        document.getElementById('viewFullDetailsBtn').title = 'View Full Details';
    } else {
        modalContent.classList.add('expanded');
        detailSection.style.maxHeight = 'none';
        document.getElementById('viewFullDetailsBtn').textContent = '📖';
        document.getElementById('viewFullDetailsBtn').title = 'Collapse Details';
    }
}

// Initialize modal functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add click event listeners to all message bubbles
    const messageBubbles = document.querySelectorAll('.message-bubble');
    messageBubbles.forEach(bubble => {
        bubble.addEventListener('click', function() {
            openTransactionDetailsModal(this);
        });
    });

    // Close transaction details modal when clicking outside
    const transactionDetailsModal = document.getElementById('transactionDetailsModal');
    if (transactionDetailsModal) {
        transactionDetailsModal.addEventListener('click', function(event) {
            if (event.target === this) {
                closeTransactionDetailsModal();
            }
        });
    }

    // Close modal on Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeTransactionDetailsModal();
        }
    });
});