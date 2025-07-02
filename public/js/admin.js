const deleteResource = (btn) => {
    const resourceId = btn.parentNode.querySelector('[name=resourceId]').value;
    const csrfToken = btn.parentNode.querySelector('[name=_csrf]').value;
    
    const resourceElement = btn.closest('.item');
    
    fetch('/admin/resource/' + resourceId, {
        method: 'DELETE',
        headers: {
            'csrf-token': csrfToken
        }
    })
    .then(result => result.json())
    .then(data => {
        console.log(data);
        resourceElement.parentNode.removeChild(resourceElement);
    })
    .catch(err => console.log(err));
};