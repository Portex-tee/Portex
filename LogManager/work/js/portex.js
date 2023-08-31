
// function decrypt(): the POST request body contains a text in a input area with id "dec-ciphertext", and the response is a string that shows in the readonly textarea with id "dec-plaintext"
function decrypt() {
    var ciphertext = document.getElementById("dec-ciphertext").value;
    var url = "http://121.41.111.120:8080/decrypt";
    var xhr = new XMLHttpRequest();
    var plaintext = document.getElementById("dec-plaintext");

    xhr.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            plaintext.innerHTML = this.responseText;
        }
    };

    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.send(ciphertext);
}

function encrypt() {
    var id = $('#id').val();
    var message = $('#message').val();
    var duration = document.getElementById('duration').value;
    var unit = document.getElementById('unit').value;
    var seconds;

    switch (unit) {
        case 'seconds':
            seconds = duration;
            break;
        case 'minutes':
            seconds = duration * 60;
            break;
        case 'hours':
            seconds = duration * 3600;
            break;
        case 'days':
            seconds = duration * 86400;
            break;
    }

    $.ajax({
        url: 'http://121.41.111.120:8080/encrypt',
        data: {id: id, message: message, seconds: seconds},
        type: 'GET',
        success: function (response) {
            $('#ciphertext').val(response);
        },
        error: function () {
            alert('An error occurred while encrypting the message.');
        }
    });
}

document.addEventListener("DOMContentLoaded", function() {
    const table = document.getElementById('LogTable');
    const rows = table.querySelectorAll('tr');

    rows.forEach(row => {
        // Assuming the 'Signature' column is the 3rd column
        let cell = row.children[4];
        if (cell) {
            let content = cell.textContent.replace(/"/g, '');  // Remove all double quotes
            let wrappedContent = '';
            let charCount = 16;

            for (let i = 0; i < content.length; i += charCount) {
                wrappedContent += content.substr(i, charCount) + (i + charCount < content.length ? '<br>' : '');
            }

            cell.innerHTML = wrappedContent;
        }
    });
});
