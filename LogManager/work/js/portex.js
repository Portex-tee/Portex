// function decrypt(): the POST request body contains a text in a input area with id "dec-ciphertext", and the response is a string that shows in the readonly textarea with id "dec-plaintext"
function decrypt() {
    var ciphertext = document.getElementById("dec-ciphertext").value;
    var url = "http://ac-dec.com:8080/decrypt";
    var xhr = new XMLHttpRequest();
    var plaintext = document.getElementById("dec-plaintext");
    var quote_out = document.getElementById("quote-out");

    xhr.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            // plaintext.innerHTML = this.responseText;
        //     this.responseText is a json string, which contains the plaintext string and the quote string
            var json = JSON.parse(this.responseText);
            plaintext.innerHTML = json.msg;
            quote_out.innerHTML = json.quote;
            fetchData();
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
        url: 'http://ac-dec.com:8080/encrypt',
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

function fetchData() {
    fetch('http://ac-dec.com/service')
        .then(response => response.json())
        .then(data => {
            let tbody = document.getElementById('LogTable').getElementsByTagName('tbody')[0];
            tbody.innerHTML = '';

            // 遍历数据，为每一行创建新的<tr>元素和<td>元素
            data.forEach(function(item) {
                let row = document.createElement('tr');

                let idCell = document.createElement('td');
                idCell.appendChild(document.createTextNode(item.id));
                row.appendChild(idCell);

                let snCell = document.createElement('td');
                snCell.appendChild(document.createTextNode(item.sn));
                row.appendChild(snCell);

                var protocolTimeCell = document.createElement('td');
                protocolTimeCell.appendChild(document.createTextNode(item.protocol));
                row.appendChild(protocolTimeCell);

                var decryptTimeCell = document.createElement('td');
                decryptTimeCell.appendChild(document.createTextNode(item.ts));
                row.appendChild(decryptTimeCell);

                let validityCell = document.createElement('td');
                if (item.valid === true) {
                    validityCell.innerHTML = '<span style="color: green;">Valid</span>';
                } else if (item.valid === false) {
                    validityCell.innerHTML = '<span style="color: red;">Invalid</span>';
                } else {
                    validityCell.appendChild(document.createTextNode('Unknown'));
                }
                row.appendChild(validityCell);

                let signatureCell = document.createElement('td');
                let content = item.sig;  // Remove all double quotes
                let wrappedContent = '';
                let charCount = 16;
                for (let i = 0; i < content.length; i += charCount) {
                    wrappedContent += content.substr(i, charCount) + (i + charCount < content.length ? '<br>' : '');
                }
                signatureCell.innerHTML = wrappedContent;
                row.appendChild(signatureCell);

                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('Error:', error));
}

document.addEventListener("DOMContentLoaded", function() {
    // 点击按钮后获取数据
    // document.querySelector('#decrypt-button').addEventListener('click', fetchData);

    // 页面加载时获取数据
    fetchData();

});
