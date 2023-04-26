function encrypt() {
    var id = document.getElementById("id").value;
    var message = document.getElementById("message").value;
    var url = "/encrypt?id=" + id + "&message=" + message;
    var xhr = new XMLHttpRequest();
    var ciphertext = document.getElementById("ciphertext").innerHTML;

    xhr.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            document.getElementById("ciphertext").innerHTML = this.responseText;
        }
    };

    xhr.open("GET", url, true);
    xhr.send();
}

// function decrypt(): the POST request body contains a text in a input area with id "dec-ciphertext", and the response is a string that shows in the readonly textarea with id "dec-plaintext"
function decrypt() {
    var ciphertext = document.getElementById("dec-ciphertext").value;
    var url = "/decrypt";
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
