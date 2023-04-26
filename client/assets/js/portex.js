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

