function encryptMessage() {
    const message = document.getElementById("message").value;
    if (!message) {
        alert("Please enter a message.");
        return;
    }

    fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            document.getElementById("iv").innerText = `IV: ${data.iv}`;
            document.getElementById("encrypted").innerText = `Encrypted: ${data.encrypted_message}`;
            document.getElementById("hmac").innerText = `HMAC: ${data.hmac}`;
            addMessageToList("You", message);  // Add message to list
            //document.getElementById("message").value = ""; // Clear input
        }
    })
    .catch(error => console.error('Error:', error));
}

function decryptMessage() {
    const ivText = document.getElementById("iv").innerText;
    const encryptedText = document.getElementById("encrypted").innerText;
    const hmacText = document.getElementById("hmac").innerText;

    console.log(`IV Text: ${ivText}`);
    console.log(`Encrypted Text: ${encryptedText}`);
    console.log(`HMAC Text: ${hmacText}`);

    const iv = ivText.split(': ')[1];
    const encryptedMessage = encryptedText.split(': ')[1];
    const hmac = hmacText.split(': ')[1];

    console.log(`IV: ${iv}`);
    console.log(`Encrypted Message: ${encryptedMessage}`);
    console.log(`HMAC: ${hmac}`);

    fetch('/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ iv, encrypted_message: encryptedMessage, hmac }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
            console.log(`Error: ${data.error}`);
        } else {
            document.getElementById("output").innerHTML = `Decrypted: ${data.decrypted_message}`;
            console.log(`Decrypted Message: ${data.decrypted_message}`);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert(`Error: ${error}`);
    });
}

function sendMessage() {
    const recipient = document.getElementById("recipient").value;
    const message = document.getElementById("message").value;
    if (!recipient || !message) {
        alert("Please enter a recipient and a message.");
        return;
    }

    addMessageToList(recipient, message);  // Add message to list

    // Clear all inputs and messages
    document.getElementById("recipient").value = ""; // Clear input
    document.getElementById("message").value = ""; // Clear input
    document.getElementById("iv").innerText = "";
    document.getElementById("encrypted").innerText = "";
    document.getElementById("hmac").innerText = "";
    document.getElementById("output").innerHTML = "";
    
    alert("Message sent!");
}

function addMessageToList(sender, message) {
    const messagesList = document.getElementById("messages-list");
    const messageItem = document.createElement("li");
    messageItem.textContent = `${sender}: ${message}`;
    messagesList.appendChild(messageItem);
    console.log(`Added message from ${sender}: ${message}`);  // Debug statement
}
