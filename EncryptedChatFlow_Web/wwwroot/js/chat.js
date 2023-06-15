
"use strict";

var connection = new signalR.HubConnectionBuilder().withUrl(apiEndpoint).build();

// Disable send button until connection is established
$("#sendButton").disabled = true;

var userName = "";

connection.on("ReceiveMessage", function (time, user, message) {

    console.log("Received message:", time, user, message); // this should print the time, user and message in the browser console

    var encodedMsg = time + " " + user + " says " + message;
    var li = document.createElement("li");
    li.textContent = encodedMsg;
    document.getElementById("messagesList").appendChild(li);
});

connection.onclose(async () => {
    await start();
});

async function start() {
    try {
        await connection.start();
        console.log("SignalR Connected.");
        $("#sendButton").disabled = false;
    } catch (err) {
        console.log(err);
        setTimeout(() => start(), 5000);
    }
}

function sendMessage() {
    var user = userName;
    if (!userName) {
        user = document.getElementById("userInput").value;
        userName = user; // Store the username for later
    }
    var message = document.getElementById("messageInput").value;
    console.log("Sending message:", user, message); // this should print the user and message in the browser console
    connection.invoke("SendMessage", user, message).catch(function (err) {
        return console.error(err.toString());
    });
    // Clear the message input
    document.getElementById("messageInput").value = '';
}


$("#sendButton").on("click", function (event) {
    sendMessage();
    event.preventDefault();
});

// Add keypress handler for the message input field
$("#messageInput").on("keypress", function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == '13') {
        // User pressed 'Enter', send the message
        sendMessage();
        event.preventDefault();
    }
});

// Add a click handler to the "Clear" button
$("#clearButton").on("click", function () {
    var messageList = document.getElementById("messagesList");
    while (messageList.firstChild) {
        messageList.removeChild(messageList.firstChild);
    }
});

start();






