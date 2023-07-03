"use strict";

// Function to get a cookie by its name
function getCookie(name) {
    let cookieArr = document.cookie.split(";");
    for (let i = 0; i < cookieArr.length; i++) {
        let cookiePair = cookieArr[i].split("=");
        console.log('Checking cookie:', cookiePair);  // Debug log
        if (name == cookiePair[0].trim()) {
            console.log('Found cookie:', name, 'with value:', cookiePair[1]);  // Debug log
            return decodeURIComponent(cookiePair[1]);
        }
    }
    console.log('Cookie not found:', name);  // Debug log
    return null;
}

// Function to handle token error or expiration
function handleTokenError() {
    // Redirect user to the login page
    window.location.href = '/Accounts/Login';
}

// Main function to handle the chat setup
function main() {
    const token = getCookie('jwt_cookie');
    if (!token) {
        handleTokenError();
        return; // End the execution if token is not found
    }
    console.log('Found cookie: jwt_cookie with value: ' + token);

    $.ajax({
        url: apiEndpoint + '/api/token',
        type: 'POST',
        beforeSend: function (xhr) { xhr.setRequestHeader('Authorization', 'Bearer ' + token); },
        success: function (data) {
            console.log('AJAX request succeeded');
            startChatConnection();  // Call 'startChatConnection'
        },
        error: function (jqXhr, textStatus, errorThrown) {
            console.log('AJAX request failed: ', textStatus, errorThrown);
            handleTokenError();
        }
    });


    function startChatConnection() {
        var apiEndpoint = 'https://localhost:44305/chathub';

        var connection = new signalR.HubConnectionBuilder().withUrl(apiEndpoint, { accessTokenFactory: () => token }).build();

        // Disable send button until connection is established
        document.getElementById("sendButton").disabled = true;

        var userName = "";

        connection.on("ReceiveMessage", function (time, user, message) {
            var encodedMsg = time + " " + user + " says " + message;
            var li = document.createElement("li");
            li.textContent = encodedMsg;
            document.getElementById("messagesList").appendChild(li);
        });

        connection.onclose(async () => {
            console.log('SignalR connection closed');
            await start();
        });

        connection.on("AccessTokenExpired", handleTokenError);

        async function start() {
            try {
                await connection.start();
                console.log("SignalR Connected.");
                document.getElementById("sendButton").disabled = false;
            } catch (err) {
                console.log(err);
                setTimeout(() => start(), 5000);
            }
        };

        function sendMessage() {
            var user = userName;
            if (!userName) {
                user = document.getElementById("userInput").value;
                userName = user; // Store the username for later
            }
            var message = document.getElementById("messageInput").value;
            connection.invoke("SendMessage", user, message).catch(function (err) {
                return console.error(err.toString());
            });
            // Clear the message input
            document.getElementById("messageInput").value = '';
        };

        document.getElementById("sendButton").addEventListener("click", function (event) {
            sendMessage();
            event.preventDefault();
        });

        // Add keypress handler for the message input field
        document.getElementById("messageInput").addEventListener("keypress", function (event) {
            var keycode = (event.keyCode ? event.keyCode : event.which);
            if (keycode == '13') {
                // User pressed 'Enter', send the message
                sendMessage();
                event.preventDefault();
            }
        });

        // Add a click handler to the "Clear" button
        document.getElementById("clearButton").addEventListener("click", function () {
            var messageList = document.getElementById("messagesList");
            while (messageList.firstChild) {
                messageList.removeChild(messageList.firstChild);
            }
        });

        start();
    }
}

document.addEventListener('DOMContentLoaded', main);













