document.addEventListener("DOMContentLoaded", function() {
    const logsDiv = document.getElementById("logs");

    function fetchLogs() {
        fetch("/logs")
            .then(response => response.text())
            .then(data => {
                logsDiv.innerHTML = "";
                const logEntries = data.split("\n").filter(entry => entry.trim() !== "");
                logEntries.forEach(entry => {
                    const logEntryDiv = document.createElement("div");
                    logEntryDiv.className = "log-entry";

                    const timestamp = entry.substring(1, 20);
                    const message = entry.substring(22);

                    const timestampSpan = document.createElement("span");
                    timestampSpan.className = "log-timestamp";
                    timestampSpan.textContent = timestamp;

                    const messageSpan = document.createElement("span");
                    messageSpan.textContent = message;

                    logEntryDiv.appendChild(timestampSpan);
                    logEntryDiv.appendChild(messageSpan);
                    logsDiv.appendChild(logEntryDiv);
                });
            })
            .catch(error => console.error("Error fetching logs:", error));
    }

    fetchLogs();
    setInterval(fetchLogs, 5000);
});
