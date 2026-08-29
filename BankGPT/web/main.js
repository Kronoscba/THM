document.addEventListener("DOMContentLoaded", () => {
  const updateLastCheck = () => {
    const lastCheck = document.querySelector("#last-check");
    const now = new Date();
    const timeString = now.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    lastCheck.textContent = timeString;
  };

  setInterval(updateLastCheck, 30000); // Update every 30 seconds
  updateLastCheck(); // Initial update

  window.suggestQuery = (query) => {
    const textarea = document.querySelector("#text");
    textarea.value = query;
    textarea.focus();
    resizeTextarea();
  };

  const form = document.querySelector("form");
  const chatBox = document.querySelector("#chatbox");
  const chatBoxHolder = document.querySelector("#chatbox-holder");
  const submitButton = document.querySelector("#submit-button");
  const textarea = document.querySelector("#text");
  const toastContainer = document.querySelector("#toast-container");
  let stickyChatbox = true;
  let isProcessing = false;

  // Auto-resize textarea
  const resizeTextarea = () => {
    const previousHeight = textarea.style.height;
    textarea.style.height = "auto";
    const newHeight = Math.min(textarea.scrollHeight, 200);
    textarea.style.height = newHeight + "px";

    // If height changed and we're in sticky mode, scroll chat
    if (previousHeight !== newHeight + "px" && stickyChatbox) {
      // Use requestAnimationFrame to ensure the textarea has been resized
      requestAnimationFrame(() => {
        chatBoxHolder.scrollTop = chatBoxHolder.scrollHeight;
      });
    }
  };

  textarea.addEventListener("input", resizeTextarea);

  const submitMessage = async () => {
    const text = textarea.value.trim();
    if (!isProcessing && text) {
      textarea.value = "";
      textarea.style.height = "auto"; // Reset height
      await handleSubmit(text);
    }
  };

  // Handle button click
  submitButton.addEventListener("click", submitMessage);

  // Handle Enter key
  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      if (e.shiftKey) {
        // Allow new line with Shift+Enter
        return;
      }
      // Submit on Enter without Shift
      e.preventDefault();
      submitMessage();
    }
  });

  const convertToHtml = (text) => {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;")
      .replace(/\n/g, "<br>");
  };

  const botStateEnum = {
    IDLE: "IDLE",
    THINKING: "THINKING",
    STREAMING: "STREAMING",
  };

  const botStateUpdateEvent = new CustomEvent("botStateUpdate", {
    detail: {
      state: botStateEnum.IDLE,
    },
    bubbles: true,
  });

  document.addEventListener("botStateUpdate", (event) => {
    const currentBotState = event.detail.state;
    const botThinking = document.querySelector("#bot-thinking");
    const input = document.querySelector("#text");

    if (currentBotState === botStateEnum.IDLE) {
      botThinking.classList.add("hidden");
      submitButton.disabled = false;
      submitButton.classList.remove("opacity-50", "cursor-not-allowed");
      input.disabled = false;
      isProcessing = false;
    } else {
      botThinking.classList.remove("hidden");
      submitButton.disabled = true;
      submitButton.classList.add("opacity-50", "cursor-not-allowed");
      input.disabled = true;
      isProcessing = true;
    }
  });

  chatBoxHolder.addEventListener("scroll", () => {
    const diff = Math.abs(
      chatBoxHolder.scrollTop -
        chatBoxHolder.scrollHeight +
        chatBoxHolder.clientHeight
    );
    stickyChatbox = diff <= 100;
  });

  const createMessageElement = (
    text,
    isUser,
    failed = false,
    errorMessage = ""
  ) => {
    const messageDiv = document.createElement("div");
    messageDiv.className = `flex ${isUser ? "justify-end" : "justify-start"}`;

    const innerDiv = document.createElement("div");
    innerDiv.className = "max-w-[85%] group relative items-start";

    innerDiv.innerHTML = `
      <div class="${
        failed
          ? "bg-red-500/10 border border-red-500/50 text-red-200"
          : isUser
          ? "bg-gradient-to-r from-teal-500 to-blue-500 text-white"
          : "bg-thm-800 text-gray-100"
      } rounded-2xl px-4 py-2 shadow-sm">
        <div class="prose prose-invert max-w-none">
          ${convertToHtml(text)}
        </div>
        ${
          failed
            ? `<div class="text-xs mt-1 text-red-200 cursor-pointer retry-message">${errorMessage}</div>`
            : ""
        }
      </div>
      ${
        !failed
          ? `
      <div class="absolute top-2 ${
        isUser ? "-left-10" : "-right-10"
      } opacity-0 group-hover:opacity-100 transition-opacity">
        <button class="text-thm-500 hover:text-thm-300 p-1 copy-button" title="Copy message">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
            <path d="M8 2a1 1 0 000 2h2a1 1 0 100-2H8z" />
            <path d="M3 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v6h-4.586l1.293-1.293a1 1 0 00-1.414-1.414l-3 3a1 1 0 000 1.414l3 3a1 1 0 001.414-1.414L10.414 13H15v3a2 2 0 01-2 2H5a2 2 0 01-2-2V5zM15 11h2a1 1 0 110 2h-2v-2z" />
          </svg>
        </button>
      </div>
      `
          : ""
      }`;

    if (isUser) {
      // Add copy functionality
      const copyButton = innerDiv.querySelector(".copy-button");
      if (copyButton) {
        copyButton.addEventListener("click", () => {
          const textToCopy = text;
          navigator.clipboard.writeText(textToCopy).then(() => {
            showToast("Message copied to clipboard");
          });
        });
      }
    }
    // Add retry functionality for failed messages
    const retryMessage = innerDiv.querySelector(".retry-message");
    if (retryMessage) {
      retryMessage.addEventListener("click", () => handleSubmit(text));
    }

    messageDiv.appendChild(innerDiv);
    return messageDiv;
  };

  const showToast = (message, duration = 2000) => {
    const toast = document.createElement("div");
    toast.className =
      "bg-thm-800/90 text-thm-100 px-4 py-2 rounded-lg text-sm shadow-lg transform tranthm-y-2 opacity-0 transition-all duration-300";
    toast.textContent = message;

    toastContainer.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
      toast.classList.remove("tranthm-y-2", "opacity-0");
    });

    setTimeout(() => {
      toast.classList.add("tranthm-y-2", "opacity-0");
      setTimeout(() => toast.remove(), 300);
    }, duration);
  };

  const handleSubmit = async (text) => {
    if (isProcessing) {
      return; // Prevent multiple submissions
    }

    // Add user message
    const messageDiv = createMessageElement(text, true);
    chatBox.appendChild(messageDiv);

    if (stickyChatbox) {
      chatBoxHolder.scrollTop = chatBoxHolder.scrollHeight;
    }

    // Show thinking indicator and disable input
    botStateUpdateEvent.detail.state = botStateEnum.THINKING;
    document.dispatchEvent(botStateUpdateEvent);

    try {
      const formData = new FormData();
      formData.append("msg", text);

      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

      const response = await fetch("/message", {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      clearTimeout(timeoutId); // Clear timeout if request completes

      if (response.ok) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let currentMessageDiv = createMessageElement("", false);
        chatBox.appendChild(currentMessageDiv);
        const textDiv = currentMessageDiv.querySelector(".prose");
        let fullText = "";

        botStateUpdateEvent.detail.state = botStateEnum.STREAMING;
        document.dispatchEvent(botStateUpdateEvent);

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          fullText += chunk;
          textDiv.innerHTML = convertToHtml(fullText);

          if (stickyChatbox) {
            chatBoxHolder.scrollTop = chatBoxHolder.scrollHeight;
          }
        }

        // Add copy functionality
        const copyButton = currentMessageDiv.querySelector(".copy-button");
        if (copyButton) {
          copyButton.addEventListener("click", () => {
            const textToCopy = textDiv.textContent;
            navigator.clipboard.writeText(textToCopy).then(() => {
              showToast("Message copied to clipboard");
            });
          });
        }
      } else {
        throw new Error("Failed to get response");
      }
    } catch (error) {
      console.error("Error:", error);
      // Remove the original message
      messageDiv.remove();

      // Add appropriate error message based on the error type
      const errorMessage =
        error.name === "AbortError"
          ? "Request timed out after 30 seconds. Click to retry."
          : "Failed to send - Click to retry";

      // Add it back with the failed state and custom error message
      chatBox.appendChild(createMessageElement(text, true, true, errorMessage));
    } finally {
      botStateUpdateEvent.detail.state = botStateEnum.IDLE;
      document.dispatchEvent(botStateUpdateEvent);
      if (stickyChatbox) {
        chatBoxHolder.scrollTop = chatBoxHolder.scrollHeight;
      }
    }
  };
});
