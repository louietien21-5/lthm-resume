(function () {
  function getConfig() {
    var node = document.getElementById("passkey-config");
    if (!node) {
      return null;
    }

    try {
      return JSON.parse(node.textContent || "{}");
    } catch (error) {
      return null;
    }
  }

  function setFeedback(message) {
    var node = document.getElementById("passkey-feedback");
    if (!node) {
      return;
    }

    node.textContent = message || "";
    if (message) {
      node.classList.remove("hidden-message");
    } else {
      node.classList.add("hidden-message");
    }
  }

  function base64urlToArrayBuffer(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  function arrayBufferToBase64url(value) {
    var bytes = new Uint8Array(value);
    var binary = "";
    for (var index = 0; index < bytes.byteLength; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function normalizeCreationOptions(options) {
    options.challenge = base64urlToArrayBuffer(options.challenge);
    options.user.id = base64urlToArrayBuffer(options.user.id);
    if (Array.isArray(options.excludeCredentials)) {
      options.excludeCredentials = options.excludeCredentials.map(function (credential) {
        return Object.assign({}, credential, {
          id: base64urlToArrayBuffer(credential.id),
        });
      });
    }
    return options;
  }

  function normalizeRequestOptions(options) {
    options.challenge = base64urlToArrayBuffer(options.challenge);
    if (Array.isArray(options.allowCredentials)) {
      options.allowCredentials = options.allowCredentials.map(function (credential) {
        return Object.assign({}, credential, {
          id: base64urlToArrayBuffer(credential.id),
        });
      });
    }
    return options;
  }

  function registrationCredentialToJSON(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        transports: typeof credential.response.getTransports === "function" ? credential.response.getTransports() : [],
      },
    };
  }

  function authenticationCredentialToJSON(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        signature: arrayBufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle ? arrayBufferToBase64url(credential.response.userHandle) : null,
      },
    };
  }

  async function postJson(url, payload, csrfToken) {
    var response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify(payload || {}),
      credentials: "same-origin",
    });

    var data = {};
    try {
      data = await response.json();
    } catch (error) {
      data = {};
    }

    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }

    return data;
  }

  async function runRegistration(config, label) {
    if (!window.PublicKeyCredential) {
      throw new Error("Passkeys are not supported in this browser.");
    }

    var optionsPayload = await postJson(
      config.registerOptionsUrl,
      { label: label || "", nextPath: config.nextPath || "" },
      config.csrfToken
    );
    var publicKey = normalizeCreationOptions(optionsPayload.options);
    var credential = await navigator.credentials.create({ publicKey: publicKey });
    if (!credential) {
      throw new Error("Passkey registration was cancelled.");
    }

    return postJson(
      config.registerVerifyUrl,
      { credential: registrationCredentialToJSON(credential) },
      config.csrfToken
    );
  }

  async function runAuthentication(config) {
    if (!window.PublicKeyCredential) {
      throw new Error("Passkeys are not supported in this browser.");
    }

    var optionsPayload = await postJson(
      config.authenticateOptionsUrl,
      { nextPath: config.nextPath || "" },
      config.csrfToken
    );
    var publicKey = normalizeRequestOptions(optionsPayload.options);
    var credential = await navigator.credentials.get({ publicKey: publicKey });
    if (!credential) {
      throw new Error("Passkey sign-in was cancelled.");
    }

    return postJson(
      config.authenticateVerifyUrl,
      { credential: authenticationCredentialToJSON(credential) },
      config.csrfToken
    );
  }

  document.addEventListener("DOMContentLoaded", function () {
    var config = getConfig();
    if (!config) {
      return;
    }

    var setupForm = document.getElementById("setup-secret-form");
    if (setupForm) {
      setupForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        setFeedback("");
        var formData = new FormData(setupForm);

        try {
          await postJson(config.setupUrl, { secret: formData.get("secret") || "" }, config.csrfToken);
          window.location.reload();
        } catch (error) {
          setFeedback(error.message);
        }
      });
    }

    var registerButton = document.getElementById("passkey-register-button");
    if (registerButton) {
      registerButton.addEventListener("click", async function () {
        setFeedback("");
        registerButton.disabled = true;
        var labelInputId = registerButton.getAttribute("data-passkey-label-input");
        var labelInput = labelInputId ? document.getElementById(labelInputId) : null;

        try {
          var result = await runRegistration(config, labelInput ? labelInput.value : "");
          window.location.href = result.redirectTo || config.passkeysUrl || "/";
        } catch (error) {
          setFeedback(error.message);
        } finally {
          registerButton.disabled = false;
        }
      });
    }

    var authenticateButton = document.getElementById("passkey-authenticate-button");
    if (authenticateButton) {
      authenticateButton.addEventListener("click", async function () {
        setFeedback("");
        authenticateButton.disabled = true;

        try {
          var result = await runAuthentication(config);
          window.location.href = result.redirectTo || "/";
        } catch (error) {
          setFeedback(error.message);
        } finally {
          authenticateButton.disabled = false;
        }
      });
    }
  });
})();
