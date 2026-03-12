const MessageOperation = {
  PROJECT_ID_CHANGE: 1,
  REDIRECT: 2,
  AGENT_ENABLED_CHANGE: 4,
};

const isValidProjectId = (id) => {
  if (id === null || id === undefined || typeof id !== "string") {
    return false;
  }
  const pattern = /^[a-zA-Z0-9]*$/;
  return pattern.test(id);
};

const projectActionCallback = (event) => {
  if (event.origin !== "https://clarity.microsoft.com") return;
  const postedMessage = event?.data;
  if (postedMessage?.operation !== MessageOperation.PROJECT_ID_CHANGE || !isValidProjectId(postedMessage?.id)) {
    return;
  }
  const isRemoveRequest = postedMessage?.id === "";
  jQuery
    .ajax({
      method: "POST",
      url: ajaxurl,
      data: {
        action: "edit_clarity_project_id",
        new_value: isRemoveRequest ? "" : postedMessage?.id,
        user_must_be_admin: postedMessage?.userMustBeAdmin,
        nonce: postedMessage?.nonce,
      },
      dataType: "json",
    })
    .done(function (json) {
      if (!json.success) {
        console.log(
          `Failed to ${isRemoveRequest ? "remove" : "add"} Clarity snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
        );
      } else {
        console.log(
          `${isRemoveRequest ? "Removed" : "Added"} Clarity snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
        );
      }
    })
    .fail(function () {
      console.log(
        `Failed to ${isRemoveRequest ? "remove" : "add"} Clarity snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
      );
    });
};

const agentsActionCallback = (event) => {
  if (event.origin !== "https://clarity.microsoft.com") return;
  const postedMessage = event?.data;
  if (postedMessage?.operation !== MessageOperation.AGENT_ENABLED_CHANGE) return;

  const isRemoveRequest = postedMessage?.status === false;
  const agent_status = postedMessage?.status === false ? 0 : 1;

  jQuery
    .ajax({
      method: "POST",
      url: ajaxurl,
      data: {
        action: "edit_agent_enabled_status",
        new_value: agent_status,
        user_must_be_admin: postedMessage?.userMustBeAdmin,
        nonce: postedMessage?.nonce,
      },
      dataType: "json",
    })
    .done(function (json) {
      if (!json.success) {
        console.log(
          `Failed to ${isRemoveRequest ? "remove" : "add"} Agent snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
        );
      } else {
        console.log(
          `${isRemoveRequest ? "Removed" : "Added"} Agent snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
        );
      }
    })
    .fail(function () {
      console.log(
        `Failed to ${isRemoveRequest ? "remove" : "add"} Agent snippet${isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`}`,
      );
    });
};

const redirectActionCallback = (event) => {
  const siteOrigin = window.location.origin;
  
  // SECURITY: Only accept messages from Clarity dashboard or our own site
  if (event.origin !== "https://clarity.microsoft.com" && event.origin !== siteOrigin) {
    return;
  }
  
  // Check if the message has the correct structure
  const postedMessage = event?.data;
  if (!postedMessage || postedMessage.operation !== MessageOperation.REDIRECT || !postedMessage.redirectURL) {
    return;
  }
  
  const redirectURL = postedMessage.redirectURL;
  
  // SECURITY: Validate the redirect URL is a WordPress admin URL on our domain
  if (redirectURL.indexOf(siteOrigin + "/wp-admin/") !== 0) {
    return;
  }
  
  // SECURITY: Only allow specific WordPress admin pages
  const allowedPages = [
    "/wp-admin/options-permalink.php",
  ];
  
  const pageAllowed = allowedPages.some(page => redirectURL.indexOf(page) !== -1);
  
  if (!pageAllowed) {
    return;
  }
  
  // Open in a new tab (bypasses iframe sandbox restrictions)
  window.open(redirectURL, "_blank");
};

window.addEventListener("message", redirectActionCallback, false);
window.addEventListener("message", agentsActionCallback, false);
window.addEventListener("message", projectActionCallback, false);
