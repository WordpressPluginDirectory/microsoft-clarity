const MessageOperation = {
	PROJECT_ID_CHANGE: 1,
};

const projectActionCallback = (event) => {
	if (event.origin !== "https://clarity.microsoft.com") return;
	const postedMessage = event?.data;
	if (
		postedMessage?.operation !== MessageOperation.PROJECT_ID_CHANGE ||
		postedMessage?.id === undefined ||
		postedMessage?.id === null
	) {
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
			},
			dataType: "json",
		})
		.done(function (json) {
			if (!json.success) {
				console.log(
					`Failed to ${isRemoveRequest ? "remove" : "add"} Clarity snippet${
						isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`
					}`
				);
			} else {
				console.log(
					`${isRemoveRequest ? "Removed" : "Added"} Clarity snippet${
						isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`
					}`
				);
			}
		})
		.fail(function () {
			console.log(
				`Failed to ${isRemoveRequest ? "remove" : "add"} Clarity snippet${
					isRemoveRequest ? "." : ` for project ${postedMessage?.id}.`
				}`
			);
		});
};

window.addEventListener("message", projectActionCallback, false);
