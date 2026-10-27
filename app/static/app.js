// Big uploads are encrypted three times and take a few seconds; stop double submits.
document.addEventListener("submit", (e) => {
  const button = e.target.querySelector("button[data-busy]");
  if (!button) return;
  button.disabled = true;
  button.textContent = button.dataset.busy;
});

// Expandable detail rows: <button data-toggle="row-id"> shows or hides the element with that id.
document.addEventListener("click", (e) => {
  const button = e.target.closest("[data-toggle]");
  if (!button) return;
  const target = document.getElementById(button.dataset.toggle);
  const open = target.classList.toggle("hidden") === false;
  button.setAttribute("aria-expanded", String(open));
  const icon = button.querySelector(".toggle-icon");
  if (icon) icon.textContent = open ? "▴" : "▾";
});
