// Big uploads are encrypted three times and take a few seconds; stop double submits.
document.addEventListener("submit", (e) => {
  const button = e.target.querySelector("button[data-busy]");
  if (!button) return;
  button.disabled = true;
  button.textContent = button.dataset.busy;
});
