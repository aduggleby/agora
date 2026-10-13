/**
 * Copies text to the clipboard: the async Clipboard API first, the hidden-textarea fallback where it is
 * unavailable (insecure origins, older browsers). Resolves true when the text was copied.
 */
export async function copyText(value: string): Promise<boolean> {
  if (!value) return false;

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Permission denied or no focus: try the fallback below.
  }

  return fallbackCopy(value);
}

function fallbackCopy(value: string): boolean {
  const input = document.createElement('textarea');
  input.value = value;
  input.setAttribute('readonly', 'readonly');
  input.style.position = 'absolute';
  input.style.left = '-9999px';
  document.body.appendChild(input);
  input.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  document.body.removeChild(input);
  return ok;
}
