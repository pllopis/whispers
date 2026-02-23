const COPY_SUCCESS_DURATION_MS = 1800;

document.querySelectorAll('.copy-button').forEach((button) => {
    button.addEventListener('click', async () => {
        const targetId = button.getAttribute('data-copy-target');
        const target = targetId ? document.getElementById(targetId) : null;
        if (!target) {
            return;
        }

        const text = target.value ?? target.textContent ?? '';
        if (!text) {
            return;
        }

        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
            } else {
                const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA';
                if (isInput) {
                    target.select();
                    target.setSelectionRange(0, text.length);
                    document.execCommand('copy');
                } else {
                    const temp = document.createElement('textarea');
                    temp.value = text;
                    temp.setAttribute('readonly', '');
                    temp.style.position = 'absolute';
                    temp.style.left = '-9999px';
                    document.body.appendChild(temp);
                    temp.select();
                    document.execCommand('copy');
                    document.body.removeChild(temp);
                }
            }

            button.classList.add('copied');
            const previousText = button.textContent;
            button.textContent = 'Copied!';
            setTimeout(() => {
                button.classList.remove('copied');
                button.textContent = previousText;
            }, COPY_SUCCESS_DURATION_MS);
        } catch (err) {
            console.error('Failed to copy', err);
        }
    });
});
