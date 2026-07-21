// Modal Alpine.js Component
document.addEventListener('alpine:init', () => {
    Alpine.data('modal', (initialOpen = false) => ({
        open: initialOpen,

        init() {
            // Close on ESC key
            this.$watch('open', (value) => {
                if (value) {
                    document.body.style.overflow = 'hidden';
                    // Focus trap
                    this.$nextTick(() => {
                        this.$refs.modalContent?.focus();
                    });
                } else {
                    document.body.style.overflow = '';
                }
            });
        },

        show() {
            this.open = true;
        },

        hide() {
            this.open = false;
        },

        toggle() {
            this.open = !this.open;
        },

        handleKeydown(e) {
            if (e.key === 'Escape') {
                this.hide();
            }
        }
    }));
});
