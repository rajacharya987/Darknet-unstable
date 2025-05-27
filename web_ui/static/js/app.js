// Wait for DOM content to be loaded
document.addEventListener('DOMContentLoaded', () => {
    const { createApp } = Vue;

    // Initialize Vue app with data from Flask
    createApp({
        data() {
            return {
                messages: [],
                newMessage: '',
                username: INITIAL_DATA.username,
                roomHash: INITIAL_DATA.roomHash,
                publicIp: INITIAL_DATA.publicIp,
                port: INITIAL_DATA.port,
                messageCheckInterval: null,
                lastMessageId: -1,
                baseUrl: `http://${INITIAL_DATA.roomHash}.aegisnet`
            };
        },
        methods: {
            async sendMessage() {
                if (!this.newMessage.trim()) return;
                
                try {
                    const response = await fetch(`${this.baseUrl}/api/send_message`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            message: this.newMessage
                        })
                    });
                    
                    if (response.ok) {
                        // Clear input but don't add message (it will come through polling)
                        this.newMessage = '';
                    } else {
                        const data = await response.json();
                        console.error('Failed to send message:', data.error);
                    }
                } catch (error) {
                    console.error('Failed to send message:', error);
                }
            },
            async checkNewMessages() {
                try {
                    const response = await fetch(`${this.baseUrl}/api/messages`);
                    if (response.ok) {
                        const data = await response.json();
                        if (data.success && data.messages) {
                            // Add only new messages
                            const newMessages = data.messages.filter(msg => msg.id > this.lastMessageId);
                            if (newMessages.length > 0) {
                                this.messages.push(...newMessages);
                                this.lastMessageId = Math.max(...data.messages.map(m => m.id));
                                
                                // Scroll to bottom
                                this.$nextTick(() => {
                                    const chatDiv = document.getElementById('chat-messages');
                                    chatDiv.scrollTop = chatDiv.scrollHeight;
                                });
                            }
                        }
                    }
                } catch (error) {
                    console.error('Failed to check messages:', error);
                }
            }
        },
        mounted() {
            // Start checking for new messages
            this.messageCheckInterval = setInterval(this.checkNewMessages, 1000);
            
            // Initial message check
            this.checkNewMessages();
        },
        beforeUnmount() {
            // Clean up interval
            if (this.messageCheckInterval) {
                clearInterval(this.messageCheckInterval);
            }
        }
    }).mount('#app');
}); 