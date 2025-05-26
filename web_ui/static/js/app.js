// Wait for DOM content to be loaded
document.addEventListener('DOMContentLoaded', () => {
    const { createApp } = Vue;

    // Initialize Vue app with data from Flask
    createApp({
        data() {
            return {
                messages: [],
                newMessage: '',
                username: '',
                roomHash: '',
                connected: false,
                socket: null,
                error: null
            };
        },
        methods: {
            setupWebSocket() {
                // Connect to WebSocket server
                this.socket = io();
                
                // Handle connection events
                this.socket.on('connect', () => {
                    this.connected = true;
                    console.log('Connected to WebSocket server');
                });
                
                this.socket.on('disconnect', () => {
                    this.connected = false;
                    console.log('Disconnected from WebSocket server');
                });
                
                // Handle incoming messages
                this.socket.on('new_message', (message) => {
                    this.messages.push(message);
                    this.$nextTick(() => {
                        this.scrollToBottom();
                    });
                });
                
                // Handle errors
                this.socket.on('error', (data) => {
                    this.error = data.message;
                    setTimeout(() => {
                        this.error = null;
                    }, 5000);
                });
            },
            
            async loadMessages() {
                try {
                    const response = await fetch('/api/messages');
                    const data = await response.json();
                    if (data.success) {
                        this.messages = data.messages;
                        this.$nextTick(() => {
                            this.scrollToBottom();
                        });
                    }
                } catch (error) {
                    console.error('Failed to load messages:', error);
                }
            },
            
            async sendMessage() {
                if (!this.newMessage.trim()) return;
                
                if (this.connected) {
                    // Send via WebSocket
                    this.socket.emit('send_message', {
                        message: this.newMessage
                    });
                    this.newMessage = '';
                } else {
                    // Fallback to HTTP if WebSocket is not connected
                    try {
                        const response = await fetch('/api/send_message', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                message: this.newMessage
                            })
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            this.newMessage = '';
                        } else {
                            this.error = data.error;
                            setTimeout(() => {
                                this.error = null;
                            }, 5000);
                        }
                    } catch (error) {
                        console.error('Failed to send message:', error);
                    }
                }
            },
            
            scrollToBottom() {
                const container = this.$refs.messagesContainer;
                container.scrollTop = container.scrollHeight;
            },
            
            formatTimestamp(timestamp) {
                return new Date(timestamp * 1000).toLocaleTimeString();
            }
        },
        mounted() {
            // Get room info from page
            this.roomHash = document.getElementById('room-hash').value;
            this.username = document.getElementById('username').value;
            
            // Setup WebSocket
            this.setupWebSocket();
            
            // Initial message load
            this.loadMessages();
        }
    }).mount('#app');
}); 