# Silent - Secure End-to-End Encrypted Messaging

Silent is a modern, high-security messaging application that implements state-of-the-art cryptographic protocols to ensure your conversations remain private, secure, and only accessible to you and your intended recipients.

![Silent App Logo](client/assets/logo.png)

## Features

- **True End-to-End Encryption**: Messages are encrypted on your device and can only be decrypted by the recipient
- **Perfect Forward Secrecy**: Using the Double Ratchet Algorithm, each message uses a new encryption key
- **Self-Destructing Messages**: Messages are automatically deleted from the server after being read
- **Offline Messaging**: Messages are stored securely until the recipient comes online
- **Media Sharing**: Share images securely with end-to-end encryption
- **Contact Verification**: Verify your contacts through secure invitation system
- **No Phone Number Required**: Use a username instead of phone number for enhanced privacy
- **Local Message Storage**: Messages are stored securely on your device using SecureStore

## Security Architecture

Silent implements multiple layers of security:

- **X3DH (Extended Triple Diffie-Hellman)** for secure key exchange and initial authentication
- **Double Ratchet Algorithm** (same protocol used by Signal) for perfect forward secrecy
- **XSalsa20-Poly1305** encryption for message content with 256-bit keys
- **Enhanced Entropy** using Python-seeded random number generation
- **NaCl/TweetNaCl** cryptographic library for proven security primitives
- **Message Self-Destruction** once read and acknowledged
- **Secure Local Storage** using Expo SecureStore for encrypted message persistence

## Technical Stack

### Frontend (Mobile App)

- React Native with Expo
- TweetNaCl.js for cryptography
- SecureStore for secure local storage
- Socket.io client for real-time communication

### Backend

- Node.js with Express
- MongoDB for temporary message storage
- Socket.io for real-time messaging
- JWT for authentication

### Entropy Server

- Python Flask server
- Video-based entropy generation
- Hardware sensors for additional entropy

## Supported Media Formats

Silent supports the following media formats for secure sharing:

- Images: JPEG, PNG

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- MongoDB (v4.4 or higher)
- Python 3.8+ with pip (for entropy server)
- Expo CLI (`npm install -g expo-cli`)
- Android Studio (for Android development) or Xcode (for iOS development)

### Installation

#### 1. Setup the Entropy Server (PyRand)


1. Create a Videos directory for entropy sources

   ```
   mkdir -p Videos
   ```

2. Add video files to the Videos directory

   - Supported formats: .mp4, .avi, .mov, .mkv, .webm, .wmv, .flv, .m4v
   - These videos will be used for entropy generation

3. Install required Python packages

   ```
   pip install flask flask-cors opencv-python numpy
   ```

4. Start the entropy server

   ```
   python entropy_server.py
   ```

   The entropy server will run on http://0.0.0.0:5000

#### 2. Server Setup

1. Navigate to the server directory

   ```
   cd server
   ```

2. Install dependencies

   ```
   npm install
   ```

3. Set up environment variables
   Create a `.env` file in the server directory with the following variables:

   ```
   PORT=3000
   MONGO_URI=mongodb://localhost:27017/silent
   JWT_SECRET=your_jwt_secret_key
   NODE_ENV=development
   ```

4. Start the server

   ```
   npm run dev
   ```

   The server will run on http://0.0.0.0:3000

#### 3. Client Setup

1. Navigate to the client directory

   ```
   cd client
   ```

2. Install dependencies

   ```
   npm install
   ```

3. Start the Expo development server

   ```
   npx expo start
   ```

4. Run on device or emulator
   - Press 'a' to run on Android emulator
   - Press 'i' to run on iOS simulator
   - Or scan the QR code with the Expo Go app on your device

## Usage

1. **Registration**: Create a new account using a username and password
2. **Adding Contacts**: Search for users and send contact requests
3. **Messaging**: Start encrypted conversations with accepted contacts
4. **Media Sharing**: Share images and videos securely
5. **Message Status**: Track when messages are sent, delivered, and seen

## Security Considerations

- Silent is designed for maximum security and privacy
- All message content is encrypted on the sender's device and can only be decrypted on the recipient's device
- The server never has access to decryption keys or message content
- Messages are removed from the server after delivery and confirmation
- All cryptographic operations use proven libraries and algorithms

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Signal Protocol for inspiration on the Double Ratchet Algorithm
- The TweetNaCl.js team for their lightweight cryptographic library
- The Expo team for their secure storage solutions

---
