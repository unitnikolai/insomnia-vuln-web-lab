FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .

# Self-signed TLS cert so gate can terminate HTTPS itself (same click-through
# warning attendees already got from Kasm's own cert, just one hop earlier).
RUN apk add --no-cache openssl \
 && mkdir -p /app/certs \
 && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /app/certs/key.pem -out /app/certs/cert.pem \
      -subj "/CN=vuln-lab-gate" \
      -addext "subjectAltName=DNS:localhost,DNS:gate,DNS:attack-box"

EXPOSE 6901
CMD ["node", "server.js"]
