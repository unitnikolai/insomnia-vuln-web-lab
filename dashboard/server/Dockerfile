FROM node:20-alpine
RUN apk add --no-cache bash git perl docker-cli docker-cli-compose
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY src ./src
EXPOSE 3000
CMD ["node", "src/index.js"]
