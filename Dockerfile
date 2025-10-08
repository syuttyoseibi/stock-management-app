
FROM node:lts-alpine
WORKDIR /app
COPY package*.json ./
RUN apk add --no-cache python3 make g++
RUN npm install
RUN mkdir data
COPY . .
CMD ["node", "server.js"]
