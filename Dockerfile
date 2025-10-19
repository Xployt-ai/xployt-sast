FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

RUN npm ci --only=production

EXPOSE 8001

CMD ["npm", "start"]
