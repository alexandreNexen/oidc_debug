FROM node:20-alpine

WORKDIR /app

COPY package.json ./package.json
COPY src ./src
COPY public ./public
COPY README.md ./README.md

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "start"]
