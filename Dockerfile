FROM node:18
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p /usr/src/app/data && chmod 777 /usr/src/app/data
USER node
EXPOSE 3001
CMD ["node", "server.js"] 