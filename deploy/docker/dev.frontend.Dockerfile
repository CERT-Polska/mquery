FROM node:16 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install --legacy-peer-deps
CMD ["npm", "start"]
