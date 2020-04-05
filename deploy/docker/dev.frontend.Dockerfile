FROM node:8 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install
CMD ["npm", "start"]
