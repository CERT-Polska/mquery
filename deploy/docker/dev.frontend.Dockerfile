FROM node:18 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN yarn install --legacy-peer-deps
CMD ["npm", "start"]
