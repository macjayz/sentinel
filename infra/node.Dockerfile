FROM node:22-alpine AS build
WORKDIR /app
ARG WORKSPACE
COPY package.json package-lock.json* tsconfig.json eslint.config.js .prettierrc ./
COPY packages ./packages
COPY apps ./apps
RUN npm install
RUN npm run build -w packages/shared
RUN npm run build -w ${WORKSPACE}

FROM node:22-alpine
WORKDIR /app
ARG WORKSPACE
ENV NODE_ENV=production
ENV WORKSPACE=${WORKSPACE}
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json* ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/packages ./packages
COPY --from=build --chown=node:node /app/${WORKSPACE} ./${WORKSPACE}
USER node
CMD ["sh", "-c", "npm run start -w $WORKSPACE"]
