FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
COPY packages ./packages
COPY apps/dashboard ./apps/dashboard
RUN npm install
EXPOSE 5173
CMD ["npm", "run", "dev", "-w", "apps/dashboard"]
