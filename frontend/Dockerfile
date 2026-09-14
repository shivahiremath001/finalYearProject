FROM node:20-slim

WORKDIR /app

# Install dependencies first for better caching (ignore windows lockfile)
COPY package.json ./
RUN npm install

# Copy the rest of the application
COPY . .

# Expose the Vite port
EXPOSE 5173

# Run Vite development server bound to all network interfaces
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
