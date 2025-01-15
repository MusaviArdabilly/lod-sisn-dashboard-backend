# Use the official Node.js image
FROM node:18-alpine

# Install CA certificates for SSL
RUN apk update && apk add --no-cache ca-certificates

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port your Express app runs on
EXPOSE 3000

# Start the Express app
CMD ["npm", "start"]
