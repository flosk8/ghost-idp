# Use the official Golang image
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application. The '.' ensures all .go files are included.
RUN CGO_ENABLED=0 GOOS=linux go build -o ghost-idp .

# Use a minimal distroless image for the final stage
FROM gcr.io/distroless/static-debian11
COPY --from=builder /app/ghost-idp /
EXPOSE 8080
CMD ["/ghost-idp"]
