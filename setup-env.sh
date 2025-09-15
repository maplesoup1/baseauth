#!/bin/bash

# SecureAuth.NetCore Environment Setup Script
# Run this script to set up environment variables for development

echo "Setting up environment variables for SecureAuth.NetCore..."

# JWT Secret (REQUIRED - must be at least 32 characters)
export JWT_SECRET="your-super-secret-jwt-key-here-must-be-at-least-32-characters-long"

# OAuth Provider Configuration (Optional - fill in your own values)
# export GOOGLE_CLIENT_ID="your-google-client-id"
# export GOOGLE_CLIENT_SECRET="your-google-client-secret"
# export FACEBOOK_APP_ID="your-facebook-app-id"
# export FACEBOOK_APP_SECRET="your-facebook-app-secret"
# export MICROSOFT_CLIENT_ID="your-microsoft-client-id"
# export MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"

# SAML Configuration (Optional)
# export AWS_SSO_SINGLE_SIGNON_URL="https://your-aws-sso-url"

# External API Configuration (Optional)
# export OPTIMUS_API_URL_INTERNAL="https://your-api-url"
# export OPTIMUS_API_TOKEN="your-api-token"

# ASP.NET Core Environment
export ASPNETCORE_ENVIRONMENT="Development"
export ASPNETCORE_URLS="https://localhost:7001;http://localhost:5001"

echo "Environment variables set successfully!"
echo ""
echo "To use these variables, run:"
echo "source setup-env.sh"
echo ""
echo "Then start the application with:"
echo "cd SecureAuth.Api && dotnet run"
echo ""
echo "The application will be available at:"
echo "- HTTPS: https://localhost:7001"
echo "- HTTP: http://localhost:5001"
echo "- Swagger UI: https://localhost:7001/swagger"