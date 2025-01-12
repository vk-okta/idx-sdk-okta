# Okta IDX Authentication

This repository demonstrates how to integrate Okta's Identity Experience (IDX) API for user authentication. It supports social IDPs (e.g., Google, Facebook) and includes full end-to-end support for authenticators like Email and Okta Verify. The repository also handles common authentication flows like user registration, account unlocking, authentication, and password reset.

## Features

- **Okta IDX Authentication**: Leverages Okta's IDX API to handle complex authentication flows.
- **Social IDP Support**: Allows users to log in using third-party social login providers such as Google, Facebook, and others.
- **Multi-factor Authentication (MFA)**: Built-in support for Okta Verify and Email-based authentication for added security.

## Authentication Flows

1. **User Registration (Sign-up)**: New users can sign up by providing email or using a social login provider.
2. **Authenticate**: Users can log in with their credentials (email/password or social login).
4. **Password Reset**: If a user forgets their password, they can reset it through email-based verification.
5. **Account Unlock**: Users can unlock their account if it’s locked due to multiple failed login attempts.
