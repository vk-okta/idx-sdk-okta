# Custom Okta IDX Authentication Widget

The **Custom Okta IDX Authentication Widget** integrates Okta's Identity Experience Framework (IDX) to deliver a seamless and secure authentication, registration, and user management experience. This widget supports a variety of authentication flows, social identity providers (IDPs), and advanced features, such as Email Magic Link and multi-factor authentication (MFA).

## Features

### 1. Predefined Authentication Flows

The widget supports the following Okta IDX flows:

- **Authenticate**: Enables users to log in using a username and password, or via a social IDP (e.g., Google, Facebook).
- **Reset Password**: Provides users with the ability to reset their password through a secure flow.
- **Unlock Account**: Assists users in unlocking their accounts if they are locked due to failed login attempts or other reasons.
- **Register User**: Facilitates new user registration through multiple methods, including email, phone, or social login.

### 2. Social Identity Providers (IDPs)

The widget allows users to authenticate via external social identity providers (IDPs) configured within Okta. Supported IDPs may include popular services such as Google, Facebook, and others. This integration provides a more flexible login experience for users who prefer social login.

### 3. Email Magic Link

The widget includes a **Passwordless Login** option via an **Email Magic Link**. This allows users to authenticate by clicking on a secure link sent to their email address, eliminating the need for passwords during the login process.

### 4. Enrollment & Factor Assurance for Multi-Factor Authentication (MFA)

This widget supports both the **enrollment** and **factor assurance** processes for various authenticators:

- **Email**: For delivering One-Time Passwords (OTPs) during authentication.
- **Phone**: Allows authentication via OTP sent via SMS or delivered through a voice call.
- **Okta Verify**: Supports Okta Verify for Push notifications and Time-Based One-Time Password (TOTP) authentication.