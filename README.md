## Description

NestJS APP With Prisma and JWT auth. Includes Registration, Login, Email Confirmation, Reset Password logic. Uses Nodemailer with Google for emails ending.

ENV:

  DATABASE_URL=your_db_url

  ACCESS_TOKEN_SECRET=your_super_secret_access_key
  ACCESS_TOKEN_EXPIRATION=15m
  REFRESH_TOKEN_SECRET=your_super_secret_refresh_key
  REFRESH_TOKEN_EXPIRATION=7d

  EMAIL_USER=your_google_app_account_email
  EMAIL_PASSWORD=app_password_from_google
  EMAIL_COMPANY=any_value

  PUBLIC_URL=your_public_app_url
## Installation

```bash
$ npm install
```

## Running the app

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Test

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```
