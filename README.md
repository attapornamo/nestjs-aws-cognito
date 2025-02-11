<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo_text.svg" width="320" alt="Nest Logo" /></a>
</p>

# AWS Cognito NestJS integration 
[NestJS](https://nestjs.com/) application with [AWS Cognito](https://aws.amazon.com/en/cognito/) authentication functionality
</br>
## 1. Prerequisites
- NodeJs 12+
- AWS Account

## 2. COGNITO: Create user group
In Cognito service, create a new User Group Pool.</br>
**Do not use the client secret as it is not supported in the JS SDK.**

## 3. Install components
```
npm install
```

## 4. Compile Env
Rename .env.txt to .env and compile with Cognito auth data.

## 5. Build & Run
```
npm run build
npm run start
```

## 6. Use application
This is a Nestjs application to test Cognito authentication. 
</br>
Contains the following route:
- auth/login --> Login
- auth/signup --> Signup
- auth/confirm-signup --> Confirm signup with email or sms code
- auth/resend-confirmation-code --> Resend confirmation code
- auth/forgot-password --> Forgot password
- auth/confirm-forgot-password --> Confirm forgot password
- auth/change-password --> Change password
- auth/require-new-password --> Require new password when login with temporary password
- auth/admin-create-user --> Admin create user
- auth/admin-delete-user --> Admin delete user
- auth/list-users --> List users
- auth/get-user --> Get user
- auth/user --> Delete user

## 7. Documentation
The file ./postman/nestjs-aws-cognito.postman_collection.json can be imported in Postman application to test this api.