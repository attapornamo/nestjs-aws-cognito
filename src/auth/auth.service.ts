import { ConfirmSignupRequestDto } from './dto/confirmsignup.request.dto';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthenticateRequestDto } from './dto/authenticate.request.dto';
import { SignupRequestDto } from './dto/signup.request.dto';
import { ChangePasswordRequestDto } from './dto/changepassword.request.dto';
import { GetUserRequestDto } from './dto/getuser.request.dto';
import { AdminCreateUserRequestDto } from './dto/admincreateuser.request.dto';
import { ResendConfirmationCodeRequestDto } from './dto/resendconfirmationcode.request.dto';
import { ConfirmForgotPasswordRequestDto } from './dto/confirmforgotpassword.request.dto';
import { AdminDeleteUserRequestDto } from './dto/admindeleteuser.request.dto';
import { ListUsersRequestDto } from './dto/listusers.request.dto';
import { RequireNewPasswordRequestDto } from './dto/requirenewpassword.request.dto';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
  AdminDeleteUserCommand,
  ForgotPasswordCommand,
  ChangePasswordCommand,
  GetUserCommand,
  AdminCreateUserCommand,
  ResendConfirmationCodeCommand,
  ConfirmForgotPasswordCommand,
  ListUsersCommand,
  RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';

type MessageActionType = 'RESEND' | 'SUPPRESS';

@Injectable()
export class AuthService {
  private readonly client: CognitoIdentityProviderClient;
  private readonly clientId: string;
  private readonly userPoolId: string;

  constructor(private configService: ConfigService) {
    // Initialize the AWS Cognito client
    this.client = new CognitoIdentityProviderClient({
      region: process.env.AWS_COGNITO_REGION,
    });
    this.clientId = process.env.AWS_COGNITO_CLIENT_ID; // Replace with your Cognito Client ID
    this.userPoolId = process.env.AWS_COGNITO_USER_POOL_ID;
  }

  async login(user: AuthenticateRequestDto) {
    try {
      // Generate the SECRET_HASH
      const secretHash = this.cognitoSecretHash(user.email);

      // Prepare the adminInitiateAuth command
      const command = new InitiateAuthCommand({
        ClientId: this.clientId,
        AuthFlow: 'USER_PASSWORD_AUTH',
        AuthParameters: {
          USERNAME: user.email,
          PASSWORD: user.password,
          SECRET_HASH: secretHash,
        },
      });

      // Send the command to AWS Cognito
      const response = await this.client.send(command);

      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Rethrow any other exceptions
      throw error;
    }
  }

  async signup(
    signupRequest: SignupRequestDto,
    attributes: Record<string, string> = {},
  ) {
    attributes.email = signupRequest.email;

    const formattedAttributes = this.formatAttributes(attributes);

    const params = {
      ClientId: this.clientId,
      Username: signupRequest.email,
      Password: signupRequest.password,
      SecretHash: this.cognitoSecretHash(signupRequest.email),
      UserAttributes: formattedAttributes,
    };

    try {
      const command = new SignUpCommand(params);
      const response = await this.client.send(command);

      // Mark the user as email verified
      await this.setUserAttributes(signupRequest.email, {
        email_verified: 'true',
      });

      return 'UserConfirmed: ' + response.UserConfirmed || false;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async confirmSignup(confirmSignup: ConfirmSignupRequestDto) {
    const params = {
      ClientId: this.clientId,
      Username: confirmSignup.email,
      ConfirmationCode: confirmSignup.code,
      SecretHash: this.cognitoSecretHash(confirmSignup.email),
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await this.client.send(command);

      return true;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async resendConfirmationCode(
    resendConfirmationCode: ResendConfirmationCodeRequestDto,
  ) {
    // Generate the SECRET_HASH
    const secretHash = this.cognitoSecretHash(resendConfirmationCode.email);

    const params = {
      ClientId: this.clientId,
      Username: resendConfirmationCode.email,
      SecretHash: secretHash,
    };

    try {
      const command = new ResendConfirmationCodeCommand(params);
      const response = await this.client.send(command);

      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async forgotPassword(email: string): Promise<string> {
    const params = {
      ClientId: this.clientId,
      SecretHash: this.cognitoSecretHash(email),
      Username: email,
    };

    try {
      const command = new ForgotPasswordCommand(params);
      await this.client.send(command);
      return 'Reset code has been sent'; // Indicates success
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async confirmForgotPassword(
    confirmForgotPassword: ConfirmForgotPasswordRequestDto,
  ) {
    const params = {
      ClientId: this.clientId,
      Username: confirmForgotPassword.email,
      ConfirmationCode: confirmForgotPassword.code,
      Password: confirmForgotPassword.password,
      SecretHash: this.cognitoSecretHash(confirmForgotPassword.email),
    };

    try {
      const command = new ConfirmForgotPasswordCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async changePassword(changePassword: ChangePasswordRequestDto) {
    const params = {
      AccessToken: changePassword.access_token,
      PreviousPassword: changePassword.previous_password,
      ProposedPassword: changePassword.proposed_password,
    };

    try {
      const command = new ChangePasswordCommand(params);
      await this.client.send(command);
      return 'Change password sucessfully';
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async requireNewPassword(requireNewPassword: RequireNewPasswordRequestDto) {
    // Generate the SECRET_HASH
    const secretHash = this.cognitoSecretHash(requireNewPassword.email);

    const params = {
      ClientId: process.env.AWS_COGNITO_CLIENT_ID,
      ChallengeName: 'NEW_PASSWORD_REQUIRED',
      Session: requireNewPassword.session,
      ChallengeResponses: {
        USERNAME: requireNewPassword.email,
        NEW_PASSWORD: requireNewPassword.password,
        SECRET_HASH: secretHash,
      },
      ...({} as any),
    };

    try {
      const command = new RespondToAuthChallengeCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async adminCreateUser(adminCreateUser: AdminCreateUserRequestDto) {
    const params = {
      UserPoolId: this.userPoolId,
      Username: adminCreateUser.email,
      MessageAction: adminCreateUser.message_action as MessageActionType,
    };

    try {
      const command = new AdminCreateUserCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async adminDeleteUser(adminDeleteUser: AdminDeleteUserRequestDto) {
    const params = {
      UserPoolId: this.userPoolId,
      Username: adminDeleteUser.email,
    };

    try {
      const command = new AdminDeleteUserCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async listUsers(listUsers: ListUsersRequestDto) {
    const params = {
      UserPoolId: this.userPoolId,
      AttributesToGet: listUsers.attributes,
      Filter: listUsers.filter,
      Limit: listUsers.limit,
      PaginationToken: listUsers.pagination_token,
    };

    try {
      const command = new ListUsersCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getUser(getUser: GetUserRequestDto) {
    const params = {
      AccessToken: getUser.access_token,
    };

    try {
      const command = new GetUserCommand(params);
      const response = await this.client.send(command);
      return response;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      // Handle other exceptions
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async deleteUser(user: AuthenticateRequestDto) {
    const params = {
      UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
      Username: user.email,
    };

    try {
      const command = new AdminDeleteUserCommand(params);
      await this.client.send(command);
      return true;
    } catch (error) {
      if (error.name !== '') {
        return error.name;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private formatAttributes(
    attributes: Record<string, string>,
  ): Array<{ Name: string; Value: string }> {
    return Object.entries(attributes).map(([key, value]) => ({
      Name: key,
      Value: value,
    }));
  }

  private async setUserAttributes(
    email: string,
    attributes: Record<string, string>,
  ): Promise<void> {
    // Implement the logic to set user attributes, e.g., using the AdminUpdateUserAttributes API
    console.log(`Setting attributes for ${email}:`, attributes);
  }

  /**
   * Generate the SECRET_HASH for AWS Cognito.
   */
  private cognitoSecretHash(username: string): string {
    const secret = process.env.AWS_COGNITO_CLIENT_SECRET;
    const message = username + this.clientId;

    return crypto.createHmac('sha256', secret).update(message).digest('base64');
  }
}
