import { ConfirmRequestDto } from './dto/confirm.request.dto';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthenticateRequestDto } from './dto/authenticate.request.dto';
import { RegisterRequestDto } from './dto/register.request.dto';
import { ChangePasswordRequestDto } from './dto/changepassword.request.dto';
import { GetUserRequestDto } from './dto/getuser.request.dto';
import {
  CognitoIdentityProviderClient,
  AdminInitiateAuthCommand,
  CognitoIdentityProviderServiceException,
  SignUpCommand,
  ConfirmSignUpCommand,
  AdminDeleteUserCommand,
  ForgotPasswordCommand,
  ChangePasswordCommand,
  GetUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';

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
      const command = new AdminInitiateAuthCommand({
        AuthFlow: 'ADMIN_NO_SRP_AUTH',
        AuthParameters: {
          USERNAME: user.email,
          PASSWORD: user.password,
          SECRET_HASH: secretHash,
        },
        ClientId: this.clientId,
        UserPoolId: this.userPoolId,
      });

      // Send the command to AWS Cognito
      const response = await this.client.send(command);

      return response;
    } catch (error) {
      if (error instanceof CognitoIdentityProviderServiceException) {
        // Handle specific AWS Cognito error codes
        if (
          error.name === 'ResetRequiredException' || // Equivalent to RESET_REQUIRED
          error.name === 'UserNotFoundException' // Equivalent to USER_NOT_FOUND
        ) {
          return false;
        }
      }

      // Rethrow any other exceptions
      throw error;
    }
  }

  async register(
    registerRequest: RegisterRequestDto,
    attributes: Record<string, string> = {},
  ) {
    attributes.email = registerRequest.email;

    const formattedAttributes = this.formatAttributes(attributes);

    const params = {
      ClientId: this.clientId,
      Username: registerRequest.email,
      Password: registerRequest.password,
      SecretHash: this.cognitoSecretHash(registerRequest.email),
      UserAttributes: formattedAttributes,
    };

    try {
      const command = new SignUpCommand(params);
      const response = await this.client.send(command);

      // Mark the user as email verified
      await this.setUserAttributes(registerRequest.email, {
        email_verified: 'true',
      });

      return 'UserConfirmed: ' + response.UserConfirmed || false;
    } catch (error) {
      if (error.name === 'UsernameExistsException') {
        return false;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async confirm(confirm: ConfirmRequestDto) {
    const params = {
      ClientId: this.clientId,
      Username: confirm.email,
      ConfirmationCode: confirm.code,
      SecretHash: this.cognitoSecretHash(confirm.email),
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await this.client.send(command);

      return true;
    } catch (error) {
      if (error.name === 'CodeMismatchException') {
        return false;
      }
      if (error.name === 'ExpiredCodeException') {
        return false;
      }

      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async sendResetLink(email: string): Promise<string> {
    const params = {
      ClientId: this.clientId,
      SecretHash: this.cognitoSecretHash(email),
      Username: email,
    };

    try {
      const command = new ForgotPasswordCommand(params);
      await this.client.send(command);
      return 'Reset link has been sent'; // Indicates success
    } catch (error) {
      if (error.name === 'CodeDeliveryFailureException') {
        return 'CodeDeliveryFailure';
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
      if (error.name === 'InvalidPasswordException') {
        return 'InvalidPasswordException';
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
      if (error.name === 'InvalidParameterException') {
        return 'InvalidParameterException';
      }
      if (error.name === 'NotAuthorizedException') {
        return 'NotAuthorizedException';
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
      if (error.name === 'InvalidParameterException') {
        return false;
      }
      if (error.name === 'NotAuthorizedException') {
        return false;
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
