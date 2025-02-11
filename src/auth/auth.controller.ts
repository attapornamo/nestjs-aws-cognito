import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Post,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfirmSignupRequestDto } from './dto/confirmsignup.request.dto';
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

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() authenticateRequest: AuthenticateRequestDto) {
    try {
      return await this.authService.login(authenticateRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('signup')
  async signup(@Body() signupRequest: SignupRequestDto) {
    try {
      return await this.authService.signup(signupRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('confirm-signup')
  async confirmSignup(@Body() confirmSignupRequest: ConfirmSignupRequestDto) {
    try {
      return await this.authService.confirmSignup(confirmSignupRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('resend-confirmation-code')
  async resendConfirmationCode(
    @Body() resendConfirmationCodeRequest: ResendConfirmationCodeRequestDto,
  ) {
    try {
      return await this.authService.resendConfirmationCode(
        resendConfirmationCodeRequest,
      );
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('forgot-password')
  async forgotPassword(@Body() data: any) {
    try {
      return await this.authService.forgotPassword(data.email);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('confirm-forgot-password')
  async confirmForgotPassword(
    @Body() confirmForgotPassword: ConfirmForgotPasswordRequestDto,
  ) {
    try {
      return await this.authService.confirmForgotPassword(
        confirmForgotPassword,
      );
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('change-password')
  async changePassword(
    @Body() changePasswordRequest: ChangePasswordRequestDto,
  ) {
    try {
      return await this.authService.changePassword(changePasswordRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('require-new-password')
  async forceChangePassword(
    @Body() requireNewPasswordRequest: RequireNewPasswordRequestDto,
  ) {
    try {
      return await this.authService.requireNewPassword(
        requireNewPasswordRequest,
      );
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('admin-create-user')
  async adminCreateUser(
    @Body() adminCreateUserRequest: AdminCreateUserRequestDto,
  ) {
    try {
      return await this.authService.adminCreateUser(adminCreateUserRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('admin-delete-user')
  async adminDeleteUser(
    @Body() adminDeleteUserRequest: AdminDeleteUserRequestDto,
  ) {
    try {
      return await this.authService.adminDeleteUser(adminDeleteUserRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Get('list-users')
  async listUsers(@Body() listUsersRequest: ListUsersRequestDto) {
    try {
      return await this.authService.listUsers(listUsersRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Get('get-user')
  async getUser(@Body() getUserRequest: GetUserRequestDto) {
    try {
      return await this.authService.getUser(getUserRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Delete('user')
  async delete(@Body() authenticateRequest: AuthenticateRequestDto) {
    try {
      return await this.authService.deleteUser(authenticateRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }
}
