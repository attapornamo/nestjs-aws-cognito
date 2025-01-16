import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Post,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfirmRequestDto } from './dto/confirm.request.dto';
import { AuthenticateRequestDto } from './dto/authenticate.request.dto';
import { RegisterRequestDto } from './dto/register.request.dto';
import { ChangePasswordRequestDto } from './dto/changepassword.request.dto';
import { GetUserRequestDto } from './dto/getuser.request.dto';
import { AdminCreateUserRequestDto } from './dto/admincreateuser.request.dto';
import { ResendConfirmationCodeRequestDto } from './dto/resendconfirmationcode.request.dto';

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

  @Post('register')
  async register(@Body() registerRequest: RegisterRequestDto) {
    try {
      return await this.authService.register(registerRequest);
    } catch (e) {
      throw new BadRequestException(e.message);
    }
  }

  @Post('confirm')
  async confirm(@Body() confirmRequest: ConfirmRequestDto) {
    try {
      return await this.authService.confirm(confirmRequest);
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

  @Post('send-reset-link')
  async sendResetLink(@Body() data: any) {
    try {
      return await this.authService.sendResetLink(data.email);
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
