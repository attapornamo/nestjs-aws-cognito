import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ConfirmRequestDto } from './dto/confirm.request.dto';
import { AuthenticateRequestDto } from './dto/authenticate.request.dto';
import { RegisterRequestDto } from './dto/register.request.dto';

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

  @Post('send-reset-link')
  async sendResetLink(@Body() data: any) {
    try {
      return await this.authService.sendResetLink(data.email);
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
