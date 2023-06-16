import {
  Body,
  Controller,
  Post,
  UseGuards,
  Req,
  Get,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';

import { JwtRefreshGuard } from './guards/jwt-refresh-auth.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { AuthEntity } from './entity/auth.entity';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignUpDto } from './dto/signup.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({ type: AuthEntity })
  async login(@Req() req) {
    return await this.authService.login(req.user);
  }

  @Post('signup')
  @ApiBody({ type: SignUpDto })
  @ApiCreatedResponse({ type: AuthEntity })
  async registerUser(@Body() createUserDto: CreateUserDto) {
    return await this.authService.signUp(createUserDto);
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  @ApiOkResponse({ type: AuthEntity })
  async refreshToken(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Get('verify/:token')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse()
  async verifyEmail(@Param() params) {
    return this.authService.verifyEmail(params.token);
  }

  @Get('resend-verification/:email')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse()
  async resendVerificationEmail(@Param() params) {
    return this.authService.resendVerificationEmail(params.email);
  }

  @Get('forgot-password/:email')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse()
  async sendForgotPasswordEmail(@Param() params) {
    return this.authService.sendForgotPasswordEmail(params.email);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBody({ type: ResetPasswordDto })
  @ApiNoContentResponse()
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return await this.authService.resetPassword(resetPasswordDto);
  }
}
