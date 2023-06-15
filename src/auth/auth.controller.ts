import {Body, Controller, Post, UseGuards, Req, Get} from '@nestjs/common';
import {ApiBody, ApiHeader, ApiOkResponse, ApiTags} from '@nestjs/swagger';
import {Request} from 'express';

import {JwtRefreshGuard} from './guards/jwt-refresh-auth.guard';
import {CreateUserDto} from 'src/users/dto/create-user.dto';
import {LocalAuthGuard} from './guards/local-auth.guard';
import {UsersService} from '../users/users.service';
import {AuthEntity} from './entity/auth.entity';
import {AuthService} from './auth.service';
import {LoginDto} from './dto/login.dto';
import {SignUpDto} from './dto/signup.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UsersService
  ) { }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @ApiBody({type: LoginDto})
  @ApiOkResponse({type: AuthEntity})
  async login(@Req() req) {
    return await this.authService.login(req.user);
  }

  @Post('signup')
  @ApiBody({type: SignUpDto})
  @ApiOkResponse({type: AuthEntity})
  async registerUser(@Body() createUserDto: CreateUserDto) {
    return await this.userService.create(createUserDto);
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  @ApiOkResponse({type: AuthEntity})
  async refreshToken(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
