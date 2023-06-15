import {Body, Controller, Post} from '@nestjs/common';
import {ApiOkResponse, ApiTags} from '@nestjs/swagger';

import {AuthService} from './auth.service';
import {AuthEntity} from './entity/auth.entity';
import {LoginDto} from './dto/login.dto';
import {SignUpDto} from './dto/signup.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  @ApiOkResponse({type: AuthEntity})
  signup(@Body() {email, password, name}: SignUpDto) {
    return this.authService.signUp(email, password, name);
  }

  @Post('login')
  @ApiOkResponse({type: AuthEntity})
  login(@Body() {email, password}: LoginDto) {
    return this.authService.login(email, password);
  }
}