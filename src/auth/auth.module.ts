import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';

import {LocalStrategy} from './strategies/local.strategy';
import {JwtStrategy} from './strategies/jwt.strategy';
import {JwtRefreshStrategy} from './strategies/jwt-refresh.strategy';
import {AuthController} from './auth.controller';
import {AuthService} from './auth.service';
import {UsersService} from 'src/users/users.service';
import {PassportModule} from '@nestjs/passport';

@Module({
  imports: [
    JwtModule.register({})
  ],
  controllers: [AuthController],
  providers: [AuthService, UsersService, JwtStrategy, JwtRefreshStrategy, LocalStrategy],
})
export class AuthModule { }