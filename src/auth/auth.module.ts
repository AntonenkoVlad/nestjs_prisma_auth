import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';

import {JwtRefreshStrategy} from './strategies/jwt-refresh.strategy';
import {LocalStrategy} from './strategies/local.strategy';
import {JwtStrategy} from './strategies/jwt.strategy';
import {UsersService} from 'src/users/users.service';
import {AuthController} from './auth.controller';
import {MailService} from 'src/mails/MailService';
import {AuthService} from './auth.service';

@Module({
  imports: [
    JwtModule.register({})
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    MailService,
    JwtStrategy,
    UsersService,
    LocalStrategy,
    JwtRefreshStrategy,
  ],
})

export class AuthModule { }