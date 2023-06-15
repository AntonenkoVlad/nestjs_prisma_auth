import * as Joi from 'joi';
import {Module} from '@nestjs/common';
import {ConfigModule} from '@nestjs/config';

import {PrismaModule} from './prisma/prisma.module';
import {AuthModule} from './auth/auth.module';
import {UsersModule} from './users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        ACCESS_TOKEN_SECRET: Joi.string().required(),
        ACCESS_TOKEN_EXPIRATION: Joi.string().required(),
        REFRESH_TOKEN_SECRET: Joi.string().required(),
        REFRESH_TOKEN_EXPIRATION: Joi.string().required(),
        SECRET_KEY: Joi.string().required(),
        DATABASE_URL: Joi.string().required(),
      })
    }),
    PrismaModule,
    AuthModule,
    UsersModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
