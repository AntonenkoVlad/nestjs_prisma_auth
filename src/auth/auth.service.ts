import {
  Injectable,
  HttpStatus,
  HttpException,
  NotFoundException,
  ConflictException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {JwtService} from '@nestjs/jwt';
import {RoleEnum, TokenEnum, User} from '@prisma/client';

import {ResetPasswordDto} from './dto/resetPassword.dto';
import {PrismaService} from './../prisma/prisma.service';
import {UsersService} from '../users/users.service';
import {TokenEntity} from './entity/token.entity';
import {MailService} from '../mails/MailService';
import {AuthEntity} from './entity/auth.entity';
import {SignUpDto} from './dto/signup.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private userService: UsersService,
    private mailService: MailService,
  ) { }

  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: {email},
    });

    if (!user)
      throw new HttpException('LOGIN.INVALID_CREDENTIALS', HttpStatus.BAD_REQUEST)

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new HttpException('LOGIN.INVALID_CREDENTIALS', HttpStatus.BAD_REQUEST)
    } else {
      const {password, ...result} = user;

      return result;
    }
  }

  async signUp(signUpDto: SignUpDto): Promise<AuthEntity> {
    const {email, password, name} = signUpDto;
    const user = await this.prisma.user.findUnique({where: {email: email}});

    if (user) throw new ConflictException('User already exist');

    const newUser = await this.userService.create({email, password, name});

    const tokenResult = await this.createEmailToken(
      newUser.id,
      newUser.email,
      TokenEnum.EMAIL_VERIFICATION,
    );
    await this.mailService.sendVerifyEmail(
      newUser.email,
      newUser.name,
      `${process.env.PUBLIC_URL}/auth/verify/${tokenResult.token}`,
    );

    const tokens = await this.getTokens(
      newUser.id,
      newUser.email,
      newUser.role,
    );

    return {
      user: newUser,
      ...tokens
    };
  }

  async login(user: User) {
    const tokens = await this.getTokens(user.id, user.email, user.role);

    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      user,
      ...tokens
    };
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: {id: userId},
      data: {
        refreshToken: null
      }
    });
  }

  async verifyEmail(token: string) {
    const tokenFromDb = await this.prisma.token.findFirst({where: {token}});

    if (!tokenFromDb) throw new ForbiddenException('Access Denied');

    const {email} = await this.prisma.user.findUnique({
      where: {email: tokenFromDb.email},
    });

    if (email) {
      await this.prisma.user.update({
        where: {
          email,
        },
        data: {
          emailVerified: true,
        },
      });

      await this.prisma.token.delete({where: {id: tokenFromDb.id}});
    }
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const userFromDb = await this.prisma.user.findUnique({
      where: {id: userId},
    });

    if (!userFromDb || !userFromDb.refreshToken)
      throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      userFromDb.refreshToken,
    );

    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const {id, email, role} = userFromDb;
    const tokens = await this.getTokens(id, email, role);

    await this.updateRefreshToken(id, tokens.refreshToken);

    return tokens;
  }

  async resendVerificationEmail(email: string) {
    const userFromDb = await this.prisma.user.findUnique({where: {email}});

    if (userFromDb.emailVerified)
      throw new HttpException(
        'RESEND_EMAIL.EMAIL_ALREADY_VERIFIED',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );

    const tokenResult = await this.createEmailToken(
      userFromDb.id,
      userFromDb.email,
      TokenEnum.EMAIL_VERIFICATION,
    );
    await this.mailService.sendVerifyEmail(
      userFromDb.email,
      userFromDb.name,
      `${process.env.PUBLIC_URL}/auth/verify/${tokenResult.token}`,
    );
  }

  async sendForgotPasswordEmail(email: string) {
    const userFromDb = await this.prisma.user.findUnique({where: {email}});

    if (!userFromDb)
      throw new HttpException('LOGIN.USER_NOT_FOUND', HttpStatus.NOT_FOUND);

    const tokenResult = await this.createEmailToken(
      userFromDb.id,
      userFromDb.email,
      TokenEnum.RESET_PASSWORD,
    );
    await this.mailService.sendResetPasswordEmail(
      userFromDb.email,
      `${process.env.PUBLIC_URL}/reset-password/${tokenResult.token}`,
    );
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const resetPasswordTokenFromDb = await this.prisma.token.findFirst({
      where: {token: resetPasswordDto.token, type: TokenEnum.RESET_PASSWORD},
    });

    if (!resetPasswordTokenFromDb)
      throw new HttpException(
        'RESET_PASSWORD.TOKEN_NOT_FOUND',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );

    const userFromDb = await this.prisma.user.findUnique({
      where: {email: resetPasswordTokenFromDb.email},
    });

    if (!userFromDb) throw new ForbiddenException('Access Denied');

    const isNewPasswordInValid = await bcrypt.compare(
      resetPasswordDto.newPassword,
      userFromDb.password,
    );

    if (isNewPasswordInValid)
      throw new HttpException(
        'RESET_PASSWORD.SAME_PASSWORD',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );

    await this.userService.update(userFromDb.id, {
      password: resetPasswordDto.newPassword,
    });
    await this.prisma.token.delete({
      where: {id: resetPasswordTokenFromDb.id},
    });
  }

  async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);

    await this.prisma.user.update({
      where: {id: userId},
      data: {refreshToken: hashedRefreshToken},
    });
  }

  async getTokens(userId: string, username: string, role: RoleEnum) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
          role,
        },
        {
          secret: process.env.ACCESS_TOKEN_SECRET,
          expiresIn: process.env.ACCESS_TOKEN_EXPIRATION || '15',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
          role,
        },
        {
          secret: process.env.REFRESH_TOKEN_SECRET,
          expiresIn: process.env.REFRESH_TOKEN_EXPIRATION || '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async createEmailToken(
    userId: string,
    email: string,
    type: TokenEnum,
  ): Promise<TokenEntity> {
    let emailVerificationToken = await this.prisma.token.findFirst({
      where: {email: email, type},
    });

    if (
      emailVerificationToken &&
      (new Date().getTime() - emailVerificationToken.updatedAt.getTime()) /
      60000 <
      15
    ) {
      throw new HttpException(
        'LOGIN.EMAIL_SENT_RECENTLY',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    const token = (Math.floor(Math.random() * 9000000) + 1000000).toString();

    if (emailVerificationToken) {
      const updatedToken = await this.prisma.token.update({
        where: {id: emailVerificationToken.id},
        data: {
          token,
        },
      });

      emailVerificationToken = updatedToken;
    } else {
      const newToken = await this.prisma.token.create({
        data: {
          email,
          token,
          userId,
          type,
        },
      });

      emailVerificationToken = newToken;
    }

    return emailVerificationToken;
  }
}
