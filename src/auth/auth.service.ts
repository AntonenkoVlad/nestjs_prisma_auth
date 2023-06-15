import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {RoleEnum, User} from '@prisma/client';
import {JwtService} from '@nestjs/jwt';

import {PrismaService} from './../prisma/prisma.service';
import {UsersService} from '../users/users.service';
import {AuthEntity} from './entity/auth.entity';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private userService: UsersService
  ) { }

  async validateUser(username: string, password: string) {
    const user = await this.prisma.user.findUnique({where: {email: username}});

    if (!user) {
      throw new NotFoundException(`No user found for email: ${username}`);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    } else {
      const {password, ...result} = user;

      return result;
    }
  }

  async signUp(email: string, password: string, name: string): Promise<AuthEntity> {
    const user = await this.prisma.user.findUnique({where: {email: email}});

    if (user) {
      throw new ConflictException('User already exist')
    }

    const newUser = await this.userService.create({email, password, name})

    const payload = {
      username: newUser.email,
      role: newUser.role,
      sub: {
        userId: newUser.id
      }
    }

    return {
      accessToken: this.jwtService.sign(payload),
      refreshToken: this.jwtService.sign(payload, {expiresIn: process.env.REFRESH_TOKEN_EXPIRATION})
    };
  }

  async login(user: User) {
    const tokens = await this.getTokens(user.id, user.email, user.role);

    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({where: {id: userId}});

    if (!user || !user.refreshToken)
      throw new ForbiddenException('Access Denied');

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.refreshToken,
    );

    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email, user.role);

    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);

    await this.prisma.user.update({
      where: {id: userId},
      data: {refreshToken: hashedRefreshToken}
    });
  }

  async getTokens(userId: string, username: string, role: RoleEnum) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
          role
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
          role
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
}