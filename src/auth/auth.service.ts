import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {JwtService} from '@nestjs/jwt';

import {PrismaService} from './../prisma/prisma.service';
import {AuthEntity} from './entity/auth.entity';
import {UsersService} from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService, private userService: UsersService) { }

  async signUp(email: string, password: string, name: string): Promise<AuthEntity> {
    const user = await this.prisma.user.findUnique({where: {email: email}});

    if (user) {
      throw new ConflictException('User already exist')
    }

    const newUser = await this.userService.create({email, password, name})

    return {
      accessToken: this.jwtService.sign({userId: newUser.id, role: newUser.role}),
    };
  }

  async login(email: string, password: string): Promise<AuthEntity> {
    const user = await this.prisma.user.findUnique({where: {email: email}});

    if (!user) {
      throw new NotFoundException(`No user found for email: ${email}`);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    return {
      accessToken: this.jwtService.sign({userId: user.id, role: user.role}),
    };
  }
}