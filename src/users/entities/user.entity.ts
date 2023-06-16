import { Exclude } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { RoleEnum, User } from '@prisma/client';

export class UserEntity implements User {
  constructor(partial: Partial<UserEntity>) {
    Object.assign(this, partial);
  }

  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  email: string;

  @Exclude()
  password: string;

  @Exclude()
  refreshToken: string;

  @ApiProperty({
    enum: RoleEnum,
  })
  role: RoleEnum;

  @ApiProperty()
  emailVerified: boolean;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}
