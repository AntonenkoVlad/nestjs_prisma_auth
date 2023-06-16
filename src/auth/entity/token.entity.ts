import {ApiProperty} from '@nestjs/swagger';
import {Token, TokenEnum} from '@prisma/client';

export class TokenEntity implements Token {
  @ApiProperty()
  id: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  token: string;

  @ApiProperty({
    enum: TokenEnum
  })
  type: TokenEnum;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}