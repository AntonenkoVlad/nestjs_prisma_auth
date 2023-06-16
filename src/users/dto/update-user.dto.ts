import { RoleEnum } from '@prisma/client';
import { ApiProperty, PartialType } from '@nestjs/swagger';

import { IsBoolean, IsOptional } from 'class-validator';
import { CreateUserDto } from './create-user.dto';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsBoolean()
  @IsOptional()
  @ApiProperty()
  emailValidated?: boolean;

  @IsOptional()
  @ApiProperty()
  role?: RoleEnum;
}
