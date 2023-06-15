import {ApiProperty, OmitType, PartialType} from '@nestjs/swagger';
import {CreateUserDto} from './create-user.dto';
import {IsBoolean, IsOptional} from 'class-validator';
import {RoleEnum} from '@prisma/client';

export class UpdateUserDto extends CreateUserDto {
  @IsBoolean()
  @IsOptional()
  @ApiProperty()
  validated?: boolean

  @IsOptional()
  @ApiProperty()
  role?: RoleEnum
}
