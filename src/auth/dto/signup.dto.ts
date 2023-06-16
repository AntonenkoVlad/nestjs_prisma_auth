import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

import { LoginDto } from './login.dto';

export class SignUpDto extends LoginDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  name: string;
}
