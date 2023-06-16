import {ApiProperty} from "@nestjs/swagger";
import {IsEmail, IsNotEmpty, IsString} from "class-validator";

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  newPassword: string;

  @ApiProperty()
  @IsString()
  token: string;
}