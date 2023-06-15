import {ApiProperty, OmitType} from "@nestjs/swagger";
import {IsBoolean, IsEmail, IsNotEmpty, IsOptional, IsString, ValidateNested} from "class-validator";

export class CreateUserDto {
  @IsEmail()
  @ApiProperty()
  email: string

  @IsString()
  @IsOptional()
  @ApiProperty()
  password: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  name: string
}
