import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  ParseUUIDPipe,
  UseGuards,
  Req,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';

import {UsersService} from './users.service';
import {CreateUserDto} from './dto/create-user.dto';
import {UpdateUserDto} from './dto/update-user.dto';
import {UserEntity} from './entities/user.entity';
import {JwtAuthGuard} from 'src/auth/guards/jwt-auth.guard';
import {RoleGuard} from 'src/auth/guards/role.guard';
import {Roles} from 'src/auth/roles.decorator';

@Controller('users')
@ApiTags('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  @Post()
  @ApiCreatedResponse({type: UserEntity})
  async create(@Body() createUserDto: CreateUserDto) {
    return new UserEntity(await this.usersService.create(createUserDto));
  }

  @Get()
  @UseGuards(JwtAuthGuard, RoleGuard)
  @ApiBearerAuth()
  @ApiOkResponse({type: UserEntity, isArray: true})
  async findAll() {
    const users = await this.usersService.findAll();
    return users.map((user) => new UserEntity(user));
  }

  @Get('getUser')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOkResponse({type: UserEntity})
  async getUser(@Req() req: Request) {
    const userId = req.user['sub'];

    return this.usersService.getUser(userId);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOkResponse({type: UserEntity})
  async findOne(@Param('id', ParseUUIDPipe) id: string) {
    return new UserEntity(await this.usersService.findOne(id));
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiCreatedResponse({type: UserEntity})
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return new UserEntity(await this.usersService.update(id, updateUserDto));
  }

  @Roles('ADMIN')
  @Delete(':id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @ApiBearerAuth()
  @ApiNoContentResponse()
  async remove(@Param('id', ParseUUIDPipe) id: string) {
    return new UserEntity(await this.usersService.remove(id));
  }
}
