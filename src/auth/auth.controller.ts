import {
  Body,
  Controller,
  ForbiddenException,
  InternalServerErrorException,
  NotFoundException,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDTO } from './dto';
import { Tokens } from './types';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/local/signup')
  async signUpLocal(@Body() dto: AuthDTO): Promise<Tokens> {
    try {
      return await this.authService.signUpLocal(dto);
    } catch (error) {
      if (error.constructor.name === PrismaClientKnownRequestError.name) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials incorrect');
        }
      }

      throw new InternalServerErrorException(
        'Something went wrong. Please try again later',
      );
    }
  }

  @Post('/local/signin')
  signInLocal(@Body() dto: AuthDTO): Promise<Tokens> {
    try {
      return this.authService.signInLocal(dto);
    } catch (error) {
      if (error.constructor.name === PrismaClientKnownRequestError.name) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials incorrect');
        }
      }

      throw new InternalServerErrorException(
        'Something went wrong. Please try again later',
      );
    }
  }

  @Post('/logout')
  logout() {
    this.authService.logout();
  }

  @Post('/refresh')
  refreshTokens() {
    this.authService.refreshTokens();
  }
}
